use super::*;

impl AnalysisState {
    pub(super) fn invalidate_descendant_partition_predicates(&mut self, root: &ObjectId) {
        // Cached effective predicates include ancestors, not just the local bound.
        for descendant in self.inherited_descendants(root) {
            self.snapshot_relation(&descendant);
            if let Some(RelationOverlay::Present(relation)) =
                self.local.relations.get_mut(&descendant)
            {
                relation.partition_constraint = None;
            }
        }
    }

    // Effective predicates may reference ancestor columns as well as the immediate key.
    pub(super) fn register_retained_partition_check(
        &mut self,
        child: &ObjectId,
        definition: String,
    ) {
        use squawk_syntax::ast::{SourceFile, Stmt};
        let parsed = SourceFile::parse(&format!("SELECT {definition}"));
        let columns = if parsed.errors().is_empty() && parsed.tree().stmts().count() == 1 {
            match parsed.tree().stmts().next() {
                Some(Stmt::Select(select)) => select
                    .select_clause()
                    .and_then(|clause| clause.target_list())
                    .and_then(|list| list.targets().next())
                    .and_then(|target| target.expr())
                    .and_then(|expr| {
                        crate::_internal::analysis::expr_visitor::ExprVisitor::convert(expr)
                            .referenced_columns()
                    }),
                _ => None,
            }
        } else {
            None
        };
        let Some(columns) = columns.filter(|columns| {
            matches!(self.local.relations.get(child), Some(RelationOverlay::Present(relation))
                if columns.iter().all(|column| relation.has_column(column)))
        }) else {
            self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
            return;
        };
        let columns: Vec<String> = columns.into_iter().collect();
        let name = self.next_generated_constraint_name_avoiding(
            child,
            &child.name,
            (columns.len() == 1).then(|| columns[0].as_str()),
            "check",
            &HashSet::new(),
        );
        self.snapshot_constraint(child, &name);
        self.local.constraints.insert(
            (child.clone(), name.clone()),
            ConstraintState {
                table_id: child.clone(),
                name: name.clone(),
                kind: ConstraintKind::Check,
                validated: true,
                definition: Some(definition),
                backing_index: None,
            },
        );
        self.snapshot_graph();
        self.local.graph.add_edge(DependencyEdge::new(
            child.clone(),
            child.clone(),
            DependencyKind::ConstraintDependency {
                constraint_name: name,
                columns,
            },
        ));
    }

    pub(super) fn retained_check_for_detached_partition(
        &mut self,
        parent: &ObjectId,
        child: &ObjectId,
    ) -> RetainedCheckSynthesis {
        let Some(RelationOverlay::Present(relation)) = self.local.relations.get(child) else {
            return RetainedCheckSynthesis::CantResolve;
        };
        let parent_strategy = match self.local.relations.get(parent) {
            Some(RelationOverlay::Present(parent)) => parent.partition_type.as_deref(),
            _ => None,
        };
        let Some(strategy) = parent_strategy else {
            return RetainedCheckSynthesis::CantResolve;
        };
        if strategy.eq_ignore_ascii_case("HASH") {
            return RetainedCheckSynthesis::NoCheck;
        }
        if let Some(predicate) = relation
            .partition_constraint
            .as_deref()
            .filter(|predicate| !predicate.trim().is_empty())
        {
            if strategy.eq_ignore_ascii_case("RANGE") {
                return RetainedCheckSynthesis::Definition(predicate.to_string());
            }
            return self
                .fold_list_partition_predicate(predicate, child)
                .map(RetainedCheckSynthesis::Definition)
                .unwrap_or(RetainedCheckSynthesis::CantResolve);
        }
        let Some(bound) = relation.partition_bound.as_deref() else {
            return RetainedCheckSynthesis::CantResolve;
        };
        if self.local.graph.edges().iter().any(|edge| {
            edge.dependent == *parent
                && matches!(
                    edge.kind,
                    DependencyKind::PartitionOf | DependencyKind::PartitionDetachPending
                )
        }) {
            // A local bound alone cannot reconstruct the ancestor's effective predicate.
            return RetainedCheckSynthesis::CantResolve;
        }
        let Some(keys) = self.partition_key_columns(parent) else {
            return RetainedCheckSynthesis::CantResolve;
        };
        self.synthesize_partition_check(strategy, bound, &keys, relation)
            .map(RetainedCheckSynthesis::Definition)
            .unwrap_or(RetainedCheckSynthesis::CantResolve)
    }

    /// Split a `PARTITION BY <strategy> (c1, c2, ...)` key into column names.
    /// Plain, quoted, and parenthesized plain identifiers (e.g. `(a)`,
    /// `((b))`) resolve to the bare column, matching PostgreSQL's retained
    /// predicate. True expressions (operators, calls, casts) and
    /// collation/opclass/sort annotations return `None`, because PostgreSQL
    /// deparses them in normalized form we cannot replicate byte-for-byte;
    /// those keys keep the conservative `CantResolve` taint.
    pub(super) fn partition_key_columns(&self, parent: &ObjectId) -> Option<Vec<(String, String)>> {
        let Some(RelationOverlay::Present(parent)) = self.local.relations.get(parent) else {
            return None;
        };
        // Fast path: visitor already resolved the keys from typed AST nodes.
        if !parent.partition_keys.is_empty() {
            return Some(parent.partition_keys.clone());
        }
        // Fallback: cache-hydrated relation — re-parse the raw partition_by
        // text using the synthetic-SQL wrap trick (legacy path).
        use squawk_syntax::ast::{SourceFile, Stmt};
        let partition_by = parent.partition_by.as_deref()?;
        let parsed = SourceFile::parse(&format!("CREATE TABLE __key () {partition_by}"));
        if !parsed.errors().is_empty() || parsed.tree().stmts().count() != 1 {
            return None;
        }
        let partition = match parsed.tree().stmts().next() {
            Some(Stmt::CreateTable(create_table)) => create_table.partition_by(),
            _ => return None,
        }?;
        let mut columns = Vec::new();
        for item in partition.partition_item_list()?.partition_items() {
            if item.op_class_ref().is_some()
                || item.attribute_list().is_some()
                || item.nulls_order().is_some()
            {
                return None;
            }
            let name = Self::resolve_partition_column_name(item.expr()?)?;
            columns.push(name);
        }
        if columns.is_empty() {
            None
        } else {
            Some(columns)
        }
    }

    /// Unwrap parentheses to a plain column name; return `None` for any
    /// non-column expression.
    pub(super) fn resolve_partition_column_name(
        expr: squawk_syntax::ast::Expr,
    ) -> Option<(String, String)> {
        use squawk_syntax::ast::{AstNode, Expr};
        let mut current = expr;
        loop {
            match current {
                Expr::ParenExpr(paren) => current = paren.expr()?,
                Expr::NameRef(name) => {
                    return Some((name.text().to_string(), name.syntax().text().to_string()));
                }
                _ => return None,
            }
        }
    }

    /// Fold PostgreSQL's `eval_const_expressions` normalizations of a LIST
    /// partition predicate into their retained-CHECK forms:
    /// `= ANY (ARRAY[...])` becomes an array constant and a single
    /// `= true`/`= false` becomes the bare column / `NOT <column>`.
    /// Single-datum non-boolean predicates are already in final form and are
    /// passed through unchanged.
    pub(super) fn fold_list_partition_predicate(
        &self,
        predicate: &str,
        child: &ObjectId,
    ) -> Option<String> {
        const ANY_MARKER: &str = "ANY (ARRAY[";
        if let Some(marker) = predicate.find(ANY_MARKER) {
            let elements_start = marker + ANY_MARKER.len();
            let rest = &predicate[elements_start..];
            let mut chars = rest.char_indices().peekable();
            let mut close = None;
            while let Some((index, ch)) = chars.next() {
                match ch {
                    '\'' => {
                        while let Some((_, quoted)) = chars.next() {
                            if quoted == '\'' {
                                match chars.peek() {
                                    Some((_, '\'')) => {
                                        chars.next();
                                    }
                                    _ => break,
                                }
                            }
                        }
                    }
                    ']' => {
                        close = Some(index);
                        break;
                    }
                    _ => {}
                }
            }
            let close = close?;
            let elements_txt = &rest[..close];
            let elements = split_top_level(elements_txt, ',');
            let column_type = self
                .local
                .relations
                .get(child)
                .and_then(|overlay| match overlay {
                    RelationOverlay::Present(relation) => Some(relation),
                    _ => None,
                })
                .and_then(|relation| {
                    predicate_column_name(predicate).and_then(|column| {
                        relation
                            .columns
                            .iter()
                            .find(|candidate| candidate.name == column)
                            .and_then(|candidate| candidate.data_type.as_deref())
                    })
                })?;
            let array_type = array_element_type(&elements, column_type)?;
            let mut values = Vec::new();
            for element in elements {
                values.push(decode_sql_literal(element)?);
            }
            let mapped = elements_for_array(&values, &array_type, self.builtin_types())?;
            let array_text = serialize_array_literal(&mapped);
            let suffix = &rest[close + 1..];
            return Some(format!(
                "{}ANY ('{array_text}'::{}[]{suffix}",
                &predicate[..marker],
                array_type
            ));
        }
        fold_boolean_equality(predicate)
    }

    /// Synthesize the retained CHECK from a `FOR VALUES ...` bound for a
    /// single-column RANGE/LIST partition.
    pub(super) fn synthesize_partition_check(
        &self,
        strategy: &str,
        bound: &str,
        keys: &[(String, String)],
        relation: &RelationState,
    ) -> Option<String> {
        let clauses = self.synthesize_partition_check_clauses(strategy, bound, keys, relation)?;
        if clauses.is_empty() {
            None
        } else if clauses.len() == 1 {
            Some(format!("({})", clauses[0]))
        } else {
            Some(format!("(({}))", clauses.join(" AND ")))
        }
    }

    pub(super) fn synthesize_partition_check_clauses(
        &self,
        strategy: &str,
        bound: &str,
        keys: &[(String, String)],
        relation: &RelationState,
    ) -> Option<Vec<String>> {
        if keys.is_empty() {
            return None;
        }

        let mut column_types = Vec::new();
        let mut comparison_lefts = Vec::new();

        for (key_name, key) in keys {
            let col_type = relation
                .columns
                .iter()
                .find(|c| &c.name == key_name)
                .and_then(|c| c.data_type.as_deref())?;

            let parsed = ParsedDataType::parse(col_type, self.builtin_types());
            if !parsed.is_builtin() {
                return None;
            }
            let comp_left = if parsed.requires_text_cast_for_comparison() {
                format!("({key})::text")
            } else {
                key.clone()
            };

            column_types.push(col_type);
            comparison_lefts.push(comp_left);
        }

        let typed_bound = parse_typed_bound(bound)?;

        if strategy.eq_ignore_ascii_case("RANGE") {
            let TypedBound::FromTo {
                from: lower_datums,
                to: upper_datums,
            } = typed_bound
            else {
                return None;
            };

            if lower_datums.len() != upper_datums.len() || lower_datums.len() != keys.len() {
                return None;
            }

            let mut clauses = Vec::new();
            for (_, key) in keys {
                clauses.push(format!("({key} IS NOT NULL)"));
            }

            let mut k_lower = keys.len();
            for (i, datum) in lower_datums.iter().enumerate() {
                if matches!(datum.kind, DatumKind::UnboundedMin) {
                    k_lower = i;
                    break;
                }
            }

            if k_lower > 0 {
                let mut or_clauses = Vec::new();
                for (i, datum) in lower_datums.iter().take(k_lower).enumerate() {
                    let mut and_clauses = Vec::new();
                    for (j, prev) in lower_datums.iter().take(i).enumerate() {
                        let literal = deparse_partition_literal(
                            column_types[j],
                            &prev.text,
                            self.builtin_types(),
                        )?;
                        and_clauses.push(format!("({} = {})", comparison_lefts[j], literal));
                    }
                    let literal = deparse_partition_literal(
                        column_types[i],
                        &datum.text,
                        self.builtin_types(),
                    )?;
                    if i == k_lower - 1 {
                        and_clauses.push(format!("({} >= {})", comparison_lefts[i], literal));
                    } else {
                        and_clauses.push(format!("({} > {})", comparison_lefts[i], literal));
                    }

                    if and_clauses.len() == 1 {
                        or_clauses.push(and_clauses[0].clone());
                    } else {
                        or_clauses.push(format!("({})", and_clauses.join(" AND ")));
                    }
                }
                if or_clauses.len() == 1 {
                    clauses.push(or_clauses[0].clone());
                } else {
                    clauses.push(format!("({})", or_clauses.join(" OR ")));
                }
            }

            let mut k_upper = keys.len();
            let mut is_maxvalue = false;
            for (i, datum) in upper_datums.iter().enumerate() {
                if matches!(datum.kind, DatumKind::UnboundedMax) {
                    k_upper = i;
                    is_maxvalue = true;
                    break;
                } else if matches!(datum.kind, DatumKind::UnboundedMin) {
                    k_upper = i;
                    break;
                }
            }

            if k_upper > 0 {
                let mut or_clauses = Vec::new();
                for (i, datum) in upper_datums.iter().take(k_upper).enumerate() {
                    let mut and_clauses = Vec::new();
                    for (j, prev) in upper_datums.iter().take(i).enumerate() {
                        let literal = deparse_partition_literal(
                            column_types[j],
                            &prev.text,
                            self.builtin_types(),
                        )?;
                        and_clauses.push(format!("({} = {})", comparison_lefts[j], literal));
                    }
                    let literal = deparse_partition_literal(
                        column_types[i],
                        &datum.text,
                        self.builtin_types(),
                    )?;
                    if i == k_upper - 1 && is_maxvalue {
                        and_clauses.push(format!("({} <= {})", comparison_lefts[i], literal));
                    } else {
                        and_clauses.push(format!("({} < {})", comparison_lefts[i], literal));
                    }

                    if and_clauses.len() == 1 {
                        or_clauses.push(and_clauses[0].clone());
                    } else {
                        or_clauses.push(format!("({})", and_clauses.join(" AND ")));
                    }
                }
                if or_clauses.len() == 1 {
                    clauses.push(or_clauses[0].clone());
                } else {
                    clauses.push(format!("({})", or_clauses.join(" OR ")));
                }
            }

            Some(clauses)
        } else if strategy.eq_ignore_ascii_case("LIST") {
            if keys.len() != 1 {
                return None;
            }
            let (_, key) = &keys[0];
            let column_type = column_types[0];
            let comparison_left = &comparison_lefts[0];

            let TypedBound::In(datums) = typed_bound else {
                return None;
            };

            let has_null = datums.iter().any(|d| matches!(d.kind, DatumKind::Null));
            let non_null_datums: Vec<_> = datums
                .iter()
                .filter(|d| !matches!(d.kind, DatumKind::Null))
                .collect();

            if non_null_datums.is_empty() {
                if has_null {
                    return Some(vec![format!("({key} IS NULL)")]);
                }
                return None;
            }

            let value_check = match non_null_datums.as_slice() {
                [single] => {
                    let parsed = ParsedDataType::parse(column_type, self.builtin_types());
                    let literal =
                        deparse_partition_literal(column_type, &single.text, self.builtin_types())?;
                    if parsed.is_named("bool") {
                        if literal == "true" {
                            key.clone()
                        } else if literal == "false" {
                            format!("(NOT {key})")
                        } else {
                            return None;
                        }
                    } else {
                        format!("({comparison_left} = {literal})")
                    }
                }
                [] => return None, // handled above, but for exhaustiveness
                _ => {
                    let mut values = Vec::new();
                    for datum in non_null_datums {
                        values.push(decode_sql_literal(&datum.text)?);
                    }
                    let type_parsed = ParsedDataType::parse(column_type, self.builtin_types());
                    if !type_parsed.is_builtin() {
                        return None;
                    }
                    let canonical_type = type_parsed.to_string();
                    let mapped = elements_for_array(&values, column_type, self.builtin_types())?;
                    if matches!(
                        type_parsed.builtin().map(|b| b.typname.as_str()),
                        Some("int4" | "int2" | "int8")
                    ) {
                        format!("({comparison_left} = ANY (ARRAY[{}]))", mapped.join(", "))
                    } else {
                        let array_text = serialize_array_literal(&mapped);
                        format!("({comparison_left} = ANY ('{array_text}'::{canonical_type}[]))")
                    }
                }
            };

            if has_null {
                Some(vec![format!("(({key} IS NULL) OR {value_check})")])
            } else {
                Some(vec![format!("({key} IS NOT NULL)"), value_check])
            }
        } else {
            None
        }
    }

    pub(super) fn synthesize_default_partition_constraint(
        &self,
        parent: &ObjectId,
    ) -> Option<String> {
        let strategy = self
            .local
            .relations
            .get(parent)
            .and_then(|overlay| match overlay {
                RelationOverlay::Present(parent) => parent.partition_type.as_deref(),
                RelationOverlay::Dropped => None,
            })?;
        let keys = self.partition_key_columns(parent)?;
        let predicates = self
            .local
            .graph
            .edges()
            .iter()
            .filter(|edge| {
                edge.referenced == *parent && matches!(edge.kind, DependencyKind::PartitionOf)
            })
            .filter_map(|edge| {
                let child = match self.local.relations.get(&edge.dependent) {
                    Some(RelationOverlay::Present(child)) => child,
                    _ => return None,
                };
                let bound = child.partition_bound.as_deref()?;
                if bound.eq_ignore_ascii_case("DEFAULT") {
                    return None;
                }
                let clauses =
                    self.synthesize_partition_check_clauses(strategy, bound, &keys, child)?;
                if clauses.len() >= 2 {
                    let first = &clauses[0];
                    let rest = clauses[1..].join(" AND ");
                    Some(format!("({first} AND ({rest}))"))
                } else {
                    Some(format!("({})", clauses[0]))
                }
            })
            .collect::<Vec<_>>();
        if predicates.is_empty() {
            return None;
        }
        if predicates.len() == 1 {
            Some(format!("(NOT {})", predicates[0]))
        } else {
            Some(format!("(NOT ({}))", predicates.join(" OR ")))
        }
    }

    pub(super) fn refresh_default_partition_constraints(&mut self, parent: &ObjectId) {
        let defaults = self
            .local
            .graph
            .edges()
            .iter()
            .filter(|edge| {
                edge.referenced == *parent && matches!(edge.kind, DependencyKind::PartitionOf)
            })
            .filter_map(|edge| {
                let RelationOverlay::Present(relation) =
                    self.local.relations.get(&edge.dependent)?
                else {
                    return None;
                };
                relation
                    .partition_bound
                    .as_deref()
                    .is_some_and(|bound| bound.eq_ignore_ascii_case("DEFAULT"))
                    .then_some(edge.dependent.clone())
            })
            .collect::<Vec<_>>();
        for child in defaults {
            let constraint = self.synthesize_default_partition_constraint(parent);
            if let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(&child) {
                relation.partition_constraint = constraint;
            }
        }
    }

    pub(super) fn partition_attachment_is_compatible(
        &self,
        parent_id: &ObjectId,
        child_id: &ObjectId,
    ) -> Result<bool, String> {
        let Some(RelationOverlay::Present(parent)) = self.local.relations.get(parent_id) else {
            return Ok(false);
        };
        let Some(RelationOverlay::Present(child)) = self.local.relations.get(child_id) else {
            return Ok(false);
        };
        if parent.columns.len() != child.columns.len() {
            return Err(format!(
                "partition '{}' must have exactly the same columns as parent '{}'",
                child_id, parent_id
            ));
        }
        for parent_column in &parent.columns {
            let Some(child_column) = child
                .columns
                .iter()
                .find(|column| column.name == parent_column.name)
            else {
                return Err(format!(
                    "partition '{}' does not have parent column '{}'",
                    child_id, parent_column.name
                ));
            };
            let type_matches = match (&parent_column.type_id, &child_column.type_id) {
                (Some(parent_type), Some(child_type)) => parent_type == child_type,
                _ => match (&parent_column.data_type, &child_column.data_type) {
                    (Some(parent_type), Some(child_type)) => {
                        let parent = crate::_internal::model::data_type::TypeIdentity::from_syntax(
                            &ParsedDataType::parse(parent_type, self.builtin_types()),
                        );
                        let child = crate::_internal::model::data_type::TypeIdentity::from_syntax(
                            &ParsedDataType::parse(child_type, self.builtin_types()),
                        );
                        if parent.is_unknown() || child.is_unknown() {
                            return Ok(false);
                        }
                        parent == child
                    }
                    _ => return Ok(false),
                },
            };
            if !type_matches || parent_column.type_modifier != child_column.type_modifier {
                return Err(format!(
                    "partition column '{}.{}' does not have the same type as parent",
                    child_id, child_column.name
                ));
            }
            if !parent_column.is_nullable && child_column.is_nullable {
                return Err(format!(
                    "partition column '{}.{}' must be NOT NULL like its parent",
                    child_id, child_column.name
                ));
            }
            if parent
                .generated_columns
                .get(&parent_column.name)
                .map(|value| &value.kind)
                != child
                    .generated_columns
                    .get(&child_column.name)
                    .map(|value| &value.kind)
            {
                return Err(format!(
                    "partition column '{}.{}' has incompatible generated-column state",
                    child_id, child_column.name
                ));
            }
        }

        let child_checks: std::collections::HashMap<&str, &ConstraintState> = self
            .local
            .constraints
            .values()
            .filter(|constraint| {
                constraint.table_id == *child_id && constraint.kind == ConstraintKind::Check
            })
            .map(|constraint| (constraint.name.as_str(), constraint))
            .collect();
        for parent_check in self.local.constraints.values().filter(|constraint| {
            constraint.table_id == *parent_id && constraint.kind == ConstraintKind::Check
        }) {
            let Some(child_check) = child_checks.get(parent_check.name.as_str()) else {
                return Err(format!(
                    "partition '{}' is missing parent CHECK constraint '{}'",
                    child_id, parent_check.name
                ));
            };
            let (Some(parent_definition), Some(child_definition)) =
                (&parent_check.definition, &child_check.definition)
            else {
                return Ok(false);
            };
            if Self::normalized_constraint_expression(parent_definition)
                != Self::normalized_constraint_expression(child_definition)
            {
                return Err(format!(
                    "partition CHECK constraint '{}' does not match parent '{}'",
                    parent_check.name, parent_id
                ));
            }
        }

        for parent_constraint in self.local.constraints.values().filter(|constraint| {
            constraint.table_id == *parent_id
                && matches!(
                    constraint.kind,
                    ConstraintKind::PrimaryKey | ConstraintKind::Unique
                )
        }) {
            let Some(child_constraint) = self
                .local
                .constraints
                .get(&(child_id.clone(), parent_constraint.name.clone()))
            else {
                continue;
            };
            if child_constraint.kind != parent_constraint.kind {
                return Err(format!(
                    "partition constraint '{}' conflicts with parent constraint kind",
                    parent_constraint.name
                ));
            }
            let columns_for = |table: &ObjectId| {
                self.local
                    .graph
                    .edges()
                    .iter()
                    .find_map(|edge| match &edge.kind {
                        DependencyKind::ConstraintOnRelation {
                            constraint_name,
                            columns,
                            ..
                        } if edge.dependent == *table
                            && edge.referenced == *table
                            && constraint_name == &parent_constraint.name =>
                        {
                            Some(columns.clone())
                        }
                        _ => None,
                    })
            };
            match (columns_for(parent_id), columns_for(child_id)) {
                (Some(parent_columns), Some(child_columns)) if parent_columns == child_columns => {}
                (Some(_), Some(_)) => {
                    return Err(format!(
                        "partition constraint '{}' has different key columns from parent",
                        parent_constraint.name
                    ));
                }
                _ => return Ok(false),
            }
        }

        for parent_trigger in self.partition_row_trigger_plans(parent_id) {
            let child_trigger_id = Self::trigger_key(child_id, &parent_trigger.name);
            if matches!(
                self.local.triggers.get(&child_trigger_id),
                Some(TriggerOverlay::Present(_))
            ) {
                return Err(format!(
                    "trigger '{}' on partition '{}' conflicts with parent trigger",
                    parent_trigger.name, child_id
                ));
            }
        }
        Ok(true)
    }

    pub(super) fn partition_row_trigger_plans(&self, parent: &ObjectId) -> Vec<TriggerState> {
        self.local
            .triggers
            .values()
            .filter_map(|overlay| match overlay {
                TriggerOverlay::Present(trigger)
                    if trigger.table_id == *parent && trigger.row_level =>
                {
                    Some(trigger.clone())
                }
                _ => None,
            })
            .collect()
    }

    pub(super) fn clone_row_triggers_to_partition(
        &mut self,
        parent: &ObjectId,
        child: &ObjectId,
    ) -> MutationResult {
        let plans = self.partition_row_trigger_plans(parent);
        for parent_trigger in &plans {
            let clone_id = Self::trigger_key(child, &parent_trigger.name);
            if matches!(
                self.local.triggers.get(&clone_id),
                Some(TriggerOverlay::Present(_))
            ) {
                return MutationResult::conflict(format!(
                    "trigger '{}' on partition '{}' conflicts with parent trigger",
                    parent_trigger.name, child
                ));
            }
        }

        for parent_trigger in plans {
            self.snapshot_generation_counter();
            self.local.generation_counter += 1;
            let generation = self.local.generation_counter;
            let clone_id = Self::trigger_key(child, &parent_trigger.name);
            self.snapshot_trigger(&clone_id);
            self.local.triggers.insert(
                clone_id.clone(),
                TriggerOverlay::Present(TriggerState {
                    name: parent_trigger.name.clone(),
                    id: clone_id.clone(),
                    table_id: child.clone(),
                    function_id: parent_trigger.function_id.clone(),
                    row_level: true,
                    parent_trigger_id: Some(parent_trigger.id.clone()),
                    enabled_mode: parent_trigger.enabled_mode,
                    generation,
                }),
            );
            self.snapshot_relation(child);
            if let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(child) {
                relation.triggers.insert(parent_trigger.name);
            }
            self.snapshot_graph_full();
            self.local.graph.add_edge(DependencyEdge::new(
                clone_id.clone(),
                child.clone(),
                DependencyKind::TriggerOnTable {
                    trigger_id: clone_id,
                    function_id: parent_trigger.function_id,
                    trigger_generation: generation,
                },
            ));
        }
        MutationResult::Applied
    }

    pub(super) fn remove_partition_trigger_clones(&mut self, parent: &ObjectId, child: &ObjectId) {
        let parent_trigger_ids: HashSet<ObjectId> = self
            .local
            .triggers
            .values()
            .filter_map(|overlay| match overlay {
                TriggerOverlay::Present(trigger) if trigger.table_id == *parent => {
                    Some(trigger.id.clone())
                }
                _ => None,
            })
            .collect();
        let clones: Vec<(ObjectId, String)> = self
            .local
            .triggers
            .iter()
            .filter_map(|(id, overlay)| match overlay {
                TriggerOverlay::Present(trigger)
                    if trigger.table_id == *child
                        && trigger
                            .parent_trigger_id
                            .as_ref()
                            .is_some_and(|id| parent_trigger_ids.contains(id)) =>
                {
                    Some((id.clone(), trigger.name.clone()))
                }
                _ => None,
            })
            .collect();
        if clones.is_empty() {
            return;
        }
        self.snapshot_relation(child);
        self.snapshot_graph_full();
        for (id, name) in clones {
            self.snapshot_trigger(&id);
            self.local
                .triggers
                .insert(id.clone(), TriggerOverlay::Dropped);
            if let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(child) {
                relation.triggers.remove(&name);
            }
            self.local.graph.retain_edges(|edge| edge.dependent != id);
        }
    }

    /// `AttachPartitionEnsureIndexes`: every partitioned index of the parent
    /// table gains an attached child index on the partition — reusing an
    /// equivalent same-kind one when available and creating a clone otherwise —
    /// and every key constraint backing such an index is cloned alongside it.
    pub(super) fn ensure_partition_indexes_and_constraints(
        &mut self,
        parent: &ObjectId,
        child: &ObjectId,
    ) {
        let parent_indexes: Vec<DependencyEdge> = self
            .local
            .graph
            .edges()
            .iter()
            .filter(|edge| {
                edge.referenced == *parent
                    && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
            })
            .cloned()
            .collect();
        let parent_constraints: Vec<ConstraintState> = self
            .local
            .constraints
            .values()
            .filter(|constraint| constraint.table_id == *parent)
            .cloned()
            .collect();

        for parent_index in parent_indexes {
            let (child_index, _valid) = self.ensure_partition_index_child(
                &parent_index.dependent,
                child,
                &parent_index.kind,
                crate::_internal::analysis::state::index_topology::ChildReuseRule::TableAttach,
            );

            let Some(parent_constraint) = parent_constraints.iter().find(|constraint| {
                constraint.backing_index.as_ref() == Some(&parent_index.dependent)
                    && matches!(
                        constraint.kind,
                        ConstraintKind::PrimaryKey | ConstraintKind::Unique
                    )
            }) else {
                continue;
            };
            // A reused child index already backs the same-kind constraint,
            // which PostgreSQL adopts as the clone rather than restructuring.
            if self.constraint_backing(&child_index).is_some() {
                continue;
            }
            // A unique or primary key constraint cloned onto a partition is
            // renamed; a primary key becomes `<partition>_pkey`, a unique
            // constraint `<partition>_<columns>_key`. Verified against a live
            // server for range, list and hash partitions.
            let columns = self
                .local
                .graph
                .edges()
                .iter()
                .find_map(|edge| match &edge.kind {
                    DependencyKind::ConstraintOnRelation {
                        constraint_name,
                        columns,
                        ..
                    } if edge.dependent == *parent
                        && edge.referenced == *parent
                        && constraint_name == &parent_constraint.name =>
                    {
                        Some(columns.clone())
                    }
                    _ => None,
                });
            let cloned_name = match parent_constraint.kind {
                ConstraintKind::PrimaryKey => format!("{}_pkey", child.name),
                ConstraintKind::Unique => {
                    let column = columns
                        .as_deref()
                        .filter(|columns| !columns.is_empty())
                        .map(|columns| columns.join("_"))
                        .unwrap_or_else(|| child.name.clone());
                    format!("{}_{}_key", child.name, column)
                }
                _ => parent_constraint.name.clone(),
            };
            self.snapshot_constraint(child, &cloned_name);
            self.local.constraints.insert(
                (child.clone(), cloned_name.clone()),
                ConstraintState {
                    table_id: child.clone(),
                    name: cloned_name.clone(),
                    kind: parent_constraint.kind,
                    validated: true,
                    definition: None,
                    backing_index: Some(child_index),
                },
            );
            if let Some(columns) = columns {
                self.snapshot_graph();
                self.local.graph.add_edge(DependencyEdge::new(
                    child.clone(),
                    child.clone(),
                    DependencyKind::ConstraintOnRelation {
                        constraint_name: cloned_name,
                        columns,
                        is_primary: parent_constraint.kind == ConstraintKind::PrimaryKey,
                    },
                ));
            } else {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
        }
    }

    /// `CloneForeignKeyConstraintsIfNeeded`: attaching a partition clones the
    /// parent's foreign keys onto the child, adopting an equivalent child
    /// constraint instead of creating a duplicate.
    pub(super) fn clone_partition_foreign_keys(&mut self, parent: &ObjectId, child: &ObjectId) {
        let parent_foreign_keys: Vec<DependencyEdge> = self
            .local
            .graph
            .edges()
            .iter()
            .filter(|edge| {
                edge.dependent == *parent
                    && matches!(edge.kind, DependencyKind::ForeignKey { .. })
                    && self.dependency_edge_is_current(edge)
            })
            .cloned()
            .collect();
        let mut targets = vec![child.clone()];
        targets.extend(self.partition_descendants(child));
        for target in targets {
            let existing = self.partition_foreign_keys(&target);
            for edge in &parent_foreign_keys {
                self.clone_partition_foreign_key(edge, &target, &existing);
            }
        }
    }

    /// Acquiring a foreign key on a partitioned table clones it onto every
    /// partition that is already attached.
    pub(super) fn clone_foreign_key_to_partition_descendants(
        &mut self,
        parent: &ObjectId,
        parent_edge: &DependencyEdge,
    ) {
        for child in self.partition_descendants(parent) {
            let existing = self.partition_foreign_keys(&child);
            self.clone_partition_foreign_key(parent_edge, &child, &existing);
        }
    }

    pub(super) fn partition_descendants(&self, root: &ObjectId) -> Vec<ObjectId> {
        let mut pending = vec![root.clone()];
        let mut visited = HashSet::from([root.clone()]);
        let mut descendants = Vec::new();
        while let Some(parent) = pending.pop() {
            for edge in self.local.graph.edges() {
                if edge.referenced != parent
                    || !matches!(
                        edge.kind,
                        DependencyKind::PartitionOf | DependencyKind::PartitionDetachPending
                    )
                    || !visited.insert(edge.dependent.clone())
                {
                    continue;
                }
                pending.push(edge.dependent.clone());
                descendants.push(edge.dependent.clone());
            }
        }
        descendants
    }

    /// PostgreSQL applies an identity column added to a partitioned table to
    /// every existing partition. The partitions share the parent's sequence.
    pub(super) fn propagate_identity_to_partition_descendants(
        &mut self,
        parent: &ObjectId,
        column: &str,
        generation: crate::_internal::analysis::facts::ColumnGeneration,
        sequence_id: &ObjectId,
    ) {
        let generation = match generation {
            crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways => {
                crate::_internal::model::relation::IdentityGeneration::Always
            }
            crate::_internal::analysis::facts::ColumnGeneration::IdentityByDefault => {
                crate::_internal::model::relation::IdentityGeneration::ByDefault
            }
            _ => unreachable!("ADD IDENTITY carries an identity generation"),
        };
        let default = Self::sequence_nextval_default(sequence_id);
        let default_text = format!(
            "nextval('{}.{}'::regclass)",
            sequence_id.schema, sequence_id.name
        );
        let mut incomplete = false;
        for descendant in self.partition_descendants(parent) {
            self.snapshot_relation(&descendant);
            let Some(RelationOverlay::Present(relation)) =
                self.local.relations.get_mut(&descendant)
            else {
                incomplete = true;
                continue;
            };
            let Some(column_state) = relation
                .columns
                .iter_mut()
                .find(|state| state.name == column)
            else {
                incomplete = true;
                continue;
            };
            column_state.default = Some(default.clone());
            column_state.default_expr_text = Some(default_text.clone());
            column_state.is_nullable = false;
            relation
                .identity_columns
                .insert(column.to_string(), generation);
        }
        if incomplete {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }
    }

    /// Attaching a table to a table with identity columns copies the identity
    /// property (but not the parent's sequence ownership) to the new subtree.
    pub(super) fn propagate_attached_partition_identity(
        &mut self,
        parent: &ObjectId,
        child: &ObjectId,
    ) {
        let parent_identity: Vec<(
            String,
            crate::_internal::model::relation::IdentityGeneration,
        )> = match self.local.relations.get(parent) {
            Some(RelationOverlay::Present(relation)) => relation
                .identity_columns
                .iter()
                .map(|(column, generation)| (column.clone(), *generation))
                .collect(),
            _ => return,
        };
        for (column, generation) in parent_identity {
            let Some(sequence_id) = self.owned_identity_sequence(parent, &column) else {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
                continue;
            };
            let default = Self::sequence_nextval_default(&sequence_id);
            let default_text = format!(
                "nextval('{}.{}'::regclass)",
                sequence_id.schema, sequence_id.name
            );
            let mut targets = vec![child.clone()];
            targets.extend(self.partition_descendants(child));
            let mut incomplete = false;
            for target in targets {
                self.snapshot_relation(&target);
                let mut applied = false;
                if let Some(RelationOverlay::Present(relation)) =
                    self.local.relations.get_mut(&target)
                {
                    if let Some(column_state) = relation
                        .columns
                        .iter_mut()
                        .find(|state| state.name == column)
                    {
                        // A partition may carry a local default; PostgreSQL
                        // keeps it even though identity takes precedence.
                        if column_state.default.is_none() {
                            column_state.default = Some(default.clone());
                            column_state.default_expr_text = Some(default_text.clone());
                        }
                        column_state.is_nullable = false;
                        applied = true;
                    }
                    if applied {
                        relation.identity_columns.insert(column.clone(), generation);
                    }
                }
                if !applied {
                    incomplete = true;
                }
            }
            if incomplete {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
        }
    }

    /// Detaching a partition drops the identity property PostgreSQL inherits
    /// from the parent, including from nested partitions in the detached
    /// subtree.
    pub(super) fn remove_inherited_partition_identity(
        &mut self,
        parent: &ObjectId,
        child: &ObjectId,
    ) {
        let parent_identity_columns: Vec<String> = match self.local.relations.get(parent) {
            Some(RelationOverlay::Present(relation)) => {
                relation.identity_columns.keys().cloned().collect()
            }
            _ => return,
        };
        for column in parent_identity_columns {
            let sequence_text = self
                .owned_identity_sequence(parent, &column)
                .map(|sequence_id| {
                    format!(
                        "nextval('{}.{}'::regclass)",
                        sequence_id.schema, sequence_id.name
                    )
                });
            let mut targets = vec![child.clone()];
            targets.extend(self.partition_descendants(child));
            for target in targets {
                self.snapshot_relation(&target);
                let Some(RelationOverlay::Present(relation)) =
                    self.local.relations.get_mut(&target)
                else {
                    continue;
                };
                relation.identity_columns.remove(&column);
                if let Some(column_state) = relation
                    .columns
                    .iter_mut()
                    .find(|state| state.name == column)
                    && column_state.default_expr_text.is_some()
                    && column_state.default_expr_text == sequence_text
                {
                    column_state.default = None;
                    column_state.default_expr_text = None;
                }
            }
        }
    }

    fn owned_identity_sequence(&self, table: &ObjectId, column: &str) -> Option<ObjectId> {
        let mut pending = vec![table.clone()];
        let mut visited = HashSet::from([table.clone()]);
        while let Some(current) = pending.pop() {
            let sequence = self
                .local
                .sequences
                .iter()
                .find_map(|(id, overlay)| match overlay {
                    SequenceOverlay::Present(sequence)
                        if sequence.kind == SequenceKind::Identity
                            && sequence.owned_by.as_ref()
                                == Some(&(current.clone(), column.to_string())) =>
                    {
                        Some(id.clone())
                    }
                    _ => None,
                });
            if sequence.is_some() {
                return sequence;
            }
            for edge in self.local.graph.edges() {
                if edge.dependent == current
                    && matches!(
                        edge.kind,
                        DependencyKind::PartitionOf | DependencyKind::PartitionDetachPending
                    )
                    && visited.insert(edge.referenced.clone())
                {
                    pending.push(edge.referenced.clone());
                }
            }
        }
        None
    }

    fn partition_foreign_keys(&self, table: &ObjectId) -> Vec<DependencyEdge> {
        self.local
            .graph
            .edges()
            .iter()
            .filter(|edge| {
                edge.dependent == *table
                    && matches!(edge.kind, DependencyKind::ForeignKey { .. })
                    && self.dependency_edge_is_current(edge)
            })
            .cloned()
            .collect()
    }

    fn clone_partition_foreign_key(
        &mut self,
        parent_edge: &DependencyEdge,
        child: &ObjectId,
        existing: &[DependencyEdge],
    ) {
        let DependencyKind::ForeignKey {
            constraint_name: Some(parent_name),
            from_columns,
            to_columns,
            operator_evidence,
            ..
        } = &parent_edge.kind
        else {
            return;
        };
        let already_present = existing.iter().any(|edge| match &edge.kind {
            DependencyKind::ForeignKey {
                from_columns: child_from_columns,
                to_columns: child_to_columns,
                ..
            } => {
                edge.referenced == parent_edge.referenced
                    && child_from_columns == from_columns
                    && child_to_columns == to_columns
            }
            _ => false,
        });
        if already_present {
            return;
        }
        let Some(RelationOverlay::Present(child_relation)) = self.local.relations.get(child) else {
            return;
        };
        let generation = child_relation.generation;
        let validated = self
            .local
            .constraints
            .get(&(parent_edge.dependent.clone(), parent_name.clone()))
            .is_none_or(|constraint| constraint.validated);
        let constraint_name = self.partition_clone_constraint_name(child, parent_name);
        self.snapshot_constraint(child, &constraint_name);
        self.local.constraints.insert(
            (child.clone(), constraint_name.clone()),
            ConstraintState {
                table_id: child.clone(),
                name: constraint_name.clone(),
                kind: ConstraintKind::ForeignKey,
                validated,
                definition: None,
                backing_index: None,
            },
        );
        if !validated {
            self.snapshot_pending_validation();
            self.local
                .pending_validation
                .insert((child.clone(), constraint_name.clone()));
        }
        self.snapshot_graph();
        self.local.graph.add_edge(DependencyEdge::new(
            child.clone(),
            parent_edge.referenced.clone(),
            DependencyKind::ForeignKey {
                constraint_name: Some(constraint_name),
                from_columns: from_columns.clone(),
                to_columns: to_columns.clone(),
                operator_evidence: operator_evidence.clone(),
                from_generation: generation,
            },
        ));
    }

    fn partition_clone_constraint_name(&self, child: &ObjectId, base: &str) -> String {
        let taken = |candidate: &str| {
            self.local
                .constraints
                .contains_key(&(child.clone(), candidate.to_string()))
        };
        if !taken(base) {
            return base.to_string();
        }
        (1..)
            .map(|suffix| {
                let suffix = format!("_{suffix}");
                let mut end = 63usize.saturating_sub(suffix.len()).min(base.len());
                while !base.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{}{suffix}", &base[..end])
            })
            .find(|candidate| !taken(candidate))
            .expect("constraint suffix space is unbounded")
    }
}
