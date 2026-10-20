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
            if item.collate().is_some()
                || item.op_class_ref().is_some()
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
}
