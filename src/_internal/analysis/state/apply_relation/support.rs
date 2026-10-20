use super::*;

impl AnalysisState {
    /// Reject a declared type the server would refuse: a length or precision
    /// outside the server's range, a type no server can resolve, or a feature
    /// that postdates it. An unknown version or baseline taints instead.
    pub(in crate::_internal::analysis::state) fn check_declared_type(
        &mut self,
        declared: &str,
    ) -> Option<MutationResult> {
        let parsed = ParsedDataType::parse(declared, self.builtin_types());
        if !parsed.is_valid_declaration() {
            return Some(MutationResult::conflict(format!(
                "type '{declared}' is not a valid type declaration"
            )));
        }
        if !self.declared_type_resolves(declared) {
            let Some((schema, name, _)) = Self::parse_type_reference(declared) else {
                self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Statement);
                return None;
            };
            let id = ObjectId::new(schema.as_deref().unwrap_or_default(), &name);
            if schema
                .as_deref()
                .is_none_or(|schema| self.schema_absence_is_authoritative(schema))
                && self.baseline_covers_family_object(
                    &id,
                    crate::_internal::db::cache::CatalogFamily::Types,
                )
            {
                return Some(MutationResult::conflict(format!(
                    "type '{declared}' does not exist"
                )));
            }
            self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Statement);
            return None;
        }
        if parsed.needs_widened_numeric_scale() {
            match self.pg_version().num() {
                Some(version) if version < WIDENED_NUMERIC_SCALE_VERSION => {
                    return Some(MutationResult::conflict(format!(
                        "type '{declared}' requires PostgreSQL 15 or later, \
                             but the baseline reports {version}"
                    )));
                }
                Some(_) => {}
                None => {
                    self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Statement);
                }
            }
        }
        None
    }

    pub(super) fn inherited_descendants(&self, root: &ObjectId) -> Vec<ObjectId> {
        let mut pending = vec![root.clone()];
        let mut visited = HashSet::from([root.clone()]);
        let mut descendants = Vec::new();
        while let Some(parent) = pending.pop() {
            for edge in self.local.graph.edges() {
                if edge.referenced != parent
                    || !matches!(
                        edge.kind,
                        DependencyKind::InheritanceOf | DependencyKind::PartitionOf
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

    pub(super) fn rename_relation_column_metadata(
        &mut self,
        table: &ObjectId,
        from: &str,
        to: &str,
    ) {
        self.snapshot_relation(table);
        if let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(table) {
            relation.apply_column_action(&ColumnAction::Rename {
                from: from.to_string(),
                to: to.to_string(),
            });
        }
        let constraints = self
            .local
            .constraints
            .iter()
            .filter(|((owner, _), constraint)| {
                owner == table && constraint.kind == ConstraintKind::Check
            })
            .filter_map(|((_, name), constraint)| {
                constraint
                    .definition
                    .as_deref()
                    .map(|source| (name.clone(), source.to_string()))
            })
            .collect::<Vec<_>>();
        for (name, source) in constraints {
            self.snapshot_constraint(table, &name);
            if let Some(constraint) = self.local.constraints.get_mut(&(table.clone(), name)) {
                constraint.definition =
                    crate::_internal::analysis::expr_visitor::ExprVisitor::rename_column_source(
                        &source,
                        &table.name,
                        from,
                        to,
                    );
            }
        }
        self.snapshot_graph_full();
        self.local.graph.rename_column_dependencies(table, from, to);
        self.local.graph.rename_index_column(table, from, to);
        let sequences = self
            .local
            .graph
            .edges()
            .iter()
            .filter(|edge| {
                matches!(&edge.kind, DependencyKind::SequenceOwnedBy { column } if column == from)
            })
            .map(|edge| (edge.dependent.clone(), edge.referenced == *table))
            .filter_map(|(sequence, owned)| owned.then_some(sequence))
            .collect::<Vec<_>>();
        for sequence in sequences {
            self.snapshot_sequence(&sequence);
            if let Some(SequenceOverlay::Present(state)) = self.local.sequences.get_mut(&sequence)
                && let Some((_, column)) = &mut state.owned_by
            {
                *column = to.to_string();
            }
            self.local
                .graph
                .rename_owned_sequence_column(&sequence, from, to);
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
        for (parent_column, child_column) in parent.columns.iter().zip(&child.columns) {
            if parent_column.name != child_column.name {
                return Err(format!(
                    "partition column '{}' does not match parent column '{}' in position",
                    child_column.name, parent_column.name
                ));
            }
            let type_matches = match (&parent_column.type_id, &child_column.type_id) {
                (Some(parent_type), Some(child_type)) => parent_type == child_type,
                _ => match (&parent_column.data_type, &child_column.data_type) {
                    (Some(parent_type), Some(child_type)) => {
                        parent_type.trim().eq_ignore_ascii_case(child_type.trim())
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

    pub(super) fn default_column_sequence_parameters(
        data_type: Option<&str>,
        persistence: &crate::_internal::model::relation::Persistence,
    ) -> SequenceParameters {
        let data_type = match data_type
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("smallint" | "smallserial" | "serial2") => "smallint",
            Some("integer" | "int" | "int4" | "serial" | "serial4") => "integer",
            _ => "bigint",
        };
        let max_value = match data_type {
            "smallint" => i16::MAX as i64,
            "integer" => i32::MAX as i64,
            _ => i64::MAX,
        };
        SequenceParameters {
            data_type: data_type.to_string(),
            max_value,
            persistence: Self::sequence_persistence(persistence),
            ..SequenceParameters::default()
        }
    }

    /// The backing index of a locally created primary key or unique constraint.
    ///
    /// Constraint syntax admits neither expressions nor predicates, so the
    /// shape is fully determined by the columns. `NULLS NOT DISTINCT` is not
    /// modeled on constraint syntax, so the server default is recorded.
    pub(super) fn constraint_index_dependency(
        columns: Vec<String>,
        is_unique: bool,
    ) -> DependencyKind {
        DependencyKind::IndexOnRelation {
            definition: IndexDefinition {
                method: Some("btree".to_string()),
                keys: index_keys(columns.clone()),
                included: index_keys(Vec::new()),
                expression_keys: 0,
                unique: is_unique,
                nulls_not_distinct: Some(false),
                predicate: IndexPredicate::None,
                unestablished: false,
                valid: true,
                ready: true,
                live: true,
            },
            dependency_columns: columns,
            dependency_columns_known: true,
            is_concurrent: false,
            is_immediate: true,
            eligibility_known: true,
        }
    }

    pub(super) fn sequence_persistence(
        persistence: &crate::_internal::model::relation::Persistence,
    ) -> SequencePersistence {
        match persistence {
            crate::_internal::model::relation::Persistence::Permanent => {
                SequencePersistence::Permanent
            }
            crate::_internal::model::relation::Persistence::Temporary => {
                SequencePersistence::Temporary
            }
            crate::_internal::model::relation::Persistence::Unlogged => {
                SequencePersistence::Unlogged
            }
        }
    }

    /// Parameters for the sequence backing an identity column.
    ///
    /// PostgreSQL folds the column type into the option list as a synthetic
    /// `AS` clause, so the column type drives the bounds and a written `AS`
    /// is a duplicate option.
    pub(super) fn identity_sequence_parameters(
        column_type: Option<&str>,
        persistence: &crate::_internal::model::relation::Persistence,
        options: Option<&crate::_internal::analysis::mutations::IdentitySequenceOptionsMutation>,
    ) -> Result<SequenceParameters, MutationResult> {
        let data_type = match column_type {
            Some(column_type) => {
                match crate::_internal::analysis::state::apply_sequence::sequence_type(column_type)
                {
                    Some((data_type, _, _)) => data_type,
                    None => {
                        return Err(MutationResult::conflict(
                            "identity column type must be smallint, integer, or bigint".to_string(),
                        ));
                    }
                }
            }
            None => "bigint",
        };
        if options.is_some_and(|options| options.data_type.is_some()) {
            return Err(MutationResult::conflict(
                "conflicting or redundant options: \"as\" specified more than once".to_string(),
            ));
        }
        let mut option_set = options.map_or_else(
            crate::_internal::analysis::state::apply_sequence::SequenceOptionSet::default,
            crate::_internal::analysis::state::apply_sequence::SequenceOptionSet::from_identity_options,
        );
        // The column type is the synthetic `AS`; a written one is a duplicate.
        option_set.as_type = None;
        let mut parameters =
            crate::_internal::analysis::state::apply_sequence::init_sequence_parameters(
                &SequenceParameters {
                    data_type: data_type.to_string(),
                    persistence: Self::sequence_persistence(persistence),
                    ..Default::default()
                },
                &option_set,
                true,
            )?;
        if let Some(persistence) = option_set.persistence() {
            parameters.persistence = persistence;
        }
        Ok(parameters)
    }

    pub(super) fn normalized_constraint_expression(definition: &str) -> String {
        let mut offset = 0usize;
        let mut normalized = String::new();
        for token in squawk_lexer::tokenize(definition) {
            let end = offset + token.len as usize;
            let text = &definition[offset..end];
            offset = end;
            if matches!(
                token.kind,
                squawk_lexer::TokenKind::Whitespace
                    | squawk_lexer::TokenKind::LineComment
                    | squawk_lexer::TokenKind::BlockComment { .. }
                    | squawk_lexer::TokenKind::Eof
            ) {
                continue;
            }
            let text = if matches!(token.kind, squawk_lexer::TokenKind::Ident) {
                text.to_ascii_lowercase()
            } else {
                text.to_string()
            };
            use std::fmt::Write;
            let _ = write!(normalized, "{:?}:{}:{};", token.kind, text.len(), text);
        }
        normalized
    }

    pub(super) fn relation_or_index_lookup(&self, id: &ObjectId) -> RelationLookup {
        if self.relation_is_present(id) || self.index_is_present(id) {
            RelationLookup::Present
        } else if matches!(self.local.relations.get(id), Some(RelationOverlay::Dropped)) {
            RelationLookup::Tombstone
        } else if self.baseline_covers_family_object(
            id,
            crate::_internal::db::cache::CatalogFamily::Relations,
        ) || self
            .baseline_covers_family_object(id, crate::_internal::db::cache::CatalogFamily::Indexes)
        {
            RelationLookup::AuthoritativelyAbsent
        } else {
            RelationLookup::Unknown
        }
    }
}
