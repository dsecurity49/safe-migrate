use super::{AnalysisState, CascadeResult, MutationResult, ObjectLookup, RelationOverlay};
use crate::_internal::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::_internal::analysis::facts::TableConstraintFact;
use crate::_internal::analysis::graph::{DependencyEdge, DependencyKind};
use crate::_internal::analysis::mutations::{
    AlterTable, AlterTableActionMutation, CreateTable, DropTable, PersistenceMutation, Rename,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::constraint::{ConstraintKind, ConstraintState};
use crate::_internal::model::relation::{ColumnAction, RelationKind, RelationState};
use crate::_internal::model::sequence::{
    SequenceKind, SequenceOverlay, SequenceParameters, SequencePersistence, SequenceState,
};
use crate::_internal::model::trigger::{TriggerOverlay, TriggerState};
use std::collections::HashSet;

type RelationLookup = ObjectLookup;

impl AnalysisState {
    fn inherited_descendants(&self, root: &ObjectId) -> Vec<ObjectId> {
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

    fn rename_relation_column_metadata(&mut self, table: &ObjectId, from: &str, to: &str) {
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
    fn partition_attachment_is_compatible(
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

    fn partition_row_trigger_plans(&self, parent: &ObjectId) -> Vec<TriggerState> {
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

    fn clone_row_triggers_to_partition(
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
                return MutationResult::Conflict {
                    reason: format!(
                        "trigger '{}' on partition '{}' conflicts with parent trigger",
                        parent_trigger.name, child
                    ),
                };
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

    fn remove_partition_trigger_clones(&mut self, parent: &ObjectId, child: &ObjectId) {
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

    fn partition_indexes_equivalent(left: &DependencyKind, right: &DependencyKind) -> bool {
        match (left, right) {
            (
                DependencyKind::IndexOnRelation {
                    using_method: left_method,
                    key_columns: left_keys,
                    included_columns: left_included,
                    dependency_columns: left_dependencies,
                    dependency_columns_known: left_dependencies_known,
                    has_expression_keys: left_expressions,
                    has_predicate: left_predicate,
                    is_unique: left_unique,
                    is_valid: left_valid,
                    is_ready: left_ready,
                    is_live: left_live,
                    has_default_sort_order: left_sort,
                    has_default_opclasses: left_opclasses,
                    has_default_collations: left_collations,
                    eligibility_known: left_eligibility,
                    ..
                },
                DependencyKind::IndexOnRelation {
                    using_method: right_method,
                    key_columns: right_keys,
                    included_columns: right_included,
                    dependency_columns: right_dependencies,
                    dependency_columns_known: right_dependencies_known,
                    has_expression_keys: right_expressions,
                    has_predicate: right_predicate,
                    is_unique: right_unique,
                    is_valid: right_valid,
                    is_ready: right_ready,
                    is_live: right_live,
                    has_default_sort_order: right_sort,
                    has_default_opclasses: right_opclasses,
                    has_default_collations: right_collations,
                    eligibility_known: right_eligibility,
                    ..
                },
            ) => {
                *left_valid
                    && *right_valid
                    && *left_ready
                    && *right_ready
                    && *left_live
                    && *right_live
                    && left_method == right_method
                    && left_keys == right_keys
                    && left_included == right_included
                    && left_dependencies == right_dependencies
                    && left_dependencies_known == right_dependencies_known
                    && left_expressions == right_expressions
                    && left_predicate == right_predicate
                    && left_unique == right_unique
                    && left_sort == right_sort
                    && left_opclasses == right_opclasses
                    && left_collations == right_collations
                    && left_eligibility == right_eligibility
            }
            _ => false,
        }
    }

    fn ensure_partition_indexes_and_constraints(&mut self, parent: &ObjectId, child: &ObjectId) {
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
        let child_indexes: Vec<DependencyEdge> = self
            .local
            .graph
            .edges()
            .iter()
            .filter(|edge| {
                edge.referenced == *child
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
            let child_index = child_indexes
                .iter()
                .find(|candidate| {
                    Self::partition_indexes_equivalent(&parent_index.kind, &candidate.kind)
                })
                .map(|edge| edge.dependent.clone())
                .unwrap_or_else(|| {
                    let columns = match &parent_index.kind {
                        DependencyKind::IndexOnRelation { key_columns, .. } => {
                            (!key_columns.is_empty()).then(|| key_columns.join("_"))
                        }
                        _ => None,
                    };
                    let id = self.next_generated_relation_name_avoiding(
                        &child.schema,
                        &child.name,
                        columns.as_deref(),
                        "idx",
                        &HashSet::new(),
                    );
                    self.snapshot_graph();
                    self.local.graph.add_edge(DependencyEdge::new(
                        id.clone(),
                        child.clone(),
                        parent_index.kind.clone(),
                    ));
                    id
                });

            let Some(parent_constraint) = parent_constraints.iter().find(|constraint| {
                constraint.backing_index.as_ref() == Some(&parent_index.dependent)
                    && matches!(
                        constraint.kind,
                        ConstraintKind::PrimaryKey | ConstraintKind::Unique
                    )
            }) else {
                continue;
            };
            if self
                .local
                .constraints
                .contains_key(&(child.clone(), parent_constraint.name.clone()))
            {
                continue;
            }
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
            self.snapshot_constraint(child, &parent_constraint.name);
            self.local.constraints.insert(
                (child.clone(), parent_constraint.name.clone()),
                ConstraintState {
                    table_id: child.clone(),
                    name: parent_constraint.name.clone(),
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
                        constraint_name: parent_constraint.name.clone(),
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

    fn default_column_sequence_parameters(
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
            persistence: match persistence {
                crate::_internal::model::relation::Persistence::Permanent => {
                    SequencePersistence::Permanent
                }
                crate::_internal::model::relation::Persistence::Temporary => {
                    SequencePersistence::Temporary
                }
                crate::_internal::model::relation::Persistence::Unlogged => {
                    SequencePersistence::Unlogged
                }
            },
            ..SequenceParameters::default()
        }
    }

    fn constraint_index_dependency(columns: Vec<String>, is_unique: bool) -> DependencyKind {
        DependencyKind::IndexOnRelation {
            using_method: Some("btree".to_string()),
            key_columns: columns.clone(),
            included_columns: Vec::new(),
            dependency_columns: columns,
            dependency_columns_known: true,
            has_expression_keys: false,
            has_predicate: false,
            is_concurrent: false,
            is_unique,
            is_immediate: true,
            is_valid: true,
            is_ready: true,
            is_live: true,
            has_default_sort_order: true,
            has_default_opclasses: true,
            has_default_collations: true,
            eligibility_known: true,
        }
    }

    pub(super) fn apply_identity_sequence_options(
        mut parameters: SequenceParameters,
        options: &crate::_internal::analysis::mutations::IdentitySequenceOptionsMutation,
    ) -> Option<SequenceParameters> {
        if let Some(increment) = options.increment {
            parameters.increment = increment;
        }
        if let Some(data_type) = options.data_type.as_deref() {
            let normalized = data_type.trim().to_ascii_lowercase();
            let (minimum, maximum) = match normalized.as_str() {
                "smallint" | "int2" => (i16::MIN as i64, i16::MAX as i64),
                "integer" | "int" | "int4" => (i32::MIN as i64, i32::MAX as i64),
                "bigint" | "int8" => (i64::MIN, i64::MAX),
                _ => return None,
            };
            parameters.data_type = match normalized.as_str() {
                "smallint" | "int2" => "smallint",
                "integer" | "int" | "int4" => "integer",
                _ => "bigint",
            }
            .to_string();
            parameters.min_value = if parameters.increment > 0 { 1 } else { minimum };
            parameters.max_value = if parameters.increment > 0 {
                maximum
            } else {
                -1
            };
        }
        let type_bounds = match parameters.data_type.as_str() {
            "smallint" => (i16::MIN as i64, i16::MAX as i64),
            "integer" => (i32::MIN as i64, i32::MAX as i64),
            "bigint" => (i64::MIN, i64::MAX),
            _ => return None,
        };
        parameters.min_value = match options.min_value {
            Some(Some(value)) => value,
            Some(None) => {
                if parameters.increment > 0 {
                    1
                } else {
                    type_bounds.0
                }
            }
            None => parameters.min_value,
        };
        parameters.max_value = match options.max_value {
            Some(Some(value)) => value,
            Some(None) => {
                if parameters.increment > 0 {
                    type_bounds.1
                } else {
                    -1
                }
            }
            None => parameters.max_value,
        };
        if let Some(start) = options.start_value {
            parameters.start_value = start;
        } else if options.increment.is_some() && options.increment.unwrap_or(1) < 0 {
            parameters.start_value = parameters.max_value;
        }
        if let Some(cache_size) = options.cache_size {
            parameters.cache_size = cache_size;
        }
        if let Some(cycle) = options.cycle {
            parameters.cycle = cycle;
        }
        if let Some(logged) = options.persistence {
            parameters.persistence = if logged {
                SequencePersistence::Permanent
            } else {
                SequencePersistence::Unlogged
            };
        }
        (parameters.increment != 0
            && parameters.cache_size > 0
            && parameters.min_value < parameters.max_value
            && parameters.start_value >= parameters.min_value
            && parameters.start_value <= parameters.max_value)
            .then_some(parameters)
    }

    fn normalized_constraint_expression(definition: &str) -> String {
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

    fn relation_or_index_lookup(&self, id: &ObjectId) -> RelationLookup {
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

    pub(super) fn apply_drop_table(
        &mut self,
        drop_table: &DropTable,
        precomputed_cascade: Option<&CascadeResult>,
    ) -> MutationResult {
        if drop_table.ids.is_empty() {
            return MutationResult::Skipped;
        }

        let renames: Vec<DependencyEdge> = self
            .local
            .graph
            .edges()
            .iter()
            .filter(|e| matches!(e.kind, DependencyKind::RenameTo))
            .cloned()
            .collect();
        let resolve = |id: &ObjectId| -> ObjectId {
            let mut current = id;
            let mut visited = HashSet::new();
            loop {
                if !visited.insert(current.clone()) {
                    return id.clone();
                }
                match renames.iter().find(|r| &r.dependent == current) {
                    Some(edge) => current = &edge.referenced,
                    None => return current.clone(),
                }
            }
        };

        let display_names = drop_table
            .ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let mut present_targets = Vec::new();
        let mut unknown_target = false;
        for id in &drop_table.ids {
            match self.relation_lookup(id, |kind| *kind == RelationKind::Table) {
                RelationLookup::Present => present_targets.push(id.clone()),
                RelationLookup::WrongKind => {
                    return MutationResult::Conflict {
                        reason: format!("'{}' is not a table", id),
                    };
                }
                RelationLookup::AuthoritativelyAbsent if drop_table.if_exists => {}
                RelationLookup::AuthoritativelyAbsent => {
                    return MutationResult::Conflict {
                        reason: format!("table '{}' does not exist", id),
                    };
                }
                RelationLookup::Tombstone if drop_table.if_exists => {}
                RelationLookup::Tombstone => {
                    return MutationResult::Conflict {
                        reason: format!("table '{}' does not exist", id),
                    };
                }
                RelationLookup::Unknown => {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    unknown_target = true;
                    if !drop_table.if_exists {
                        return MutationResult::Skipped;
                    }
                }
            }
        }

        present_targets.sort_unstable_by_key(ToString::to_string);
        present_targets.dedup();
        // `IF EXISTS` suppresses an absent-object error; it does not prove an
        // object outside a scoped baseline is absent. PostgreSQL can therefore
        // drop an unmodeled target (and its dependencies) in the same atomic
        // statement. Do not apply known siblings with an incomplete target
        // list.
        if unknown_target {
            return MutationResult::Skipped;
        }
        if present_targets.is_empty() {
            return MutationResult::Skipped;
        }

        // A synchronized relation row proves that the table exists, but it
        // cannot prove a DROP result when the dependency catalog family was
        // omitted.  Treat both RESTRICT and CASCADE conservatively rather
        // than letting a partial graph look complete merely because it has
        // some cached edges.
        if present_targets
            .iter()
            .any(|id| self.baseline_relation_is_known(id))
            && !self.baseline_has_coverage(crate::_internal::db::cache::CatalogFamily::Dependencies)
        {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
            return MutationResult::Skipped;
        }

        // Relation-owned dependency loaders currently expand selected
        // foreign-key boundaries, but do not establish that every possible
        // cross-schema default, generated expression, policy, or extension
        // dependency was loaded. Keep a scoped baseline DROP TABLE
        // conservative until that object-class coverage is explicit.
        if present_targets.iter().any(|id| {
            self.baseline_scoped_family_object(
                id,
                crate::_internal::db::cache::CatalogFamily::Relations,
            )
        }) {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
            return MutationResult::Skipped;
        }

        let roots: HashSet<ObjectId> = present_targets.iter().map(&resolve).collect();
        let mut dropped_relations = roots.clone();
        let mut dropped_indexes = HashSet::new();
        let mut dropped_constraints = HashSet::new();

        if drop_table.cascade {
            let local_closure;
            let closure = match precomputed_cascade {
                Some(c) => c,
                None => {
                    local_closure = self.cascade_for_relations(&present_targets);
                    &local_closure
                }
            };
            let closure_touches_baseline = closure
                .dropped_relations
                .iter()
                .any(|id| self.baseline_relation_is_known(id) && !roots.contains(id))
                || closure
                    .dropped_constraints
                    .iter()
                    .any(|constraint| self.baseline_foreign_keys.contains(constraint));
            if closure_touches_baseline
                && !self
                    .baseline_has_coverage(crate::_internal::db::cache::CatalogFamily::Dependencies)
            {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
                return MutationResult::Skipped;
            }
            if closure
                .dropped_relations
                .iter()
                .any(|id| !self.relation_is_present(id) && !self.baseline_relation_is_known(id))
            {
                // A scoped cache may retain a dependency edge to a relation
                // whose catalog row was omitted. CASCADE removes it in
                // PostgreSQL, but its unmodeled metadata makes the result
                // incomplete rather than exact.
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
            }
            dropped_relations = closure.dropped_relations.clone();
            dropped_indexes = closure.dropped_indexes.clone();
            dropped_constraints = closure.dropped_constraints.clone();

            for dropped_rel_id in &closure.dropped_relations {
                self.snapshot_relation(dropped_rel_id);
                self.local
                    .relations
                    .insert(dropped_rel_id.clone(), RelationOverlay::Dropped);
            }

            self.snapshot_graph_full();
            self.local.graph.retain_edges(|e| match &e.kind {
                DependencyKind::IndexOnRelation { .. } => {
                    !closure.dropped_indexes.contains(&resolve(&e.dependent))
                }
                DependencyKind::ForeignKey {
                    constraint_name, ..
                } => {
                    let from_dropped = closure.dropped_relations.contains(&resolve(&e.dependent));
                    let to_dropped = closure.dropped_relations.contains(&resolve(&e.referenced));
                    let constraint_explicitly_dropped = if let Some(cname) = constraint_name {
                        closure
                            .dropped_constraints
                            .contains(&(resolve(&e.dependent), cname.clone()))
                    } else {
                        false
                    };
                    !(from_dropped || to_dropped || constraint_explicitly_dropped)
                }
                DependencyKind::ViewDependency { .. } => {
                    !closure.dropped_relations.contains(&resolve(&e.dependent))
                }
                DependencyKind::SequenceOwnedBy { .. } => {
                    !closure.dropped_relations.contains(&resolve(&e.referenced))
                }
                _ => true,
            });
        } else {
            let has_view_deps = self.local.graph.edges().iter().any(|e| {
                self.dependency_edge_is_current(e)
                    && matches!(e.kind, DependencyKind::ViewDependency { .. })
                    && roots.contains(&resolve(&e.referenced))
                    && !roots.contains(&resolve(&e.dependent))
            });
            let has_fk_deps = self.local.graph.edges().iter().any(|e| {
                self.dependency_edge_is_current(e)
                    && matches!(e.kind, DependencyKind::ForeignKey { .. })
                    && roots.contains(&resolve(&e.referenced))
                    && !roots.contains(&resolve(&e.dependent))
            });
            let has_inheritance_deps = self.local.graph.edges().iter().any(|e| {
                matches!(
                    e.kind,
                    DependencyKind::InheritanceOf
                        | DependencyKind::PartitionOf
                        | DependencyKind::PartitionDetachPending
                ) && roots.contains(&resolve(&e.referenced))
                    && !roots.contains(&resolve(&e.dependent))
            });

            if has_view_deps || has_fk_deps || has_inheritance_deps {
                let relation_word = if present_targets.len() == 1 {
                    "relation"
                } else {
                    "relations"
                };
                let dependent_verb = if present_targets.len() == 1 {
                    "has"
                } else {
                    "have"
                };
                return MutationResult::Conflict {
                    reason: format!(
                        "{relation_word} '{}' still {dependent_verb} dependent objects; use CASCADE",
                        display_names,
                    ),
                };
            }

            for id in &roots {
                self.snapshot_relation(id);
                self.local
                    .relations
                    .insert(id.clone(), RelationOverlay::Dropped);
            }

            self.snapshot_graph_full();
            self.local.graph.retain_edges(|e| {
                if roots.contains(&resolve(&e.dependent)) {
                    return !matches!(
                        e.kind,
                        DependencyKind::ForeignKey { .. }
                            | DependencyKind::ColumnGeneratedFrom { .. }
                            | DependencyKind::ColumnDefaultOnSequence { .. }
                    );
                }
                if roots.contains(&resolve(&e.referenced)) {
                    return !matches!(
                        e.kind,
                        DependencyKind::IndexOnRelation { .. }
                            | DependencyKind::SequenceOwnedBy { .. }
                            | DependencyKind::ColumnGeneratedFrom { .. }
                    );
                }
                true
            });
        }

        let owned_sequences_to_drop: Vec<ObjectId> =
            self.local
                .sequences
                .iter()
                .filter_map(|(id, overlay)| match overlay {
                    SequenceOverlay::Present(sequence)
                        if sequence.owned_by.as_ref().is_some_and(|(table, _)| {
                            dropped_relations.contains(&resolve(table))
                        }) =>
                    {
                        Some(id.clone())
                    }
                    _ => None,
                })
                .collect();
        for sequence_id in owned_sequences_to_drop {
            self.snapshot_sequence(&sequence_id);
            self.local
                .sequences
                .insert(sequence_id, SequenceOverlay::Dropped);
        }

        self.remove_dropped_constraints(&dropped_relations, &dropped_constraints);

        let triggers_to_drop: Vec<ObjectId> = self
            .local
            .triggers
            .iter()
            .filter_map(|(id, overlay)| {
                let TriggerOverlay::Present(trigger) = overlay else {
                    return None;
                };
                let graph_matches = self.local.graph.edges().iter().any(|edge| {
                    matches!(edge.kind, DependencyKind::TriggerOnTable { .. })
                        && edge.dependent == *id
                        && dropped_relations.contains(&resolve(&edge.referenced))
                });
                (dropped_relations.contains(&resolve(&trigger.table_id)) || graph_matches)
                    .then(|| id.clone())
            })
            .collect();
        for trigger_id in triggers_to_drop {
            self.snapshot_trigger(&trigger_id);
            self.local
                .triggers
                .insert(trigger_id, TriggerOverlay::Dropped);
        }

        // PostgreSQL drops triggers only after the table drop succeeds.
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|e| {
            !(matches!(e.kind, DependencyKind::TriggerOnTable { .. })
                && dropped_relations.contains(&resolve(&e.referenced)))
        });

        // A successful relation drop removes every modeled edge that touches
        // the dropped relation (or a cascaded index).  Keep this final sweep
        // broad so newly added edge kinds cannot leak stale topology through
        // a table-drop path.
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|edge| {
            let dependent = resolve(&edge.dependent);
            let referenced = resolve(&edge.referenced);
            !dropped_relations.contains(&dependent)
                && !dropped_relations.contains(&referenced)
                && !dropped_indexes.contains(&dependent)
        });

        let publication_updates: Vec<(String, Vec<_>)> = self
            .local
            .publications
            .iter()
            .filter_map(|(name, overlay)| {
                let crate::_internal::model::replication::PublicationOverlay::Present(publication) =
                    overlay
                else {
                    return None;
                };
                let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
                    &publication.scope
                else {
                    return None;
                };
                let retained = objects
                    .iter()
                    .filter(|object| {
                        let crate::_internal::analysis::facts::PublicationObjectFact::Table {
                            name,
                            ..
                        } = object
                        else {
                            return true;
                        };
                        !dropped_relations.contains(&resolve(&self.resolve_relation_id(name)))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                (retained.len() != objects.len()).then(|| (name.clone(), retained))
            })
            .collect();
        for (publication_name, retained) in publication_updates {
            self.snapshot_publication(&publication_name);
            if let Some(crate::_internal::model::replication::PublicationOverlay::Present(
                publication,
            )) = self.local.publications.get_mut(&publication_name)
                && let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
                    &mut publication.scope
            {
                *objects = retained;
            }
        }
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|edge| {
            !matches!(edge.kind, DependencyKind::PublicationIncludes { .. })
                || !dropped_relations.contains(&resolve(&edge.dependent))
        });

        MutationResult::Applied
    }

    /// PostgreSQL records every NOT NULL column (whether declared inline,
    /// introduced by a PRIMARY KEY, or set later) as a `pg_constraint` row of
    /// `contype = 'n'` on PG18+. The normalized catalog represents it as a
    /// `ConstraintKind::NotNull` entry with its single column on a
    /// `ConstraintOnRelation` edge, mirroring the live sync so the differential
    /// harness and destructive-transition dependency checks agree with
    /// PostgreSQL.
    fn register_not_null_constraint(&mut self, table: &ObjectId, column: &str) {
        // PostgreSQL only materializes NOT NULL columns as `pg_constraint`
        // rows (`contype = 'n'`) on PG18+. On PG17 and earlier a NOT NULL
        // column is tracked purely by its nullability attribute, so recording
        // it as a distinct constraint would add normalized state that the live
        // database never lists. Column nullability is still carried by the
        // column itself; only this separate constraint representation is
        // suppressed.
        if self.effective_pg_version_num(0) < 180_000 {
            return;
        }
        if self.not_null_constraint_for_column(table, column).is_some() {
            return;
        }
        let name = self.next_generated_constraint_name_avoiding(
            table,
            &table.name,
            Some(column),
            "not_null",
            &HashSet::new(),
        );
        self.snapshot_constraint(table, &name);
        self.local.constraints.insert(
            (table.clone(), name.clone()),
            ConstraintState {
                table_id: table.clone(),
                name: name.clone(),
                kind: ConstraintKind::NotNull,
                validated: true,
                definition: None,
                backing_index: None,
            },
        );
        self.snapshot_graph();
        self.local.graph.add_edge(DependencyEdge::new(
            table.clone(),
            table.clone(),
            DependencyKind::ConstraintOnRelation {
                constraint_name: name,
                columns: vec![column.to_string()],
                is_primary: false,
            },
        ));
    }

    fn drop_not_null_constraint(&mut self, table: &ObjectId, column: &str) {
        let Some((table_id, name)) = self.not_null_constraint_for_column(table, column) else {
            return;
        };
        self.snapshot_constraint(&table_id, &name);
        self.local
            .constraints
            .remove(&(table_id.clone(), name.clone()));
        self.snapshot_graph_full();
        let resolution_graph = self.local.graph.clone();
        let column_name = column.to_string();
        self.local.graph.retain_edges(|edge| {
            !matches!(
                &edge.kind,
                DependencyKind::ConstraintOnRelation {
                    constraint_name,
                    columns,
                    is_primary: false,
                    ..
                } if resolution_graph.resolve_rename(&edge.dependent) == &table_id
                    && constraint_name == &name
                    && columns.len() == 1
                    && columns[0] == column_name
            )
        });
    }

    /// Resolve the `ConstraintKind::NotNull` constraint (if any) that guards a
    /// single column on `table`, returning its identity. Not-null constraints
    /// carry exactly one column on a non-primary `ConstraintOnRelation` edge.
    fn not_null_constraint_for_column(
        &self,
        table: &ObjectId,
        column: &str,
    ) -> Option<(ObjectId, String)> {
        let resolution_graph = self.local.graph.clone();
        self.local.graph.edges().iter().find_map(|edge| {
            let dependent = resolution_graph.resolve_rename(&edge.dependent);
            if dependent != table {
                return None;
            }
            if let DependencyKind::ConstraintOnRelation {
                constraint_name,
                columns,
                is_primary: false,
                ..
            } = &edge.kind
                && columns.len() == 1
                && columns[0] == column
            {
                Some((dependent.clone(), constraint_name.clone()))
            } else {
                None
            }
        })
    }

    pub(super) fn apply_create_table(&mut self, create: &CreateTable) -> MutationResult {
        if let Some(strategy) = &create.partition_strategy
            && !["range", "list", "hash"]
                .iter()
                .any(|valid| strategy.eq_ignore_ascii_case(valid))
        {
            return MutationResult::Conflict {
                reason: format!("unrecognized partitioning strategy '{strategy}'"),
            };
        }
        if let Err(result) = self.ensure_schema_target(&create.id.schema) {
            return result;
        }
        if create.if_not_exists && self.relation_namespace_is_taken(&create.id) {
            return MutationResult::Skipped;
        }
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::Conflict {
                reason: format!("relation '{}' already exists", create.id),
            };
        }
        if let Some(type_id) = &create.of_type {
            match self.local.types.get(type_id) {
                Some(crate::_internal::model::types::TypeOverlay::Present(
                    crate::_internal::model::types::TypeState {
                        kind: crate::_internal::model::types::TypeKind::Composite { .. },
                        ..
                    },
                )) => {}
                Some(crate::_internal::model::types::TypeOverlay::Present(_)) => {
                    return MutationResult::Conflict {
                        reason: format!("type '{}' is not composite", type_id),
                    };
                }
                Some(crate::_internal::model::types::TypeOverlay::Dropped) => {
                    return MutationResult::Conflict {
                        reason: format!("composite type '{}' does not exist", type_id),
                    };
                }
                None => {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                }
            }
        }

        let mut inherited_columns = Vec::new();
        let mut inherited_names = HashSet::new();
        let mut inherited_generated_columns = std::collections::HashMap::new();
        let mut inherited_check_constraints: std::collections::HashMap<
            String,
            (Vec<String>, String),
        > = std::collections::HashMap::new();
        let mut like_dependency_edges = Vec::new();
        let mut like_identity_columns = Vec::new();
        let mut like_generated_columns = Vec::new();
        let mut like_check_constraints = Vec::new();
        let mut like_indexes = Vec::new();
        let mut like_extended_statistics = Vec::new();
        let mut reserved_statistics_ids = HashSet::new();
        let mut partition_foreign_keys = Vec::new();
        for parent_id in &create.inherits {
            if let Err(result) = self.ensure_relation_target(
                parent_id,
                |kind| *kind == RelationKind::Table,
                format!("inheritance parent relation '{}' does not exist", parent_id),
                format!("inheritance parent '{}' is not a table", parent_id),
            ) {
                return result;
            }
            if self
                .local
                .graph
                .check_inheritance_cycle(parent_id, &create.id)
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "inheriting '{}' into '{}' would create an inheritance cycle",
                        parent_id, create.id
                    ),
                };
            }
            let Some(RelationOverlay::Present(parent)) = self.local.relations.get(parent_id) else {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            };
            for column in &parent.columns {
                if !inherited_names.insert(column.name.clone()) {
                    let existing = inherited_columns
                        .iter_mut()
                        .find(|candidate: &&mut crate::_internal::model::column::Column| {
                            candidate.name == column.name
                        })
                        .expect("an inherited name always has a column");
                    let compatible_type = match (
                        existing.type_id.as_ref(),
                        column.type_id.as_ref(),
                        existing.data_type.as_deref(),
                        column.data_type.as_deref(),
                    ) {
                        (Some(left), Some(right), _, _) => left == right,
                        (_, _, Some(left), Some(right)) => {
                            left.trim().eq_ignore_ascii_case(right.trim())
                        }
                        _ => false,
                    };
                    if !compatible_type
                        || (existing.default.is_some()
                            && column.default.is_some()
                            && existing.default != column.default)
                    {
                        return MutationResult::Conflict {
                            reason: format!(
                                "inherited column '{}' has incompatible parent definitions",
                                column.name
                            ),
                        };
                    }
                    existing.is_nullable &= column.is_nullable;
                    if existing.default.is_none() {
                        existing.default = column.default.clone();
                        existing.default_expr_text = column.default_expr_text.clone();
                    }
                    continue;
                }
                inherited_columns.push(column.clone());
            }
            for (column, generated) in &parent.generated_columns {
                if let Some(existing) = inherited_generated_columns.get(column)
                    && existing != generated
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "inherited generated column '{}' has incompatible parent definitions",
                            column
                        ),
                    };
                }
                inherited_generated_columns.insert(column.clone(), generated.clone());
            }
            for constraint in self.local.constraints.values().filter(|constraint| {
                constraint.table_id == *parent_id
                    && matches!(constraint.kind, ConstraintKind::Check)
            }) {
                let Some(definition) = constraint.definition.as_deref() else {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                    return MutationResult::Skipped;
                };
                let Some(columns) =
                    self.local
                        .graph
                        .edges()
                        .iter()
                        .find_map(|edge| match &edge.kind {
                            DependencyKind::ConstraintDependency {
                                constraint_name,
                                columns,
                            } if edge.dependent == *parent_id
                                && edge.referenced == *parent_id
                                && constraint_name == &constraint.name =>
                            {
                                Some(columns.clone())
                            }
                            _ => None,
                        })
                else {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                    return MutationResult::Skipped;
                };
                if let Some((_, existing)) = inherited_check_constraints.get(&constraint.name)
                    && Self::normalized_constraint_expression(existing)
                        != Self::normalized_constraint_expression(definition)
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "inherited CHECK constraint '{}' has incompatible parent definitions",
                            constraint.name
                        ),
                    };
                }
                inherited_check_constraints
                    .insert(constraint.name.clone(), (columns, definition.to_string()));
            }
        }
        like_check_constraints.extend(inherited_check_constraints.iter().map(
            |(name, (columns, definition))| (name.clone(), columns.clone(), definition.clone()),
        ));

        // An unadorned LIKE copies only names, types, and NOT NULL markers.
        // Each selected property is copied independently, matching PostgreSQL's
        // `INCLUDING` contract without inventing unrelated catalog objects.
        for like_source in &create.like_sources {
            let source_id = &like_source.relation;
            if !self.relation_is_present(source_id)
                && let Some(crate::_internal::model::types::TypeOverlay::Present(
                    crate::_internal::model::types::TypeState {
                        kind: crate::_internal::model::types::TypeKind::Composite { fields },
                        ..
                    },
                )) = self.local.types.get(source_id)
            {
                for field in fields {
                    if !inherited_names.insert(field.name.clone()) {
                        return MutationResult::Conflict {
                            reason: format!(
                                "column '{}' is copied from more than one source",
                                field.name
                            ),
                        };
                    }
                    inherited_columns.push(
                        crate::_internal::model::column::Column::migration_created(
                            field.name.clone(),
                            Some(field.data_type.clone()),
                            true,
                            None,
                        ),
                    );
                }
                continue;
            }
            if let Err(result) = self.ensure_relation_target(
                source_id,
                |kind| {
                    matches!(
                        kind,
                        RelationKind::Table | RelationKind::View | RelationKind::MaterializedView
                    )
                },
                format!("LIKE source relation '{}' does not exist", source_id),
                format!(
                    "LIKE source '{}' cannot provide a table row type",
                    source_id
                ),
            ) {
                return result;
            }
            let Some(RelationOverlay::Present(source)) = self.local.relations.get(source_id) else {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            };
            let source = source.clone();
            if like_source.properties.statistics {
                for statistics in source.extended_statistics.values() {
                    let id = self.next_generated_statistics_name_avoiding(
                        &create.id.schema,
                        &create.id.name,
                        &statistics.columns,
                        &reserved_statistics_ids,
                    );
                    reserved_statistics_ids.insert(id.clone());
                    let mut cloned = statistics.clone();
                    cloned.id = id;
                    // LIKE copies the statistics definition, while PostgreSQL
                    // initializes the new object's target independently.
                    cloned.target = None;
                    like_extended_statistics.push(cloned);
                }
            }
            if like_source.properties.generated || like_source.properties.defaults {
                like_dependency_edges.extend(self.local.graph.edges().iter().filter_map(|edge| {
                    if edge.dependent != *source_id {
                        return None;
                    }
                    match &edge.kind {
                        DependencyKind::ColumnGeneratedFrom { .. }
                            if like_source.properties.generated =>
                        {
                            Some(DependencyEdge::new(
                                create.id.clone(),
                                create.id.clone(),
                                edge.kind.clone(),
                            ))
                        }
                        DependencyKind::ColumnDefaultOnSequence { .. }
                            if like_source.properties.defaults =>
                        {
                            Some(DependencyEdge::new(
                                create.id.clone(),
                                edge.referenced.clone(),
                                edge.kind.clone(),
                            ))
                        }
                        _ => None,
                    }
                }));
            }
            if like_source.properties.identity {
                for (column, generation) in &source.identity_columns {
                    let Some(parameters) = self.local.sequences.values().find_map(|overlay| {
                        let SequenceOverlay::Present(sequence) = overlay else {
                            return None;
                        };
                        (sequence.kind == SequenceKind::Identity
                            && sequence.owned_by.as_ref()
                                == Some(&(source_id.clone(), column.clone())))
                        .then(|| sequence.parameters.clone())
                    }) else {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                        return MutationResult::Skipped;
                    };
                    like_identity_columns.push((column.clone(), *generation, parameters));
                }
            }
            if like_source.properties.generated {
                like_generated_columns.extend(
                    source
                        .generated_columns
                        .iter()
                        .map(|(column, state)| (column.clone(), state.clone())),
                );
            }
            if like_source.properties.constraints {
                let source_checks: Vec<ConstraintState> = self
                    .local
                    .constraints
                    .values()
                    .filter(|constraint| {
                        constraint.table_id == *source_id
                            && matches!(constraint.kind, ConstraintKind::Check)
                    })
                    .cloned()
                    .collect();
                for constraint in source_checks {
                    let Some(columns) = self.local.graph.edges().iter().find_map(|edge| {
                        if edge.dependent != *source_id || edge.referenced != *source_id {
                            return None;
                        }
                        match &edge.kind {
                            DependencyKind::ConstraintDependency {
                                constraint_name,
                                columns,
                            } if constraint_name == &constraint.name => Some(columns.clone()),
                            _ => None,
                        }
                    }) else {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                        return MutationResult::Skipped;
                    };
                    let Some(definition) = constraint.definition.clone() else {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                        return MutationResult::Skipped;
                    };
                    like_check_constraints.push((constraint.name.clone(), columns, definition));
                }
            }
            if like_source.properties.indexes {
                let source_constraints: Vec<ConstraintState> = self
                    .local
                    .constraints
                    .values()
                    .filter(|constraint| constraint.table_id == *source_id)
                    .cloned()
                    .collect();
                let mut copied_constraints = HashSet::new();
                for edge in self.local.graph.edges().iter().filter(|edge| {
                    edge.referenced == *source_id
                        && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                }) {
                    let constraint = source_constraints
                        .iter()
                        .find(|constraint| {
                            constraint.backing_index.as_ref() == Some(&edge.dependent)
                        })
                        .and_then(|constraint| {
                            let columns = self.local.graph.edges().iter().find_map(|key_edge| {
                                if key_edge.dependent != *source_id
                                    || key_edge.referenced != *source_id
                                {
                                    return None;
                                }
                                match &key_edge.kind {
                                    DependencyKind::ConstraintOnRelation {
                                        constraint_name,
                                        columns,
                                        ..
                                    }
                                    | DependencyKind::ConstraintDependency {
                                        constraint_name,
                                        columns,
                                    } if constraint_name == &constraint.name => {
                                        Some(columns.clone())
                                    }
                                    _ => None,
                                }
                            })?;
                            copied_constraints.insert(constraint.name.clone());
                            Some((constraint.kind, columns))
                        });
                    like_indexes.push((edge.kind.clone(), constraint));
                }
                for constraint in source_constraints.into_iter().filter(|constraint| {
                    matches!(
                        constraint.kind,
                        ConstraintKind::PrimaryKey
                            | ConstraintKind::Unique
                            | ConstraintKind::Exclusion
                    ) && !copied_constraints.contains(&constraint.name)
                }) {
                    let Some((columns, is_key)) =
                        self.local.graph.edges().iter().find_map(|edge| {
                            if edge.dependent != *source_id || edge.referenced != *source_id {
                                return None;
                            }
                            match &edge.kind {
                                DependencyKind::ConstraintOnRelation {
                                    constraint_name,
                                    columns,
                                    ..
                                } if constraint_name == &constraint.name => {
                                    Some((columns.clone(), true))
                                }
                                DependencyKind::ConstraintDependency {
                                    constraint_name,
                                    columns,
                                } if constraint_name == &constraint.name => {
                                    Some((columns.clone(), false))
                                }
                                _ => None,
                            }
                        })
                    else {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                        return MutationResult::Skipped;
                    };
                    let is_unique = matches!(
                        constraint.kind,
                        ConstraintKind::PrimaryKey | ConstraintKind::Unique
                    );
                    like_indexes.push((
                        DependencyKind::IndexOnRelation {
                            using_method: is_key.then(|| "btree".to_string()),
                            key_columns: columns.clone(),
                            included_columns: Vec::new(),
                            dependency_columns: columns.clone(),
                            dependency_columns_known: true,
                            has_expression_keys: !is_key,
                            has_predicate: false,
                            is_concurrent: false,
                            is_unique,
                            is_immediate: true,
                            is_valid: true,
                            is_ready: true,
                            is_live: true,
                            has_default_sort_order: is_key,
                            has_default_opclasses: is_key,
                            has_default_collations: is_key,
                            eligibility_known: true,
                        },
                        Some((constraint.kind, columns)),
                    ));
                }
            }
            for source_column in &source.columns {
                if !inherited_names.insert(source_column.name.clone()) {
                    return MutationResult::Conflict {
                        reason: format!(
                            "column '{}' is copied from more than one source relation",
                            source_column.name
                        ),
                    };
                }
                let mut column = source_column.clone();
                if !like_source.properties.defaults {
                    column.default = None;
                    column.default_expr_text = None;
                }
                if !like_source.properties.storage {
                    column.storage = None;
                }
                if !like_source.properties.compression {
                    column.compression = None;
                }
                column.statistics_target = None;
                column.options.clear();
                if !like_source.properties.generated {
                    column.generated = Some(false);
                }
                inherited_columns.push(column);
            }
        }

        if let Some(parent_id) = &create.partition_of {
            if let Err(result) = self.ensure_relation_target(
                parent_id,
                |kind| *kind == RelationKind::Table,
                format!("partition parent relation '{}' does not exist", parent_id),
                format!("partition parent '{}' is not a table", parent_id),
            ) {
                return result;
            }
            let Some(RelationOverlay::Present(parent)) = self.local.relations.get(parent_id) else {
                unreachable!("partition parent presence was checked above")
            };
            if parent.partition_type.is_none() {
                return MutationResult::Conflict {
                    reason: format!("partition parent '{}' is not partitioned", parent_id),
                };
            }
            for column in &parent.columns {
                if !inherited_names.insert(column.name.clone()) {
                    return MutationResult::Conflict {
                        reason: format!(
                            "partition column '{}' conflicts with another table source",
                            column.name
                        ),
                    };
                }
                inherited_columns.push(column.clone());
            }
            inherited_generated_columns.extend(parent.generated_columns.clone());

            let parent_constraints: Vec<ConstraintState> = self
                .local
                .constraints
                .values()
                .filter(|constraint| constraint.table_id == *parent_id)
                .cloned()
                .collect();
            for constraint in parent_constraints
                .iter()
                .filter(|constraint| matches!(constraint.kind, ConstraintKind::Check))
            {
                let Some(definition) = constraint.definition.clone() else {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                    return MutationResult::Skipped;
                };
                let Some(columns) =
                    self.local
                        .graph
                        .edges()
                        .iter()
                        .find_map(|edge| match &edge.kind {
                            DependencyKind::ConstraintDependency {
                                constraint_name,
                                columns,
                            } if edge.dependent == *parent_id
                                && edge.referenced == *parent_id
                                && constraint_name == &constraint.name =>
                            {
                                Some(columns.clone())
                            }
                            _ => None,
                        })
                else {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                    return MutationResult::Skipped;
                };
                like_check_constraints.push((constraint.name.clone(), columns, definition));
            }

            for edge in self.local.graph.edges().iter().filter(|edge| {
                edge.referenced == *parent_id
                    && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
            }) {
                let constraint = parent_constraints
                    .iter()
                    .find(|constraint| constraint.backing_index.as_ref() == Some(&edge.dependent))
                    .and_then(|constraint| {
                        let columns =
                            self.local
                                .graph
                                .edges()
                                .iter()
                                .find_map(|key_edge| match &key_edge.kind {
                                    DependencyKind::ConstraintOnRelation {
                                        constraint_name,
                                        columns,
                                        ..
                                    }
                                    | DependencyKind::ConstraintDependency {
                                        constraint_name,
                                        columns,
                                    } if key_edge.dependent == *parent_id
                                        && key_edge.referenced == *parent_id
                                        && constraint_name == &constraint.name =>
                                    {
                                        Some(columns.clone())
                                    }
                                    _ => None,
                                })?;
                        Some((constraint.kind, columns))
                    });
                like_indexes.push((edge.kind.clone(), constraint));
            }

            partition_foreign_keys.extend(self.local.graph.edges().iter().filter_map(|edge| {
                let DependencyKind::ForeignKey {
                    constraint_name: Some(name),
                    ..
                } = &edge.kind
                else {
                    return None;
                };
                (edge.dependent == *parent_id).then(|| (name.clone(), edge.clone()))
            }));
        }

        let mut column_names = inherited_names;
        for column in &create.columns {
            if !column_names.insert(column.name.clone()) {
                let inherited = inherited_columns
                    .iter()
                    .find(|candidate| candidate.name == column.name)
                    .expect("an inherited name always has a column");
                let compatible = match (inherited.data_type.as_deref(), column.ty.as_deref()) {
                    (Some(left), Some(right)) => left.trim().eq_ignore_ascii_case(right.trim()),
                    _ => false,
                };
                if !compatible {
                    return MutationResult::Conflict {
                        reason: format!(
                            "column '{}' conflicts with an inherited column type",
                            column.name
                        ),
                    };
                }
            }
        }
        for column in &create.columns {
            let Some(expr) = &column.generated_expr else {
                continue;
            };
            let Some(references) = expr.referenced_columns() else {
                self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Statement);
                return MutationResult::Skipped;
            };
            if let Some(reference) = references
                .iter()
                .find(|reference| *reference == &column.name || !column_names.contains(*reference))
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "generated expression for '{}.{}' references invalid column '{}'",
                        create.id, column.name, reference
                    ),
                };
            }
        }
        let primary_declarations = create
            .columns
            .iter()
            .filter(|column| column.is_primary_key)
            .count()
            + create
                .table_constraints
                .iter()
                .filter(|constraint| matches!(constraint, TableConstraintFact::PrimaryKey { .. }))
                .count();
        if primary_declarations > 1 {
            return MutationResult::Conflict {
                reason: "multiple primary keys for table are not allowed".to_string(),
            };
        }
        for constraint in &create.table_constraints {
            let columns = match constraint {
                TableConstraintFact::PrimaryKey { columns, .. }
                | TableConstraintFact::Unique { columns, .. } => columns,
                TableConstraintFact::Check { .. } | TableConstraintFact::Exclude { .. } => {
                    continue;
                }
            };
            if columns.is_empty() {
                return MutationResult::Conflict {
                    reason: "key constraint must name at least one column".to_string(),
                };
            }
            let mut key_columns = HashSet::new();
            for column in columns {
                if !key_columns.insert(column) {
                    return MutationResult::Conflict {
                        reason: format!(
                            "column '{}' appears more than once in a key constraint",
                            column
                        ),
                    };
                }
                if !column_names.contains(column) {
                    return MutationResult::Conflict {
                        reason: format!(
                            "constraint references column '{}' which does not exist on relation '{}'",
                            column, create.id
                        ),
                    };
                }
            }
        }

        let mut effective_fk_target_columns = Vec::with_capacity(create.foreign_keys.len());
        for fk in &create.foreign_keys {
            if fk.from_columns.is_empty() {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key on relation '{}' has no source columns",
                        create.id
                    ),
                };
            }
            if !fk.to_columns.is_empty() && fk.from_columns.len() != fk.to_columns.len() {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key on '{}' has {} source columns but {} referenced columns",
                        create.id,
                        fk.from_columns.len(),
                        fk.to_columns.len()
                    ),
                };
            }
            let mut source_columns = HashSet::new();
            if let Some(column) = fk
                .from_columns
                .iter()
                .find(|column| !source_columns.insert(column.as_str()))
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key on '{}' repeats source column '{}'",
                        create.id, column
                    ),
                };
            }
            let mut target_columns = HashSet::new();
            if let Some(column) = fk
                .to_columns
                .iter()
                .find(|column| !target_columns.insert(column.as_str()))
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key on '{}' repeats referenced column '{}'",
                        create.id, column
                    ),
                };
            }
            if let Some(column) = fk.from_columns.iter().find(|name| {
                !create
                    .columns
                    .iter()
                    .any(|candidate| candidate.name == **name)
            }) {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key column '{}' does not exist on relation '{}'",
                        column, create.id
                    ),
                };
            }
            let target_columns: HashSet<String> = if fk.to_table == create.id {
                create
                    .columns
                    .iter()
                    .map(|column| column.name.clone())
                    .collect()
            } else {
                if let Err(result) = self.ensure_relation_target(
                    &fk.to_table,
                    |kind| *kind == RelationKind::Table,
                    format!(
                        "foreign key references relation '{}' which does not exist",
                        fk.to_table
                    ),
                    format!(
                        "foreign key references '{}' which is not a table",
                        fk.to_table
                    ),
                ) {
                    return result;
                }
                let Some(RelationOverlay::Present(parent)) = self.local.relations.get(&fk.to_table)
                else {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                };
                parent
                    .columns
                    .iter()
                    .map(|column| column.name.clone())
                    .collect()
            };
            // A scoped/programmatic legacy baseline may omit column facts while
            // retaining the relation identity.  Do not turn that absence into
            // a false column conflict; key/index eligibility is checked
            // separately and remains conservative.
            let target_columns_known =
                !self.baseline_relation_is_known(&fk.to_table) || !target_columns.is_empty();
            if target_columns_known
                && let Some(column) = fk
                    .to_columns
                    .iter()
                    .find(|name| !target_columns.contains(*name))
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key references column '{}.{}' which does not exist",
                        fk.to_table, column
                    ),
                };
            }
            let target_keys = if fk.to_table == create.id {
                let mut keys = Vec::new();
                if primary_declarations == 1 {
                    let columns = create
                        .table_constraints
                        .iter()
                        .find_map(|constraint| match constraint {
                            TableConstraintFact::PrimaryKey { columns, .. } => {
                                Some(columns.clone())
                            }
                            _ => None,
                        })
                        .unwrap_or_else(|| {
                            create
                                .columns
                                .iter()
                                .filter(|column| column.is_primary_key)
                                .map(|column| column.name.clone())
                                .collect()
                        });
                    keys.push((columns, true));
                }
                keys.extend(create.table_constraints.iter().filter_map(
                    |constraint| match constraint {
                        TableConstraintFact::Unique { columns, .. } => {
                            Some((columns.clone(), false))
                        }
                        _ => None,
                    },
                ));
                keys.extend(
                    create
                        .columns
                        .iter()
                        .filter(|column| column.is_unique)
                        .map(|column| (vec![column.name.clone()], false)),
                );
                Some(keys)
            } else {
                self.unique_keys_for_relation(&fk.to_table)
            };
            let referenced_columns = if fk.to_columns.is_empty() {
                let primary_keys: Vec<&Vec<String>> = target_keys
                    .as_ref()
                    .map(|keys| {
                        keys.iter()
                            .filter_map(|(columns, primary)| primary.then_some(columns))
                            .collect()
                    })
                    .unwrap_or_default();
                if target_keys.is_some() && primary_keys.len() != 1 {
                    return MutationResult::Conflict {
                        reason: format!(
                            "foreign key on '{}' omits referenced columns but target '{}' has no single primary key",
                            create.id, fk.to_table
                        ),
                    };
                }
                primary_keys.first().cloned().cloned().unwrap_or_default()
            } else {
                fk.to_columns.clone()
            };
            effective_fk_target_columns.push(referenced_columns.clone());
            if let Some(keys) = target_keys.as_ref()
                && !keys
                    .iter()
                    .any(|(columns, _)| columns == &referenced_columns)
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key on '{}' references columns on '{}' that are not backed by a primary key or unique key",
                        create.id, fk.to_table
                    ),
                };
            } else if target_keys.is_none() {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
            let source_types: Vec<Option<(Option<ObjectId>, Option<String>)>> = fk
                .from_columns
                .iter()
                .map(|column| {
                    create
                        .columns
                        .iter()
                        .find(|candidate| candidate.name == *column)
                        .map(|state| {
                            (
                                state
                                    .ty
                                    .as_deref()
                                    .and_then(|raw| self.resolve_type_reference(raw)),
                                state.ty.clone(),
                            )
                        })
                })
                .collect();
            let target_types: Vec<Option<(Option<ObjectId>, Option<String>)>> =
                if fk.to_table == create.id {
                    referenced_columns
                        .iter()
                        .map(|column| {
                            create
                                .columns
                                .iter()
                                .find(|candidate| candidate.name == *column)
                                .map(|state| {
                                    (
                                        state
                                            .ty
                                            .as_deref()
                                            .and_then(|raw| self.resolve_type_reference(raw)),
                                        state.ty.clone(),
                                    )
                                })
                        })
                        .collect()
                } else {
                    self.local
                        .relations
                        .get(&fk.to_table)
                        .and_then(|overlay| match overlay {
                            RelationOverlay::Present(parent) => Some(
                                referenced_columns
                                    .iter()
                                    .map(|column| {
                                        parent.get_column(column).map(|state| {
                                            (state.type_id.clone(), state.data_type.clone())
                                        })
                                    })
                                    .collect(),
                            ),
                            RelationOverlay::Dropped => None,
                        })
                        .unwrap_or_default()
                };
            let mut type_evidence_unknown = false;
            let type_mismatch =
                source_types
                    .iter()
                    .zip(&target_types)
                    .any(|(source, target)| match (source, target) {
                        (Some((Some(source_id), _)), Some((Some(target_id), _))) => {
                            source_id != target_id
                        }
                        (Some((_, Some(source_ty))), Some((_, Some(target_ty)))) => {
                            !source_ty.trim().eq_ignore_ascii_case(target_ty.trim())
                        }
                        _ => {
                            type_evidence_unknown = true;
                            false
                        }
                    });
            if type_mismatch {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
                return MutationResult::Skipped;
            }
            if type_evidence_unknown {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
        }

        let resolved_persistence = match create.persistence {
            PersistenceMutation::Permanent => {
                crate::_internal::model::relation::Persistence::Permanent
            }
            PersistenceMutation::Temporary => {
                crate::_internal::model::relation::Persistence::Temporary
            }
            PersistenceMutation::Unlogged => {
                crate::_internal::model::relation::Persistence::Unlogged
            }
        };

        // PostgreSQL chooses all implicit sequence names before the
        // table becomes visible. Reserve them up front so a collision
        // or malformed statement cannot leave partial local state.
        let mut reserved_sequences = HashSet::new();
        let mut implicit_sequences = Vec::new();
        for column in &create.columns {
            let kind = match column.generation {
                crate::_internal::analysis::facts::ColumnGeneration::Serial => {
                    Some(SequenceKind::SerialLike)
                }
                crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways
                | crate::_internal::analysis::facts::ColumnGeneration::IdentityByDefault => {
                    Some(SequenceKind::Identity)
                }
                crate::_internal::analysis::facts::ColumnGeneration::Ordinary
                | crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored
                | crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual => None,
            };
            if let Some(kind) = kind {
                let sequence_id = column
                    .identity_sequence
                    .as_ref()
                    .and_then(|options| options.sequence_name.clone())
                    .unwrap_or_else(|| {
                        self.next_implicit_sequence_id(
                            &create.id,
                            &column.name,
                            &reserved_sequences,
                        )
                    });
                if self.relation_namespace_is_taken(&sequence_id)
                    || reserved_sequences.contains(&sequence_id)
                {
                    return MutationResult::Conflict {
                        reason: format!("relation '{}' already exists", sequence_id),
                    };
                }
                let default_parameters = Self::default_column_sequence_parameters(
                    column.ty.as_deref(),
                    &resolved_persistence,
                );
                let parameters = match column.identity_sequence.as_ref() {
                    Some(options) => {
                        let Some(parameters) =
                            Self::apply_identity_sequence_options(default_parameters, options)
                        else {
                            return MutationResult::Conflict {
                                reason: format!(
                                    "identity sequence options for '{}.{}' are invalid",
                                    create.id, column.name
                                ),
                            };
                        };
                        parameters
                    }
                    None => default_parameters,
                };
                reserved_sequences.insert(sequence_id.clone());
                implicit_sequences.push((sequence_id, column.name.clone(), kind, parameters));
            }
        }
        for (column, _, parameters) in &like_identity_columns {
            let sequence_id =
                self.next_implicit_sequence_id(&create.id, column, &reserved_sequences);
            reserved_sequences.insert(sequence_id.clone());
            implicit_sequences.push((
                sequence_id,
                column.clone(),
                SequenceKind::Identity,
                parameters.clone(),
            ));
        }

        // Resolve every constraint name before mutating the relation. PostgreSQL
        // rejects duplicate names atomically, while a state map would otherwise
        // silently overwrite the earlier inline constraint.
        let mut reserved_constraint_names = HashSet::new();
        let mut reserved_index_ids = HashSet::new();
        for (name, _, _) in &like_check_constraints {
            if !reserved_constraint_names.insert(name.clone()) {
                return MutationResult::Conflict {
                    reason: format!("constraint '{}' is copied more than once", name),
                };
            }
        }
        for (name, _) in &partition_foreign_keys {
            if !reserved_constraint_names.insert(name.clone()) {
                return MutationResult::Conflict {
                    reason: format!("constraint '{}' is inherited more than once", name),
                };
            }
        }
        let primary_key_name = create
            .columns
            .iter()
            .find(|column| column.is_primary_key)
            .map(|column| column.primary_key_constraint_name.clone())
            .or_else(|| {
                create.table_constraints.iter().find_map(|constraint| {
                    if let TableConstraintFact::PrimaryKey {
                        constraint_name, ..
                    } = constraint
                    {
                        Some(constraint_name.clone())
                    } else {
                        None
                    }
                })
            });
        let primary_key_constraint_name = primary_key_name.map(|explicit_name| {
            explicit_name.unwrap_or_else(|| {
                self.next_generated_relation_name_avoiding(
                    &create.id.schema,
                    &create.id.name,
                    None,
                    "pkey",
                    &reserved_index_ids,
                )
                .name
            })
        });
        if let Some(name) = &primary_key_constraint_name
            && !reserved_constraint_names.insert(name.clone())
        {
            return MutationResult::Conflict {
                reason: format!("constraint '{}' is specified more than once", name),
            };
        }
        if let Some(name) = &primary_key_constraint_name {
            let index_id = ObjectId::new(&create.id.schema, name);
            if self.relation_namespace_is_taken(&index_id) {
                return MutationResult::Conflict {
                    reason: format!("relation '{}' already exists", index_id),
                };
            }
            reserved_index_ids.insert(index_id);
        }

        let unique_constraints = create
            .columns
            .iter()
            .filter(|column| column.is_unique)
            .map(|column| {
                (
                    column.unique_constraint_name.clone(),
                    vec![column.name.clone()],
                )
            })
            .chain(create.table_constraints.iter().filter_map(|constraint| {
                if let TableConstraintFact::Unique {
                    constraint_name,
                    columns,
                } = constraint
                {
                    Some((constraint_name.clone(), columns.clone()))
                } else {
                    None
                }
            }))
            .collect::<Vec<_>>();
        let mut unique_constraint_names = Vec::with_capacity(unique_constraints.len());
        for (explicit_name, columns) in &unique_constraints {
            let name = explicit_name.clone().unwrap_or_else(|| {
                self.next_generated_relation_name_avoiding(
                    &create.id.schema,
                    &create.id.name,
                    Some(&columns.join("_")),
                    "key",
                    &reserved_index_ids,
                )
                .name
            });
            if !reserved_constraint_names.insert(name.clone()) {
                return MutationResult::Conflict {
                    reason: format!("constraint '{}' is specified more than once", name),
                };
            }
            let index_id = ObjectId::new(&create.id.schema, &name);
            if self.relation_namespace_is_taken(&index_id) {
                return MutationResult::Conflict {
                    reason: format!("relation '{}' already exists", index_id),
                };
            }
            reserved_index_ids.insert(index_id);
            unique_constraint_names.push((name, columns.clone()));
        }

        let mut foreign_key_constraint_names = Vec::with_capacity(create.foreign_keys.len());
        for fk in &create.foreign_keys {
            let name = fk.constraint_name.clone().unwrap_or_else(|| {
                self.next_generated_constraint_name_avoiding(
                    &create.id,
                    &create.id.name,
                    Some(&fk.from_columns.join("_")),
                    "fkey",
                    &reserved_constraint_names,
                )
            });
            if !reserved_constraint_names.insert(name.clone()) {
                return MutationResult::Conflict {
                    reason: format!("constraint '{}' is specified more than once", name),
                };
            }
            foreign_key_constraint_names.push(name);
        }

        let mut inline_constraint_names = Vec::new();
        for constraint in &create.table_constraints {
            let (kind, explicit_name, name_hint, label, definition, columns, columns_complete) =
                match constraint {
                    TableConstraintFact::Check {
                        constraint_name,
                        name_hint,
                        definition,
                        columns,
                        columns_complete,
                    } => (
                        ConstraintKind::Check,
                        constraint_name,
                        name_hint.as_deref(),
                        "check",
                        Some(definition.as_str()),
                        columns,
                        columns_complete,
                    ),
                    TableConstraintFact::Exclude {
                        constraint_name,
                        columns,
                        columns_complete,
                    } => (
                        ConstraintKind::Exclusion,
                        constraint_name,
                        None,
                        "excl",
                        None,
                        columns,
                        columns_complete,
                    ),
                    _ => continue,
                };
            let name = explicit_name.clone().unwrap_or_else(|| {
                if matches!(&kind, ConstraintKind::Exclusion) {
                    self.next_generated_relation_name_avoiding(
                        &create.id.schema,
                        &create.id.name,
                        name_hint,
                        label,
                        &reserved_index_ids,
                    )
                    .name
                } else {
                    self.next_generated_constraint_name_avoiding(
                        &create.id,
                        &create.id.name,
                        name_hint,
                        label,
                        &reserved_constraint_names,
                    )
                }
            });
            if !reserved_constraint_names.insert(name.clone()) {
                if matches!(&kind, ConstraintKind::Check)
                    && inherited_check_constraints.get(&name).is_some_and(
                        |(_, inherited_definition)| {
                            definition.is_some_and(|definition| {
                                Self::normalized_constraint_expression(definition)
                                    == Self::normalized_constraint_expression(inherited_definition)
                            })
                        },
                    )
                {
                    continue;
                }
                return MutationResult::Conflict {
                    reason: format!("constraint '{}' is specified more than once", name),
                };
            }
            let backing_index = if matches!(&kind, ConstraintKind::Exclusion) {
                let index_id = ObjectId::new(&create.id.schema, &name);
                if self.relation_namespace_is_taken(&index_id) {
                    return MutationResult::Conflict {
                        reason: format!("relation '{}' already exists", index_id),
                    };
                }
                reserved_index_ids.insert(index_id.clone());
                Some(index_id)
            } else {
                None
            };
            inline_constraint_names.push((
                kind,
                name,
                definition.map(str::to_string),
                columns.clone(),
                *columns_complete,
                backing_index,
            ));
        }

        let mut like_index_plans = Vec::new();
        for (index_kind, constraint) in like_indexes {
            let (name2, label) = match &constraint {
                Some((ConstraintKind::PrimaryKey, _)) => (None, "pkey"),
                Some((ConstraintKind::Unique, columns)) => (Some(columns.join("_")), "key"),
                Some((ConstraintKind::Exclusion, columns)) => (Some(columns.join("_")), "excl"),
                Some(_) => unreachable!("LIKE INDEXES clones only index-backed constraints"),
                None => {
                    let columns = match &index_kind {
                        DependencyKind::IndexOnRelation { key_columns, .. } => {
                            key_columns.join("_")
                        }
                        _ => unreachable!("LIKE index plan must contain an index edge"),
                    };
                    ((!columns.is_empty()).then_some(columns), "idx")
                }
            };
            let index_id = loop {
                let candidate = self.next_generated_relation_name_avoiding(
                    &create.id.schema,
                    &create.id.name,
                    name2.as_deref(),
                    label,
                    &reserved_index_ids,
                );
                if constraint.is_none() || !reserved_constraint_names.contains(&candidate.name) {
                    break candidate;
                }
                reserved_index_ids.insert(candidate);
            };
            reserved_index_ids.insert(index_id.clone());
            if constraint.is_some() {
                reserved_constraint_names.insert(index_id.name.clone());
            }
            like_index_plans.push((index_id, index_kind, constraint));
        }

        self.snapshot_relation(&create.id);

        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;

        let mut rel_state = RelationState::new(
            create.id.clone(),
            ObjectId::new("", &self.local.current_role),
            generation,
            if create.as_select { None } else { Some(0) },
            RelationKind::Table,
            resolved_persistence,
            self.local.transactions.len(),
        );
        rel_state.on_commit = create.on_commit.map(|action| match action {
            crate::_internal::analysis::mutations::OnCommitMutation::PreserveRows => {
                crate::_internal::model::relation::OnCommitAction::PreserveRows
            }
            crate::_internal::analysis::mutations::OnCommitMutation::DeleteRows => {
                crate::_internal::model::relation::OnCommitAction::DeleteRows
            }
            crate::_internal::analysis::mutations::OnCommitMutation::Drop => {
                crate::_internal::model::relation::OnCommitAction::Drop
            }
        });
        rel_state.of_type = create.of_type.clone();
        rel_state.columns = inherited_columns;
        rel_state.identity_columns.extend(
            like_identity_columns
                .iter()
                .map(|(column, generation, _)| (column.clone(), *generation)),
        );
        rel_state.generated_columns = inherited_generated_columns;
        rel_state.generated_columns.extend(like_generated_columns);
        rel_state.extended_statistics.extend(
            like_extended_statistics
                .into_iter()
                .map(|statistics| (statistics.id.clone(), statistics)),
        );

        if create.as_select && !create.as_select_columns_known {
            // CTAS derives its columns from a query that is intentionally not
            // represented in the current fact model. Keep the relation
            // identity for the destructive-operation rule, but make later
            // column-targeting transitions conservative.
            self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
        }

        rel_state.partition_type = create.partition_strategy.as_deref().map(str::to_uppercase);
        rel_state.partition_by = create.partition_by.clone();
        rel_state.partition_bound = create
            .partition_bound
            .as_deref()
            .map(canonical_partition_bound);

        let pk_columns: HashSet<&str> = create
            .table_constraints
            .iter()
            .filter_map(|tc| {
                if let TableConstraintFact::PrimaryKey { columns, .. } = tc {
                    Some(columns.iter().map(|s| s.as_str()))
                } else {
                    None
                }
            })
            .flatten()
            .collect();

        let mut not_null_columns = Vec::new();
        for col in &create.columns {
            let is_pk = col.is_primary_key || pk_columns.contains(col.name.as_str());
            if col.not_null || is_pk {
                not_null_columns.push(col.name.clone());
            }
            rel_state.apply_column_action(&ColumnAction::Add {
                name: col.name.clone(),
                data_type: col.ty.clone(),
                not_null: col.not_null || is_pk,
                default: col.default.clone(),
            });
            if let Some(column) = rel_state
                .columns
                .iter_mut()
                .find(|column| column.name == col.name)
            {
                column.is_nullable &= !(col.not_null || is_pk);
                if col.default.is_some() {
                    column.default = RelationState::normalize_column_default(&col.default);
                    column.default_expr_text = None;
                }
            }
            if let Some(column) = rel_state
                .columns
                .iter_mut()
                .find(|column| column.name == col.name)
            {
                column.type_id = column
                    .data_type
                    .as_deref()
                    .and_then(|raw| self.resolve_type_reference(raw));
                column.type_modifier = col.type_modifier;
                if matches!(
                    col.generation,
                    crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored
                        | crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual
                ) {
                    column.generated = Some(true);
                }
            }
            if matches!(
                col.generation,
                crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored
                    | crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual
            ) {
                rel_state.generated_columns.insert(
                    col.name.clone(),
                    crate::_internal::model::relation::GeneratedColumnState {
                        kind: match col.generation {
                            crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored => {
                                crate::_internal::model::relation::GeneratedColumnKind::Stored
                            }
                            crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual => {
                                crate::_internal::model::relation::GeneratedColumnKind::Virtual
                            }
                            _ => unreachable!("generated kind checked above"),
                        },
                        expression: col.generated_expr_sql.clone(),
                    },
                );
            }
            if matches!(
                col.generation,
                crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways
                    | crate::_internal::analysis::facts::ColumnGeneration::IdentityByDefault
            ) {
                rel_state.identity_columns.insert(
                    col.name.clone(),
                    match col.generation {
                        crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways => {
                            crate::_internal::model::relation::IdentityGeneration::Always
                        }
                        crate::_internal::analysis::facts::ColumnGeneration::IdentityByDefault => {
                            crate::_internal::model::relation::IdentityGeneration::ByDefault
                        }
                        _ => unreachable!("identity generation checked above"),
                    },
                );
            }
        }

        for column in &rel_state.columns {
            let parent_count = create
                .inherits
                .iter()
                .chain(create.partition_of.iter())
                .filter(|parent| {
                    matches!(self.local.relations.get(*parent),
                    Some(RelationOverlay::Present(relation)) if relation.has_column(&column.name))
                })
                .count() as u32;
            let is_local = create.partition_of.is_none()
                && (parent_count == 0
                    || create
                        .columns
                        .iter()
                        .any(|declared| declared.name == column.name));
            rel_state.column_inheritance.insert(
                column.name.clone(),
                crate::_internal::model::relation::ColumnInheritance {
                    parent_count,
                    is_local,
                },
            );
        }

        for (sequence_id, column_name, _, _) in &implicit_sequences {
            if let Some(column) = rel_state
                .columns
                .iter_mut()
                .find(|column| column.name == *column_name)
            {
                column.default = Some(Self::sequence_nextval_default(sequence_id));
                column.default_expr_text = Some(format!(
                    "nextval('{}.{}'::regclass)",
                    sequence_id.schema, sequence_id.name
                ));
                column.is_nullable = false;
            }
        }

        self.local
            .relations
            .insert(create.id.clone(), RelationOverlay::Present(rel_state));

        if !like_dependency_edges.is_empty() {
            self.snapshot_graph();
            for edge in like_dependency_edges {
                self.local.graph.add_edge(edge);
            }
        }

        for column in &create.columns {
            let Some(expr) = &column.generated_expr else {
                continue;
            };
            let Some(references) = expr.referenced_columns() else {
                self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Statement);
                continue;
            };
            self.snapshot_graph();
            for depends_on_column in references {
                self.local.graph.add_edge(DependencyEdge::new(
                    create.id.clone(),
                    create.id.clone(),
                    DependencyKind::ColumnGeneratedFrom {
                        column: column.name.clone(),
                        depends_on_column,
                    },
                ));
            }
        }

        for column in &not_null_columns {
            self.register_not_null_constraint(&create.id, column);
        }

        for (name, columns, definition) in like_check_constraints {
            self.snapshot_constraint(&create.id, &name);
            self.local.constraints.insert(
                (create.id.clone(), name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name: name.clone(),
                    kind: ConstraintKind::Check,
                    validated: true,
                    definition: Some(definition),
                    backing_index: None,
                },
            );
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                create.id.clone(),
                DependencyKind::ConstraintDependency {
                    constraint_name: name,
                    columns,
                },
            ));
        }

        for (index_id, index_kind, constraint) in like_index_plans {
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                index_id.clone(),
                create.id.clone(),
                index_kind,
            ));
            if let Some((kind, columns)) = constraint {
                let constraint_name = index_id.name.clone();
                self.snapshot_constraint(&create.id, &constraint_name);
                self.local.constraints.insert(
                    (create.id.clone(), constraint_name.clone()),
                    ConstraintState {
                        table_id: create.id.clone(),
                        name: constraint_name.clone(),
                        kind,
                        validated: true,
                        definition: None,
                        backing_index: Some(index_id),
                    },
                );
                self.snapshot_graph();
                self.local.graph.add_edge(DependencyEdge::new(
                    create.id.clone(),
                    create.id.clone(),
                    match kind {
                        ConstraintKind::PrimaryKey | ConstraintKind::Unique => {
                            DependencyKind::ConstraintOnRelation {
                                constraint_name,
                                columns,
                                is_primary: matches!(kind, ConstraintKind::PrimaryKey),
                            }
                        }
                        ConstraintKind::Exclusion => DependencyKind::ConstraintDependency {
                            constraint_name,
                            columns,
                        },
                        _ => unreachable!("LIKE INDEXES clones only index-backed constraints"),
                    },
                ));
            }
        }

        for (sequence_id, column_name, kind, parameters) in implicit_sequences {
            self.snapshot_sequence(&sequence_id);
            self.snapshot_generation_counter();
            self.local.generation_counter += 1;
            self.local.sequences.insert(
                sequence_id.clone(),
                SequenceOverlay::Present(SequenceState {
                    id: sequence_id.clone(),
                    owner: ObjectId::new("", &self.local.current_role),
                    owned_by: Some((create.id.clone(), column_name.clone())),
                    kind,
                    parameters,
                    generation: self.local.generation_counter,
                }),
            );
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                sequence_id,
                create.id.clone(),
                DependencyKind::SequenceOwnedBy {
                    column: column_name,
                },
            ));
        }

        if let Some(name) = primary_key_constraint_name.clone() {
            let index_id = ObjectId::new(&create.id.schema, &name);
            self.snapshot_constraint(&create.id, &name);
            self.local.constraints.insert(
                (create.id.clone(), name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name: name.clone(),
                    kind: ConstraintKind::PrimaryKey,
                    validated: true,
                    definition: None,
                    backing_index: Some(index_id.clone()),
                },
            );
            let columns = create
                .table_constraints
                .iter()
                .find_map(|constraint| match constraint {
                    TableConstraintFact::PrimaryKey { columns, .. } => Some(columns.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| {
                    create
                        .columns
                        .iter()
                        .filter(|column| column.is_primary_key)
                        .map(|column| column.name.clone())
                        .collect()
                });
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                index_id,
                create.id.clone(),
                Self::constraint_index_dependency(columns, true),
            ));
        }

        for (name, columns) in unique_constraint_names {
            let index_id = ObjectId::new(&create.id.schema, &name);
            self.snapshot_constraint(&create.id, &name);
            self.local.constraints.insert(
                (create.id.clone(), name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name: name.clone(),
                    kind: ConstraintKind::Unique,
                    validated: true,
                    definition: None,
                    backing_index: Some(index_id.clone()),
                },
            );
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                index_id,
                create.id.clone(),
                Self::constraint_index_dependency(columns.clone(), true),
            ));
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                create.id.clone(),
                DependencyKind::ConstraintOnRelation {
                    constraint_name: name,
                    columns,
                    is_primary: false,
                },
            ));
        }

        if let Some(parent_id) = &create.partition_of {
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                parent_id.clone(),
                DependencyKind::PartitionOf,
            ));
        }
        for parent_id in &create.inherits {
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                parent_id.clone(),
                DependencyKind::InheritanceOf,
            ));
        }

        if !create.foreign_keys.is_empty() {
            self.snapshot_graph();
        }

        for ((fk, constraint_name), referenced_columns) in create
            .foreign_keys
            .iter()
            .zip(foreign_key_constraint_names)
            .zip(effective_fk_target_columns)
        {
            self.snapshot_constraint(&create.id, &constraint_name);
            self.local.constraints.insert(
                (create.id.clone(), constraint_name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name: constraint_name.clone(),
                    kind: ConstraintKind::ForeignKey,
                    validated: true,
                    definition: None,
                    backing_index: None,
                },
            );
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                fk.to_table.clone(),
                DependencyKind::ForeignKey {
                    constraint_name: Some(constraint_name),
                    from_columns: fk.from_columns.clone(),
                    to_columns: referenced_columns,
                    operator_evidence: None,
                    from_generation: generation,
                },
            ));
        }
        for (constraint_name, edge) in partition_foreign_keys {
            let DependencyKind::ForeignKey {
                from_columns,
                to_columns,
                operator_evidence,
                ..
            } = edge.kind
            else {
                unreachable!("partition foreign-key plans contain only foreign keys")
            };
            self.snapshot_constraint(&create.id, &constraint_name);
            self.local.constraints.insert(
                (create.id.clone(), constraint_name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name: constraint_name.clone(),
                    kind: ConstraintKind::ForeignKey,
                    validated: true,
                    definition: None,
                    backing_index: None,
                },
            );
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                edge.referenced,
                DependencyKind::ForeignKey {
                    constraint_name: Some(constraint_name),
                    from_columns,
                    to_columns,
                    operator_evidence,
                    from_generation: generation,
                },
            ));
        }
        for (kind, name, definition, columns, columns_complete, backing_index) in
            inline_constraint_names
        {
            self.snapshot_constraint(&create.id, &name);
            self.local.constraints.insert(
                (create.id.clone(), name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name: name.clone(),
                    kind,
                    validated: true,
                    definition,
                    backing_index: backing_index.clone(),
                },
            );
            if let Some(index_id) = backing_index {
                self.snapshot_graph();
                self.local.graph.add_edge(DependencyEdge::new(
                    index_id,
                    create.id.clone(),
                    DependencyKind::IndexOnRelation {
                        using_method: None,
                        key_columns: columns.clone(),
                        included_columns: Vec::new(),
                        dependency_columns: columns.clone(),
                        dependency_columns_known: columns_complete,
                        has_expression_keys: true,
                        has_predicate: false,
                        is_concurrent: false,
                        is_unique: false,
                        is_immediate: true,
                        is_valid: true,
                        is_ready: true,
                        is_live: true,
                        has_default_sort_order: false,
                        has_default_opclasses: false,
                        has_default_collations: false,
                        eligibility_known: false,
                    },
                ));
            }
            if columns_complete {
                self.snapshot_graph();
                self.local.graph.add_edge(DependencyEdge::new(
                    create.id.clone(),
                    create.id.clone(),
                    DependencyKind::ConstraintDependency {
                        constraint_name: name,
                        columns,
                    },
                ));
            } else {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
        }
        if let Some(name) = primary_key_constraint_name {
            let columns = create
                .table_constraints
                .iter()
                .find_map(|constraint| match constraint {
                    TableConstraintFact::PrimaryKey { columns, .. } => Some(columns.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| {
                    create
                        .columns
                        .iter()
                        .filter(|column| column.is_primary_key)
                        .map(|column| column.name.clone())
                        .collect()
                });
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                create.id.clone(),
                DependencyKind::ConstraintOnRelation {
                    constraint_name: name,
                    columns,
                    is_primary: true,
                },
            ));
        }
        if let Some(parent) = &create.partition_of {
            let generated_partition_constraint =
                self.local
                    .relations
                    .get(&create.id)
                    .and_then(|overlay| match overlay {
                        RelationOverlay::Present(relation) => Some(relation),
                        RelationOverlay::Dropped => None,
                    })
                    .and_then(|relation| {
                        let bound = relation.partition_bound.as_deref()?;
                        if bound.eq_ignore_ascii_case("DEFAULT") {
                            self.synthesize_default_partition_constraint(parent)
                        } else {
                            let strategy = self.local.relations.get(parent).and_then(
                                |overlay| match overlay {
                                    RelationOverlay::Present(parent) => {
                                        parent.partition_type.as_deref()
                                    }
                                    RelationOverlay::Dropped => None,
                                },
                            )?;
                            let keys = self.partition_key_columns(parent)?;
                            self.synthesize_partition_check(strategy, bound, &keys, relation)
                        }
                    });
            if generated_partition_constraint.is_some()
                && let Some(RelationOverlay::Present(relation)) =
                    self.local.relations.get_mut(&create.id)
            {
                relation.partition_constraint = generated_partition_constraint;
            }
            let result = self.clone_row_triggers_to_partition(parent, &create.id);
            debug_assert!(matches!(result, MutationResult::Applied));
            if !matches!(result, MutationResult::Applied) {
                return result;
            }
        }
        MutationResult::Applied
    }

    /// `ALTER TABLE ... ADD CONSTRAINT ... USING INDEX` transfers ownership
    /// of the index to the constraint. PostgreSQL renames the index when an
    /// explicit constraint name differs, so keep the modeled index identity
    /// in sync with the catalog-visible name.
    fn adopt_index_for_constraint(
        &mut self,
        index: &ObjectId,
        table: &ObjectId,
        constraint_name: &str,
    ) {
        let adopted = ObjectId::new(index.schema.clone(), constraint_name);
        if adopted == *index {
            return;
        }
        let Some(edge) = self
            .local
            .graph
            .edges()
            .iter()
            .find(|edge| {
                matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                    && edge.dependent == *index
                    && edge.referenced == *table
            })
            .cloned()
        else {
            return;
        };
        let DependencyKind::IndexOnRelation {
            using_method,
            key_columns,
            included_columns,
            dependency_columns,
            dependency_columns_known,
            has_expression_keys,
            has_predicate,
            is_concurrent,
            is_unique,
            is_immediate,
            is_valid,
            is_ready,
            is_live,
            has_default_sort_order,
            has_default_opclasses,
            has_default_collations,
            eligibility_known,
        } = edge.kind
        else {
            return;
        };
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|existing| {
            !(matches!(existing.kind, DependencyKind::IndexOnRelation { .. })
                && existing.dependent == *index)
        });
        self.local.graph.add_edge(DependencyEdge::new(
            adopted,
            table.clone(),
            DependencyKind::IndexOnRelation {
                using_method,
                key_columns,
                included_columns,
                dependency_columns,
                dependency_columns_known,
                has_expression_keys,
                has_predicate,
                is_concurrent,
                is_unique,
                is_immediate,
                is_valid,
                is_ready,
                is_live,
                has_default_sort_order,
                has_default_opclasses,
                has_default_collations,
                eligibility_known,
            },
        ));
    }

    pub(super) fn apply_alter_table(&mut self, alter: &AlterTable) -> MutationResult {
        let recursive_rename_descendants = if !alter.only
            && matches!(alter.action, AlterTableActionMutation::RenameColumn { .. })
        {
            self.inherited_descendants(&alter.id)
        } else {
            Vec::new()
        };
        if let AlterTableActionMutation::RenameColumn { from, to } = &alter.action {
            for descendant in &recursive_rename_descendants {
                let Some(RelationOverlay::Present(relation)) = self.local.relations.get(descendant)
                else {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                    return MutationResult::Skipped;
                };
                if relation.has_column(to) {
                    return MutationResult::Conflict {
                        reason: format!(
                            "column '{}' already exists on relation '{}'",
                            to, descendant
                        ),
                    };
                }
                if relation.generated_columns.values().any(|generated| {
                    generated.expression.as_deref().is_none_or(|source| {
                        crate::_internal::analysis::expr_visitor::ExprVisitor::rename_column_source(
                            source,
                            &descendant.name,
                            from,
                            to,
                        )
                        .is_none()
                    })
                }) {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                    return MutationResult::Skipped;
                }
                let Some(provenance) = relation.column_inheritance.get(from) else {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                    return MutationResult::Skipped;
                };
                let expected_parents = self
                    .local
                    .graph
                    .edges()
                    .iter()
                    .filter(|edge| {
                        edge.dependent == *descendant
                            && matches!(
                                edge.kind,
                                DependencyKind::InheritanceOf | DependencyKind::PartitionOf
                            )
                            && (edge.referenced == alter.id
                                || recursive_rename_descendants.contains(&edge.referenced))
                    })
                    .count() as u32;
                if provenance.parent_count > expected_parents {
                    return MutationResult::Conflict {
                        reason: format!("cannot rename inherited column '{}'", from),
                    };
                }
            }
        }
        if alter.only
            && matches!(alter.action, AlterTableActionMutation::RenameColumn { .. })
            && self.local.graph.edges().iter().any(|edge| {
                matches!(
                    edge.kind,
                    DependencyKind::InheritanceOf
                        | DependencyKind::PartitionOf
                        | DependencyKind::PartitionDetachPending
                ) && self.local.graph.resolve_rename(&edge.referenced)
                    == self.local.graph.resolve_rename(&alter.id)
            })
        {
            return MutationResult::Conflict {
                reason: "inherited columns must be renamed in child tables too".into(),
            };
        }
        let concurrent_detach = matches!(
            alter.action,
            AlterTableActionMutation::DetachPartition {
                mode: crate::_internal::analysis::facts::DetachPartitionMode::Concurrently,
                ..
            }
        );
        if concurrent_detach && self.in_transaction() {
            return MutationResult::Conflict {
                reason: "DETACH PARTITION CONCURRENTLY cannot run inside a transaction".into(),
            };
        }
        match self.relation_lookup(&alter.id, |kind| *kind == RelationKind::Table) {
            ObjectLookup::Present => {}
            ObjectLookup::WrongKind => {
                return MutationResult::Conflict {
                    reason: format!("object '{}' is not a table", alter.id),
                };
            }
            ObjectLookup::AuthoritativelyAbsent | ObjectLookup::Tombstone => {
                return MutationResult::Conflict {
                    reason: format!("relation '{}' does not exist", alter.id),
                };
            }
            ObjectLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            }
        }

        if let AlterTableActionMutation::OwnerTo { new_owner } = &alter.action {
            let Some((owner, known)) = self.role_fact_identity(new_owner) else {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
                return MutationResult::Skipped;
            };
            if !known {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
            if known && self.local.roles_known && self.present_role(&owner).is_none() {
                return MutationResult::Conflict {
                    reason: format!("role '{}' does not exist", owner),
                };
            }
            if known && !self.local.roles_known {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
            self.snapshot_relation(&alter.id);
            let result = match self.local.relations.get_mut(&alter.id) {
                Some(RelationOverlay::Present(relation)) => {
                    relation.owner = ObjectId::new("", owner.clone());
                    MutationResult::Applied
                }
                _ => MutationResult::Conflict {
                    reason: format!("relation '{}' does not exist", alter.id),
                },
            };
            if matches!(result, MutationResult::Applied) {
                self.transfer_owned_sequence_owners(&alter.id, &ObjectId::new("", owner));
            }
            return result;
        }

        // Validate all targets before taking snapshots or creating implicit
        // sequences. RelationState's low-level column helper intentionally
        // ignores missing names, but PostgreSQL rejects those ALTER TABLE
        // actions; silently continuing would make later state look valid.
        let Some(RelationOverlay::Present(relation)) = self.local.relations.get(&alter.id) else {
            return MutationResult::Conflict {
                reason: format!("relation '{}' does not exist", alter.id),
            };
        };
        let relation_columns_known =
            !relation.columns.is_empty() || relation.estimated_rows.is_some();
        if let AlterTableActionMutation::SetRuleMode { rule_name, mode } = &alter.action {
            let Some(rule_name) = rule_name else {
                self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Statement);
                return MutationResult::Skipped;
            };
            if !relation.rules.contains_key(rule_name) {
                return MutationResult::Conflict {
                    reason: format!(
                        "rule '{}' does not exist on relation '{}'",
                        rule_name, alter.id
                    ),
                };
            }
            self.snapshot_relation(&alter.id);
            let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(&alter.id)
            else {
                unreachable!("relation presence was checked before rule mutation")
            };
            relation.rules.insert(rule_name.clone(), *mode);
            return MutationResult::Applied;
        }
        // Adding a column does not need to enumerate existing columns when the
        // baseline is incomplete; the new column is still represented in the
        // post-statement state.  Other column-targeting actions remain
        // conservative until their target list is known.
        if !relation_columns_known
            && matches!(
                alter.action,
                AlterTableActionMutation::DropColumn { .. }
                    | AlterTableActionMutation::RenameColumn { .. }
                    | AlterTableActionMutation::SetNotNull { .. }
                    | AlterTableActionMutation::DropNotNull { .. }
                    | AlterTableActionMutation::SetType { .. }
                    | AlterTableActionMutation::SetDefault { .. }
                    | AlterTableActionMutation::SetStorage { .. }
                    | AlterTableActionMutation::SetCompression { .. }
                    | AlterTableActionMutation::SetStatistics { .. }
                    | AlterTableActionMutation::SetGeneratedExpression { .. }
                    | AlterTableActionMutation::DropGeneratedExpression { .. }
                    | AlterTableActionMutation::SetColumnOptions { .. }
                    | AlterTableActionMutation::ResetColumnOptions { .. }
            )
        {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
            return MutationResult::Skipped;
        }
        match &alter.action {
            AlterTableActionMutation::AddColumn {
                name,
                ty,
                if_not_exists,
                ..
            } if relation.has_column(name) => {
                return if *if_not_exists {
                    MutationResult::Skipped
                } else {
                    MutationResult::Conflict {
                        reason: format!(
                            "column '{}' already exists with type {}; this statement adds it again with type {}",
                            name,
                            relation
                                .columns
                                .iter()
                                .find(|column| column.name == *name)
                                .and_then(|column| column.data_type.as_deref())
                                .unwrap_or("unknown"),
                            ty.as_deref().unwrap_or("unknown"),
                        ),
                    }
                };
            }
            AlterTableActionMutation::DropColumn {
                name, if_exists, ..
            } if !relation.has_column(name) => {
                return if *if_exists {
                    MutationResult::Skipped
                } else {
                    MutationResult::Conflict {
                        reason: format!(
                            "column '{}' does not exist on relation '{}'",
                            name, alter.id
                        ),
                    }
                };
            }
            AlterTableActionMutation::RenameColumn { from, to } => {
                if !relation.has_column(from) {
                    return MutationResult::Conflict {
                        reason: format!(
                            "column '{}' does not exist on relation '{}'",
                            from, alter.id
                        ),
                    };
                }
                if relation.has_column(to) {
                    return MutationResult::Conflict {
                        reason: format!(
                            "column '{}' already exists on relation '{}'",
                            to, alter.id
                        ),
                    };
                }
                if relation.generated_columns.values().any(|generated| {
                    generated.expression.as_deref().is_none_or(|source| {
                        crate::_internal::analysis::expr_visitor::ExprVisitor::rename_column_source(
                            source,
                            &alter.id.name,
                            from,
                            to,
                        )
                        .is_none()
                    })
                }) {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                    return MutationResult::Skipped;
                }
            }
            AlterTableActionMutation::SetNotNull { column }
            | AlterTableActionMutation::DropNotNull { column }
            | AlterTableActionMutation::SetType { column, .. }
            | AlterTableActionMutation::SetDefault { column, .. }
            | AlterTableActionMutation::SetStorage { column, .. }
            | AlterTableActionMutation::SetCompression { column, .. }
            | AlterTableActionMutation::SetStatistics { column, .. }
            | AlterTableActionMutation::SetGeneratedExpression { column, .. }
            | AlterTableActionMutation::DropGeneratedExpression { column, .. }
            | AlterTableActionMutation::SetColumnOptions { column, .. }
            | AlterTableActionMutation::ResetColumnOptions { column, .. }
                if !relation.has_column(column) =>
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "column '{}' does not exist on relation '{}'",
                        column, alter.id
                    ),
                };
            }
            AlterTableActionMutation::SetCompression {
                method: Some(method),
                ..
            } if !method.eq_ignore_ascii_case("pglz") => {
                // lz4 availability is a PostgreSQL build capability, not a
                // catalog fact carried by V8. Do not claim an exact result.
                self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Statement);
                return MutationResult::Skipped;
            }
            AlterTableActionMutation::SetGeneratedExpression { column, expr, .. } => {
                if !relation.generated_columns.contains_key(column) {
                    return MutationResult::Conflict {
                        reason: format!(
                            "column '{}.{}' is not a generated column",
                            alter.id, column
                        ),
                    };
                }
                let Some(references) = expr.referenced_columns() else {
                    self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Statement);
                    return MutationResult::Skipped;
                };
                if let Some(reference) = references
                    .iter()
                    .find(|reference| *reference == column || !relation.has_column(reference))
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "generated expression for '{}.{}' references invalid column '{}'",
                            alter.id, column, reference
                        ),
                    };
                }
            }
            AlterTableActionMutation::DropGeneratedExpression { column, if_exists }
                if !relation.generated_columns.contains_key(column) =>
            {
                return if *if_exists {
                    MutationResult::Skipped
                } else {
                    MutationResult::Conflict {
                        reason: format!(
                            "column '{}.{}' has no generated expression",
                            alter.id, column
                        ),
                    }
                };
            }
            _ => {}
        }

        match &alter.action {
            AlterTableActionMutation::DropConstraint {
                name, if_exists, ..
            } => {
                if !self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), name.clone()))
                {
                    return if *if_exists
                        && self.baseline_covers_family_object(
                            &alter.id,
                            crate::_internal::db::cache::CatalogFamily::Relations,
                        ) {
                        MutationResult::Skipped
                    } else if self.baseline_covers_family_object(
                        &alter.id,
                        crate::_internal::db::cache::CatalogFamily::Relations,
                    ) {
                        MutationResult::Conflict {
                            reason: format!(
                                "constraint '{}' does not exist on relation '{}'",
                                name, alter.id
                            ),
                        }
                    } else {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                        MutationResult::Skipped
                    };
                }
            }
            AlterTableActionMutation::ValidateConstraint {
                constraint_name: name,
            } => {
                if !self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), name.clone()))
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "constraint '{}' does not exist on relation '{}'",
                            name, alter.id
                        ),
                    };
                }
            }
            AlterTableActionMutation::RenameConstraint { old_name, new_name } => {
                if !self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), old_name.clone()))
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "constraint '{}' does not exist on relation '{}'",
                            old_name, alter.id
                        ),
                    };
                }
                if self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), new_name.clone()))
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "constraint '{}' already exists on relation '{}'",
                            new_name, alter.id
                        ),
                    };
                }
                let constraint = &self.local.constraints[&(alter.id.clone(), old_name.clone())];
                if matches!(
                    constraint.kind,
                    ConstraintKind::PrimaryKey | ConstraintKind::Unique | ConstraintKind::Exclusion
                ) && let Some(index) = &constraint.backing_index
                {
                    return self.apply_rename_relation(&Rename {
                        old_id: index.clone(),
                        new_id: ObjectId::new(index.schema.clone(), new_name.clone()),
                    });
                }
            }
            AlterTableActionMutation::AddForeignKey {
                constraint_name,
                from_columns,
                ..
            } => {
                let name = constraint_name.clone().unwrap_or_else(|| {
                    self.next_generated_constraint_name_avoiding(
                        &alter.id,
                        &alter.id.name,
                        Some(&from_columns.join("_")),
                        "fkey",
                        &HashSet::new(),
                    )
                });
                if self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), name.clone()))
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "constraint '{}' already exists on relation '{}'",
                            name, alter.id
                        ),
                    };
                }
            }
            AlterTableActionMutation::AddCheckConstraint {
                constraint_name,
                columns,
                columns_complete,
                ..
            } => {
                let name = constraint_name.clone().unwrap_or_else(|| {
                    self.next_generated_constraint_name_avoiding(
                        &alter.id,
                        &alter.id.name,
                        (*columns_complete && columns.len() == 1).then(|| columns[0].as_str()),
                        "check",
                        &HashSet::new(),
                    )
                });
                if self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), name.clone()))
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "constraint '{}' already exists on relation '{}'",
                            name, alter.id
                        ),
                    };
                }
            }
            AlterTableActionMutation::AddExcludeConstraint {
                constraint_name, ..
            } => {
                let name = constraint_name.clone().unwrap_or_else(|| {
                    self.next_generated_constraint_name_avoiding(
                        &alter.id,
                        &alter.id.name,
                        None,
                        "excl",
                        &HashSet::new(),
                    )
                });
                if self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), name.clone()))
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "constraint '{}' already exists on relation '{}'",
                            name, alter.id
                        ),
                    };
                }
            }
            AlterTableActionMutation::AddUniqueConstraint {
                constraint_name,
                columns,
                using_index,
            }
            | AlterTableActionMutation::AddPrimaryKeyConstraint {
                constraint_name,
                columns,
                using_index,
            } => {
                if using_index.is_none() {
                    if columns.is_empty() {
                        return MutationResult::Conflict {
                            reason: "key constraint must name at least one column".to_string(),
                        };
                    }
                    let mut key_columns = HashSet::new();
                    for column in columns {
                        if !key_columns.insert(column) {
                            return MutationResult::Conflict {
                                reason: format!(
                                    "column '{}' appears more than once in a key constraint",
                                    column
                                ),
                            };
                        }
                        if relation_columns_known && !relation.has_column(column) {
                            return MutationResult::Conflict {
                                reason: format!(
                                    "constraint references column '{}' which does not exist on relation '{}'",
                                    column, alter.id
                                ),
                            };
                        }
                    }
                }
                if matches!(
                    &alter.action,
                    AlterTableActionMutation::AddPrimaryKeyConstraint { .. }
                ) && self
                    .local
                    .constraints
                    .iter()
                    .any(|((table, _), constraint)| {
                        table == &alter.id && constraint.kind == ConstraintKind::PrimaryKey
                    })
                {
                    return MutationResult::Conflict {
                        reason: format!("relation '{}' already has a primary key", alter.id),
                    };
                }
                let name = constraint_name
                    .clone()
                    .or_else(|| using_index.as_ref().map(|index| index.name.clone()))
                    .unwrap_or_else(|| {
                        self.next_generated_constraint_name_avoiding(
                            &alter.id,
                            &alter.id.name,
                            None,
                            if matches!(
                                &alter.action,
                                AlterTableActionMutation::AddPrimaryKeyConstraint { .. }
                            ) {
                                "pkey"
                            } else {
                                "key"
                            },
                            &HashSet::new(),
                        )
                    });
                if self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), name.clone()))
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "constraint '{}' already exists on relation '{}'",
                            name, alter.id
                        ),
                    };
                }
                if using_index.is_none()
                    && self.relation_namespace_object_is_present(&ObjectId::new(
                        &alter.id.schema,
                        &name,
                    ))
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "constraint index '{}.{}' already exists",
                            alter.id.schema, name
                        ),
                    };
                }
            }
            AlterTableActionMutation::AlterConstraint { name, .. } => {
                let Some(name) = name else {
                    self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
                    return MutationResult::Applied;
                };
                if !self
                    .local
                    .constraints
                    .contains_key(&(alter.id.clone(), name.clone()))
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "constraint '{}' does not exist on relation '{}'",
                            name, alter.id
                        ),
                    };
                }
                self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
                return MutationResult::Applied;
            }
            AlterTableActionMutation::AttachPartition {
                child, strategy, ..
            } => {
                if let Err(result) = self.ensure_relation_target(
                    child,
                    |kind| *kind == RelationKind::Table,
                    format!("partition child relation '{}' does not exist", child),
                    format!("partition child '{}' is not a table", child),
                ) {
                    return result;
                }
                let Some(RelationOverlay::Present(parent)) = self.local.relations.get(&alter.id)
                else {
                    unreachable!("alter target presence established above")
                };
                let Some(partition_type) = &parent.partition_type else {
                    return MutationResult::Conflict {
                        reason: format!("partition parent '{}' is not partitioned", alter.id),
                    };
                };
                if strategy
                    .as_deref()
                    .is_some_and(|strategy| !strategy.eq_ignore_ascii_case(partition_type))
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "partition strategy for '{}' does not match parent '{}' ({})",
                            child, alter.id, partition_type
                        ),
                    };
                }
                if self.local.graph.check_partition_cycle(&alter.id, child) {
                    return MutationResult::Conflict {
                        reason: format!(
                            "attaching partition '{}' to '{}' would create a partition cycle",
                            child, alter.id
                        ),
                    };
                }
                let existing_parent = self.local.graph.edges().iter().find_map(|edge| {
                    (matches!(
                        edge.kind,
                        DependencyKind::PartitionOf | DependencyKind::PartitionDetachPending
                    ) && edge.dependent == *child)
                        .then_some(edge.referenced.clone())
                });
                if let Some(existing_parent) = existing_parent {
                    return MutationResult::Conflict {
                        reason: format!(
                            "partition '{}' is already attached to '{}'",
                            child, existing_parent
                        ),
                    };
                }
                match self.partition_attachment_is_compatible(&alter.id, child) {
                    Ok(true) => {}
                    Ok(false) => {
                        // Missing catalog detail should lower confidence, not
                        // erase the attachment from the transition state. The
                        // taint keeps downstream findings conservative while
                        // the mutation retains the edge and bound.
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    }
                    Err(reason) => return MutationResult::Conflict { reason },
                }
            }
            AlterTableActionMutation::DetachPartition { child, mode } => {
                if matches!(
                    mode,
                    crate::_internal::analysis::facts::DetachPartitionMode::Concurrently
                ) {
                    for edge in self
                        .local
                        .graph
                        .edges()
                        .iter()
                        .filter(|edge| edge.referenced == alter.id)
                    {
                        if matches!(edge.kind, DependencyKind::PartitionDetachPending) {
                            return MutationResult::Conflict {
                                reason: format!(
                                    "parent '{}' already has a partition pending detach",
                                    alter.id
                                ),
                            };
                        }
                        if matches!(edge.kind, DependencyKind::PartitionOf)
                            && let Some(RelationOverlay::Present(partition)) =
                                self.local.relations.get(&edge.dependent)
                            && partition
                                .partition_bound
                                .as_deref()
                                .is_some_and(|bound| bound.trim().eq_ignore_ascii_case("DEFAULT"))
                        {
                            return MutationResult::Conflict {
                                reason: format!(
                                    "cannot detach concurrently from '{}' while it has a default partition",
                                    alter.id
                                ),
                            };
                        }
                    }
                }
                if let Err(result) = self.ensure_relation_target(
                    child,
                    |kind| *kind == RelationKind::Table,
                    format!("partition child relation '{}' does not exist", child),
                    format!("partition child '{}' is not a table", child),
                ) {
                    return result;
                }
                let expected_kind = match mode {
                    crate::_internal::analysis::facts::DetachPartitionMode::Finalize => {
                        DependencyKind::PartitionDetachPending
                    }
                    crate::_internal::analysis::facts::DetachPartitionMode::Immediate
                    | crate::_internal::analysis::facts::DetachPartitionMode::Concurrently => {
                        DependencyKind::PartitionOf
                    }
                };
                if !self.local.graph.edges().iter().any(|edge| {
                    edge.kind == expected_kind
                        && edge.dependent == *child
                        && edge.referenced == alter.id
                }) {
                    let action = match mode {
                        crate::_internal::analysis::facts::DetachPartitionMode::Finalize => {
                            "has no pending concurrent detach from"
                        }
                        _ => "is not attached to",
                    };
                    return MutationResult::Conflict {
                        reason: format!("partition '{}' {} parent '{}'", child, action, alter.id),
                    };
                }
            }
            AlterTableActionMutation::InheritTable { parent }
            | AlterTableActionMutation::NoInheritTable { parent } => {
                if let Err(result) = self.ensure_relation_target(
                    parent,
                    |kind| *kind == RelationKind::Table,
                    format!("inheritance parent relation '{}' does not exist", parent),
                    format!("inheritance parent '{}' is not a table", parent),
                ) {
                    return result;
                }
                let has_edge = self.local.graph.edges().iter().any(|edge| {
                    matches!(edge.kind, DependencyKind::InheritanceOf)
                        && edge.dependent == alter.id
                        && edge.referenced == *parent
                });
                match &alter.action {
                    AlterTableActionMutation::InheritTable { .. } if has_edge => {
                        return MutationResult::Conflict {
                            reason: format!(
                                "relation '{}' already inherits from '{}'",
                                alter.id, parent
                            ),
                        };
                    }
                    AlterTableActionMutation::NoInheritTable { .. } if !has_edge => {
                        return MutationResult::Conflict {
                            reason: format!(
                                "relation '{}' does not inherit from '{}'",
                                alter.id, parent
                            ),
                        };
                    }
                    AlterTableActionMutation::InheritTable { .. }
                        if self.local.graph.check_inheritance_cycle(parent, &alter.id) =>
                    {
                        return MutationResult::Conflict {
                            reason: format!(
                                "inheriting '{}' into '{}' would create an inheritance cycle",
                                parent, alter.id
                            ),
                        };
                    }
                    AlterTableActionMutation::InheritTable { .. } => {
                        let Some(RelationOverlay::Present(parent_relation)) =
                            self.local.relations.get(parent)
                        else {
                            unreachable!("inheritance parent presence was checked above")
                        };
                        let Some(RelationOverlay::Present(child_relation)) =
                            self.local.relations.get(&alter.id)
                        else {
                            unreachable!("alter target presence was checked above")
                        };
                        for parent_column in &parent_relation.columns {
                            let Some(child_column) = child_relation.get_column(&parent_column.name)
                            else {
                                return MutationResult::Conflict {
                                    reason: format!(
                                        "relation '{}' lacks inherited column '{}'",
                                        alter.id, parent_column.name
                                    ),
                                };
                            };
                            let compatible_type = match (
                                parent_column.type_id.as_ref(),
                                child_column.type_id.as_ref(),
                                parent_column.data_type.as_deref(),
                                child_column.data_type.as_deref(),
                            ) {
                                (Some(left), Some(right), _, _) => left == right,
                                (_, _, Some(left), Some(right)) => {
                                    left.trim().eq_ignore_ascii_case(right.trim())
                                }
                                _ => false,
                            };
                            if !compatible_type
                                || (!parent_column.is_nullable && child_column.is_nullable)
                                || parent_relation.generated_columns.get(&parent_column.name)
                                    != child_relation.generated_columns.get(&parent_column.name)
                            {
                                return MutationResult::Conflict {
                                    reason: format!(
                                        "column '{}.{}' is incompatible with inheritance parent '{}'",
                                        alter.id, parent_column.name, parent
                                    ),
                                };
                            }
                        }
                        for parent_constraint in
                            self.local.constraints.values().filter(|constraint| {
                                constraint.table_id == *parent
                                    && matches!(constraint.kind, ConstraintKind::Check)
                            })
                        {
                            let Some(child_constraint) = self
                                .local
                                .constraints
                                .get(&(alter.id.clone(), parent_constraint.name.clone()))
                            else {
                                return MutationResult::Conflict {
                                    reason: format!(
                                        "relation '{}' lacks inherited CHECK constraint '{}'",
                                        alter.id, parent_constraint.name
                                    ),
                                };
                            };
                            let definitions_match = parent_constraint
                                .definition
                                .as_deref()
                                .zip(child_constraint.definition.as_deref())
                                .is_some_and(|(parent_definition, child_definition)| {
                                    Self::normalized_constraint_expression(parent_definition)
                                        == Self::normalized_constraint_expression(child_definition)
                                });
                            if !matches!(child_constraint.kind, ConstraintKind::Check)
                                || !definitions_match
                            {
                                return MutationResult::Conflict {
                                    reason: format!(
                                        "CHECK constraint '{}' is incompatible with inheritance parent '{}'",
                                        parent_constraint.name, parent
                                    ),
                                };
                            }
                        }
                    }
                    _ => {}
                }
            }
            AlterTableActionMutation::SetCluster { index: Some(index) } => {
                let owned = self.local.graph.edges().iter().any(|edge| {
                    matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                        && edge.dependent == *index
                        && edge.referenced == alter.id
                });
                if !owned {
                    return MutationResult::Conflict {
                        reason: format!(
                            "index '{}' does not belong to relation '{}'",
                            index, alter.id
                        ),
                    };
                }
            }
            AlterTableActionMutation::SetReplicaIdentity {
                option:
                    crate::_internal::analysis::mutations::ReplicaIdentityMutation::UsingIndex(index),
            } => {
                let Some(edge) = self.local.graph.edges().iter().find(|edge| {
                    edge.dependent == *index
                        && edge.referenced == alter.id
                        && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                }) else {
                    return MutationResult::Conflict {
                        reason: format!(
                            "replica identity index '{}' does not belong to relation '{}'",
                            index, alter.id
                        ),
                    };
                };
                let DependencyKind::IndexOnRelation {
                    key_columns,
                    dependency_columns_known,
                    has_expression_keys,
                    has_predicate,
                    is_unique,
                    is_immediate,
                    is_valid,
                    is_ready,
                    is_live,
                    eligibility_known,
                    ..
                } = &edge.kind
                else {
                    unreachable!("index edge was checked above");
                };
                if !*eligibility_known || !*dependency_columns_known {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                    return MutationResult::Skipped;
                }
                let all_keys_not_null = self
                    .local
                    .relations
                    .get(&alter.id)
                    .and_then(|overlay| match overlay {
                        RelationOverlay::Present(relation) => {
                            Some(key_columns.iter().all(|column| {
                                relation
                                    .columns
                                    .iter()
                                    .find(|candidate| candidate.name == *column)
                                    .is_some_and(|column| !column.is_nullable)
                            }))
                        }
                        RelationOverlay::Dropped => None,
                    })
                    .unwrap_or(false);
                if !*is_unique
                    || *has_predicate
                    || *has_expression_keys
                    || !*is_valid
                    || !*is_immediate
                    || !*is_ready
                    || !*is_live
                    || !all_keys_not_null
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "index '{}' is not eligible for replica identity on relation '{}'",
                            index, alter.id
                        ),
                    };
                }
            }
            AlterTableActionMutation::SetOfType {
                type_id: Some(type_id),
            } => {
                if self
                    .local
                    .relations
                    .get(&alter.id)
                    .and_then(|overlay| match overlay {
                        RelationOverlay::Present(relation) => relation.of_type.as_ref(),
                        RelationOverlay::Dropped => None,
                    })
                    .is_some()
                {
                    return MutationResult::Conflict {
                        reason: format!("relation '{}' is already a typed table", alter.id),
                    };
                }
                let Some(crate::_internal::model::types::TypeOverlay::Present(
                    crate::_internal::model::types::TypeState {
                        kind: crate::_internal::model::types::TypeKind::Composite { fields },
                        ..
                    },
                )) = self.local.types.get(type_id)
                else {
                    return MutationResult::Conflict {
                        reason: format!("type '{}' is not an existing composite type", type_id),
                    };
                };
                let Some(RelationOverlay::Present(relation)) = self.local.relations.get(&alter.id)
                else {
                    self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                    return MutationResult::Skipped;
                };
                let matches_layout = relation.columns.len() == fields.len()
                    && relation.columns.iter().zip(fields).all(|(column, field)| {
                        column.name == field.name
                            && column.data_type.as_deref().is_some_and(|data_type| {
                                data_type
                                    .trim()
                                    .eq_ignore_ascii_case(field.data_type.trim())
                            })
                    });
                if !matches_layout {
                    return MutationResult::Conflict {
                        reason: format!(
                            "relation '{}' does not match composite type '{}' column layout",
                            alter.id, type_id
                        ),
                    };
                }
            }
            AlterTableActionMutation::SetOfType { type_id: None } => {
                let typed = self
                    .local
                    .relations
                    .get(&alter.id)
                    .and_then(|overlay| match overlay {
                        RelationOverlay::Present(relation) => relation.of_type.as_ref(),
                        RelationOverlay::Dropped => None,
                    });
                if typed.is_none() {
                    return MutationResult::Conflict {
                        reason: format!("relation '{}' is not a typed table", alter.id),
                    };
                }
            }
            _ => {}
        }

        let trigger_mode = match &alter.action {
            AlterTableActionMutation::DisableTrigger { trigger_name } => Some((
                trigger_name.as_deref(),
                crate::_internal::model::trigger::TriggerEnableMode::Disabled,
            )),
            AlterTableActionMutation::EnableTrigger { trigger_name } => Some((
                trigger_name.as_deref(),
                crate::_internal::model::trigger::TriggerEnableMode::Origin,
            )),
            AlterTableActionMutation::SetTriggerMode { trigger_name, mode } => {
                Some((trigger_name.as_deref(), *mode))
            }
            _ => None,
        };
        if let Some((trigger_name, enabled_mode)) = trigger_mode {
            let all = trigger_name.is_none_or(|name| {
                name.eq_ignore_ascii_case("all") || name.eq_ignore_ascii_case("user")
            });
            let trigger_ids: Vec<ObjectId> = self
                .local
                .triggers
                .iter()
                .filter_map(|(id, overlay)| {
                    let TriggerOverlay::Present(trigger) = overlay else {
                        return None;
                    };
                    (trigger.table_id == alter.id
                        && (all || trigger_name == Some(trigger.name.as_str())))
                    .then(|| id.clone())
                })
                .collect();
            if trigger_ids.is_empty() && !all {
                return MutationResult::Conflict {
                    reason: format!(
                        "trigger '{}' does not exist on relation '{}'",
                        trigger_name.unwrap_or_default(),
                        alter.id
                    ),
                };
            }
            for trigger_id in trigger_ids {
                self.snapshot_trigger(&trigger_id);
                if let Some(TriggerOverlay::Present(trigger)) =
                    self.local.triggers.get_mut(&trigger_id)
                {
                    trigger.enabled_mode = enabled_mode;
                }
            }
            return MutationResult::Applied;
        }

        let mut effective_fk_target_columns: Option<Vec<String>> = None;
        if let AlterTableActionMutation::AddForeignKey {
            to_table,
            from_columns,
            to_columns,
            ..
        } = &alter.action
        {
            if from_columns.is_empty() {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key on relation '{}' has no source columns",
                        alter.id
                    ),
                };
            }
            if !to_columns.is_empty() && from_columns.len() != to_columns.len() {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key on '{}' has {} source columns but {} referenced columns",
                        alter.id,
                        from_columns.len(),
                        to_columns.len()
                    ),
                };
            }
            let mut source_columns = HashSet::new();
            if let Some(column) = from_columns
                .iter()
                .find(|column| !source_columns.insert(column.as_str()))
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key on '{}' repeats source column '{}'",
                        alter.id, column
                    ),
                };
            }
            let mut target_columns = HashSet::new();
            if let Some(column) = to_columns
                .iter()
                .find(|column| !target_columns.insert(column.as_str()))
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key on '{}' repeats referenced column '{}'",
                        alter.id, column
                    ),
                };
            }
            if let Some(RelationOverlay::Present(child)) = self.local.relations.get(&alter.id)
                && (!self.baseline_relation_is_known(&alter.id) || !child.columns.is_empty())
                && let Some(column) = from_columns.iter().find(|column| !child.has_column(column))
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key column '{}' does not exist on relation '{}'",
                        column, alter.id
                    ),
                };
            }

            if let Err(result) = self.ensure_relation_target(
                to_table,
                |kind| *kind == RelationKind::Table,
                format!(
                    "foreign key references relation '{}' which does not exist",
                    to_table
                ),
                format!("foreign key references '{}' which is not a table", to_table),
            ) {
                return result;
            }
            let Some(RelationOverlay::Present(parent)) = self.local.relations.get(to_table) else {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            };
            let target_columns_known =
                !self.baseline_relation_is_known(to_table) || !parent.columns.is_empty();
            if target_columns_known
                && let Some(column) = to_columns.iter().find(|column| !parent.has_column(column))
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key references column '{}.{}' which does not exist",
                        to_table, column
                    ),
                };
            }
            let target_keys = self.unique_keys_for_relation(to_table);
            let mut fk_evidence_unknown = target_keys.is_none();
            let referenced_columns = if to_columns.is_empty() {
                let primary_keys: Vec<&Vec<String>> = target_keys
                    .as_ref()
                    .map(|keys| {
                        keys.iter()
                            .filter_map(|(columns, is_primary)| is_primary.then_some(columns))
                            .collect()
                    })
                    .unwrap_or_default();
                if target_keys.is_some() && primary_keys.len() != 1 {
                    return MutationResult::Conflict {
                        reason: format!(
                            "foreign key on '{}' omits referenced columns but target '{}' has no single primary key",
                            alter.id, to_table
                        ),
                    };
                }
                primary_keys.first().cloned().cloned().unwrap_or_default()
            } else {
                to_columns.clone()
            };
            effective_fk_target_columns = Some(referenced_columns.clone());
            if let Some(keys) = target_keys.as_ref()
                && !keys
                    .iter()
                    .any(|(columns, _)| columns == &referenced_columns)
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key on '{}' references columns on '{}' that are not backed by a primary key or unique key",
                        alter.id, to_table
                    ),
                };
            }
            let Some(child) =
                self.local
                    .relations
                    .get(&alter.id)
                    .and_then(|overlay| match overlay {
                        RelationOverlay::Present(relation) => Some(relation.clone()),
                        RelationOverlay::Dropped => None,
                    })
            else {
                unreachable!("alter target presence established above");
            };
            let source_types: Vec<Option<(Option<ObjectId>, Option<String>)>> = from_columns
                .iter()
                .map(|column| {
                    child
                        .get_column(column)
                        .map(|state| (state.type_id.clone(), state.data_type.clone()))
                })
                .collect();
            let target_types: Vec<Option<(Option<ObjectId>, Option<String>)>> = referenced_columns
                .iter()
                .map(|column| {
                    parent
                        .get_column(column)
                        .map(|state| (state.type_id.clone(), state.data_type.clone()))
                })
                .collect();
            let mut type_evidence_unknown = false;
            let type_mismatch =
                source_types
                    .iter()
                    .zip(&target_types)
                    .any(|(source, target)| match (source, target) {
                        (Some((Some(source_id), _)), Some((Some(target_id), _))) => {
                            source_id != target_id
                        }
                        (Some((_, Some(source_ty))), Some((_, Some(target_ty)))) => {
                            !source_ty.trim().eq_ignore_ascii_case(target_ty.trim())
                        }
                        _ => {
                            type_evidence_unknown = true;
                            false
                        }
                    });
            if type_mismatch {
                // PostgreSQL permits some binary-compatible type pairs, but
                // the cache model does not carry the catalog cast graph.  A
                // mismatch therefore cannot be classified safely here.
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
                return MutationResult::Skipped;
            }
            if type_evidence_unknown {
                fk_evidence_unknown = true;
            }
            if fk_evidence_unknown {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
        }

        let implicit_add = match &alter.action {
            AlterTableActionMutation::AddColumn {
                name,
                generation,
                identity_sequence,
                ..
            } => match generation {
                crate::_internal::analysis::facts::ColumnGeneration::Serial => Some((
                    self.next_implicit_sequence_id(&alter.id, name, &HashSet::new()),
                    name.clone(),
                    SequenceKind::SerialLike,
                    None,
                )),
                crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways
                | crate::_internal::analysis::facts::ColumnGeneration::IdentityByDefault => Some((
                    identity_sequence
                        .as_ref()
                        .and_then(|options| options.sequence_name.clone())
                        .unwrap_or_else(|| {
                            self.next_implicit_sequence_id(&alter.id, name, &HashSet::new())
                        }),
                    name.clone(),
                    SequenceKind::Identity,
                    identity_sequence.clone(),
                )),
                crate::_internal::analysis::facts::ColumnGeneration::Ordinary
                | crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored
                | crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual => None,
            },
            _ => None,
        };
        if let Some((sequence_id, _, _, _)) = &implicit_add
            && self.relation_namespace_is_taken(sequence_id)
        {
            return MutationResult::Conflict {
                reason: format!("relation '{}' already exists", sequence_id),
            };
        }
        let owned_sequences_for_column: Vec<ObjectId> = match &alter.action {
            AlterTableActionMutation::DropColumn { name, .. }
            | AlterTableActionMutation::RenameColumn { from: name, .. } => self
                .local
                .sequences
                .iter()
                .filter_map(|(id, overlay)| match overlay {
                    SequenceOverlay::Present(sequence)
                        if sequence.owned_by.as_ref()
                            == Some(&(alter.id.clone(), name.clone())) =>
                    {
                        Some(id.clone())
                    }
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };

        let using_index = match &alter.action {
            AlterTableActionMutation::AddUniqueConstraint { using_index, .. }
            | AlterTableActionMutation::AddPrimaryKeyConstraint { using_index, .. } => {
                using_index.as_ref()
            }
            _ => None,
        };
        if let Some(index) = using_index {
            let Some(edge) = self
                .local
                .graph
                .edges()
                .iter()
                .find(|edge| {
                    matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                        && edge.dependent == *index
                })
                .cloned()
            else {
                return MutationResult::Conflict {
                    reason: format!(
                        "constraint references index '{}' which does not exist",
                        index
                    ),
                };
            };
            if edge.referenced != alter.id {
                return MutationResult::Conflict {
                    reason: format!(
                        "constraint index '{}' belongs to relation '{}', not '{}'",
                        index, edge.referenced, alter.id
                    ),
                };
            }
            if let DependencyKind::IndexOnRelation {
                using_method,
                has_expression_keys,
                has_predicate,
                is_unique,
                is_valid,
                is_ready,
                is_live,
                has_default_sort_order,
                has_default_opclasses,
                has_default_collations,
                eligibility_known,
                ..
            } = &edge.kind
            {
                if !*eligibility_known {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        crate::_internal::analysis::evidence::EvidenceScope::Chain,
                    );
                    return MutationResult::Skipped;
                }
                let is_btree = using_method
                    .as_deref()
                    .is_some_and(|method| method.eq_ignore_ascii_case("btree"));
                if !*is_unique
                    || *has_predicate
                    || *has_expression_keys
                    || !*is_valid
                    || !*is_ready
                    || !*is_live
                    || !*has_default_sort_order
                    || !*has_default_opclasses
                    || !*has_default_collations
                    || !is_btree
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "constraint index '{}' must be unique and non-partial, live/valid/ready, a btree with simple columns, and use the default definition",
                            index
                        ),
                    };
                }
            }

            let constraint_name = match &alter.action {
                AlterTableActionMutation::AddUniqueConstraint {
                    constraint_name, ..
                }
                | AlterTableActionMutation::AddPrimaryKeyConstraint {
                    constraint_name, ..
                } => constraint_name
                    .clone()
                    .unwrap_or_else(|| index.name.clone()),
                _ => unreachable!("using_index is only valid for key constraints"),
            };
            let adopted_index = ObjectId::new(index.schema.clone(), constraint_name);
            if adopted_index != *index && self.relation_namespace_object_is_present(&adopted_index)
            {
                return MutationResult::Conflict {
                    reason: format!("constraint index '{}' already exists", adopted_index),
                };
            }
        }

        let mut drop_column_constraints: HashSet<(ObjectId, String)> = HashSet::new();
        let mut drop_column_indexes: HashSet<ObjectId> = HashSet::new();
        let mut drop_column_statistics: HashSet<ObjectId> = HashSet::new();
        let mut cascade_generated_columns: HashSet<String> = HashSet::new();
        let mut cascade_view_roots: HashSet<ObjectId> = HashSet::new();
        if let AlterTableActionMutation::DropColumn { name, cascade, .. } = &alter.action {
            let resolved_table = self.local.graph.resolve_rename(&alter.id).clone();
            if self.baseline_relation_is_known(&resolved_table)
                && (!self.baseline_has_coverage(
                    crate::_internal::db::cache::CatalogFamily::Dependencies,
                ) || self.baseline_scoped_family_object(
                    &resolved_table,
                    crate::_internal::db::cache::CatalogFamily::Relations,
                ))
            {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
                return MutationResult::Skipped;
            }
            let mut unknown_dependency = false;
            let mut known_dependency = false;
            if let Some(RelationOverlay::Present(relation)) = self.local.relations.get(&alter.id) {
                for statistics in relation.extended_statistics.values() {
                    if statistics.columns.iter().any(|column| column == name) {
                        known_dependency = true;
                        if *cascade {
                            drop_column_statistics.insert(statistics.id.clone());
                        }
                    }
                }
            }
            for edge in self.local.graph.edges() {
                if !self.dependency_edge_is_current(edge) {
                    continue;
                }
                let dependent = self.local.graph.resolve_rename(&edge.dependent);
                let referenced = self.local.graph.resolve_rename(&edge.referenced);
                match &edge.kind {
                    DependencyKind::ForeignKey {
                        constraint_name,
                        from_columns,
                        to_columns,
                        ..
                    } if dependent == &resolved_table => {
                        if from_columns.is_empty() {
                            unknown_dependency = true;
                        } else if from_columns.iter().any(|column| column == name) {
                            known_dependency = true;
                            if let Some(constraint_name) = constraint_name {
                                drop_column_constraints
                                    .insert((resolved_table.clone(), constraint_name.clone()));
                            } else {
                                unknown_dependency = true;
                            }
                        }
                        // The source-side columns are the only columns on this
                        // relation represented by the edge. Keep this branch
                        // explicit so a future edge shape cannot be mistaken
                        // for a source-column dependency.
                        let _ = to_columns;
                    }
                    DependencyKind::ForeignKey {
                        constraint_name,
                        to_columns,
                        ..
                    } if referenced == &resolved_table => {
                        if to_columns.is_empty() {
                            unknown_dependency = true;
                        } else if to_columns.iter().any(|column| column == name) {
                            known_dependency = true;
                            if let Some(constraint_name) = constraint_name {
                                drop_column_constraints
                                    .insert((dependent.clone(), constraint_name.clone()));
                            } else {
                                unknown_dependency = true;
                            }
                        }
                    }
                    DependencyKind::ConstraintOnRelation {
                        constraint_name,
                        columns,
                        ..
                    } if dependent == &resolved_table => {
                        // A NOT NULL constraint is dropped implicitly with its
                        // column in PostgreSQL; it is not a dependent object
                        // that requires CASCADE on DROP COLUMN. The execution
                        // path removes the constraint state along with the
                        // column, so it must not gate or conflict here.
                        let is_not_null = self
                            .local
                            .constraints
                            .get(&(dependent.clone(), constraint_name.clone()))
                            .is_some_and(|constraint| {
                                matches!(constraint.kind, ConstraintKind::NotNull)
                            });
                        if is_not_null {
                            // Auto-dropped with the column; nothing to gate on.
                        } else if columns.is_empty() {
                            unknown_dependency = true;
                        } else if columns.iter().any(|column| column == name) {
                            known_dependency = true;
                            drop_column_constraints
                                .insert((resolved_table.clone(), constraint_name.clone()));
                        }
                    }
                    DependencyKind::IndexOnRelation {
                        key_columns,
                        included_columns,
                        dependency_columns,
                        dependency_columns_known,
                        has_expression_keys,
                        has_predicate,
                        ..
                    } if referenced == &resolved_table => {
                        // PostgreSQL automatically removes an index when a
                        // dependent column is dropped; it does not require
                        // CASCADE. Synchronized catalog rows prove expression
                        // and predicate columns through pg_depend. Locally
                        // parsed expression/predicate indexes do not have
                        // equivalent evidence and remain conservative.
                        if !*dependency_columns_known {
                            unknown_dependency = true;
                        } else if dependency_columns.iter().any(|column| column == name) {
                            drop_column_indexes.insert(dependent.clone());
                        } else if !*has_expression_keys && !*has_predicate {
                            debug_assert!(
                                key_columns
                                    .iter()
                                    .chain(included_columns)
                                    .all(|column| dependency_columns.contains(column))
                            );
                        }
                    }
                    DependencyKind::ViewDependency {
                        referenced_column, ..
                    } if referenced == &resolved_table => match referenced_column {
                        Some(column) if column == name => {
                            known_dependency = true;
                            if *cascade {
                                cascade_view_roots.insert(dependent.clone());
                            }
                        }
                        Some(_) => {}
                        None => unknown_dependency = true,
                    },
                    DependencyKind::ConstraintDependency {
                        constraint_name,
                        columns,
                    } if dependent == &resolved_table => {
                        if columns.iter().any(|column| column == name) {
                            known_dependency = true;
                            drop_column_constraints
                                .insert((resolved_table.clone(), constraint_name.clone()));
                        }
                    }
                    DependencyKind::ColumnGeneratedFrom {
                        column,
                        depends_on_column,
                    } if (dependent == &resolved_table || referenced == &resolved_table)
                        && column != name
                        && depends_on_column == name =>
                    {
                        known_dependency = true;
                        if *cascade {
                            cascade_generated_columns.insert(column.clone());
                        }
                    }
                    _ => {}
                }
            }

            // A generated dependent can itself participate in another
            // dependency. Compute the complete generated-column closure first
            // so CASCADE does not drop the source and leave a typed edge
            // referring to a generated column that PostgreSQL also removes.
            loop {
                let additional: Vec<String> = self
                    .local
                    .graph
                    .edges()
                    .iter()
                    .filter_map(|edge| {
                        let dependent = self.local.graph.resolve_rename(&edge.dependent);
                        let referenced = self.local.graph.resolve_rename(&edge.referenced);
                        match &edge.kind {
                            DependencyKind::ColumnGeneratedFrom {
                                column,
                                depends_on_column,
                            } if dependent == &resolved_table
                                && referenced == &resolved_table
                                && cascade_generated_columns.contains(depends_on_column)
                                && column != name
                                && !cascade_generated_columns.contains(column) =>
                            {
                                Some(column.clone())
                            }
                            _ => None,
                        }
                    })
                    .collect();
                if additional.is_empty() {
                    break;
                }
                cascade_generated_columns.extend(additional);
            }

            // A generated dependent can itself participate in another
            // dependency. Preserve exactness only for closures whose
            // dependent constraint identity is available; otherwise leave the
            // operation conservative rather than dropping a column while
            // retaining a typed foreign-key/constraint edge.
            if !cascade_generated_columns.is_empty() {
                for edge in self.local.graph.edges() {
                    if !self.dependency_edge_is_current(edge) {
                        continue;
                    }
                    let dependent = self.local.graph.resolve_rename(&edge.dependent);
                    let referenced = self.local.graph.resolve_rename(&edge.referenced);
                    match &edge.kind {
                        DependencyKind::IndexOnRelation {
                            dependency_columns,
                            dependency_columns_known,
                            ..
                        } if referenced == &resolved_table => {
                            if !*dependency_columns_known {
                                unknown_dependency = true;
                            } else if dependency_columns
                                .iter()
                                .any(|column| cascade_generated_columns.contains(column))
                            {
                                drop_column_indexes.insert(dependent.clone());
                            }
                        }
                        DependencyKind::ViewDependency {
                            referenced_column, ..
                        } if referenced == &resolved_table => match referenced_column {
                            Some(column) if cascade_generated_columns.contains(column) => {
                                cascade_view_roots.insert(dependent.clone());
                            }
                            Some(_) => {}
                            None => unknown_dependency = true,
                        },
                        DependencyKind::ForeignKey {
                            constraint_name,
                            from_columns,
                            to_columns,
                            ..
                        } if (dependent == &resolved_table
                            && from_columns
                                .iter()
                                .any(|column| cascade_generated_columns.contains(column)))
                            || (referenced == &resolved_table
                                && to_columns
                                    .iter()
                                    .any(|column| cascade_generated_columns.contains(column))) =>
                        {
                            if let Some(constraint_name) = constraint_name {
                                known_dependency = true;
                                drop_column_constraints
                                    .insert((dependent.clone(), constraint_name.clone()));
                            } else {
                                unknown_dependency = true;
                            }
                        }
                        DependencyKind::ConstraintOnRelation {
                            constraint_name,
                            columns,
                            ..
                        }
                        | DependencyKind::ConstraintDependency {
                            constraint_name,
                            columns,
                        } if dependent == &resolved_table
                            && columns
                                .iter()
                                .any(|column| cascade_generated_columns.contains(column)) =>
                        {
                            known_dependency = true;
                            drop_column_constraints
                                .insert((dependent.clone(), constraint_name.clone()));
                        }
                        DependencyKind::ColumnGeneratedFrom {
                            column,
                            depends_on_column,
                        } if referenced == &resolved_table
                            && cascade_generated_columns.contains(depends_on_column)
                            && !cascade_generated_columns.contains(column) => {}
                        _ => {}
                    }
                }
            }

            // Every CHECK/EXCLUDE constraint must have a typed dependency edge.
            // An empty edge is authoritative for a constant expression; a
            // missing edge means the cache is incomplete.
            for (table_id, constraint_name) in self.local.constraints.keys() {
                if self.local.graph.resolve_rename(table_id) != &resolved_table {
                    continue;
                }
                let represented = self.local.graph.edges().iter().any(|edge| {
                    (edge.dependent == resolved_table
                        && matches!(
                            &edge.kind,
                            DependencyKind::ConstraintOnRelation {
                                constraint_name: name,
                                ..
                            } if name == constraint_name
                        ))
                        || matches!(
                            &edge.kind,
                            DependencyKind::ConstraintDependency {
                                constraint_name: name,
                                ..
                            } if edge.dependent == resolved_table && name == constraint_name
                        )
                        || matches!(
                            &edge.kind,
                            DependencyKind::ForeignKey {
                                constraint_name: Some(name),
                                ..
                            } if (edge.dependent == resolved_table
                                || edge.referenced == resolved_table)
                                && name == constraint_name
                        )
                });
                if !represented {
                    unknown_dependency = true;
                }
            }

            if unknown_dependency {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
                return MutationResult::Skipped;
            }
            if known_dependency && !cascade {
                return MutationResult::Conflict {
                    reason: format!(
                        "column '{}.{}' has dependent objects; use CASCADE",
                        alter.id, name
                    ),
                };
            }
        }

        self.snapshot_relation(&alter.id);
        let action_type_id = match &alter.action {
            AlterTableActionMutation::AddColumn { ty, .. } => ty
                .as_deref()
                .and_then(|raw| self.resolve_type_reference(raw)),
            AlterTableActionMutation::SetType { ty, .. } => self.resolve_type_reference(ty),
            _ => None,
        };
        // Not-null constraint state lives in `self.local.constraints` and the
        // graph, not the relation overlay. Collect the transitions applied to
        // `rel` here and replay them once the `rel` borrow (below) is released
        // so the `&mut self` calls do not contend with the overlay borrow.
        let mut deferred_not_null: Vec<(String, bool)> = Vec::new();
        let rel_overlay = self.local.relations.get_mut(&alter.id);
        #[allow(clippy::collapsible_if)]
        if let Some(RelationOverlay::Present(rel)) = rel_overlay {
            let generation = rel.generation;
            match &alter.action {
                AlterTableActionMutation::AddColumn {
                    name,
                    ty,
                    if_not_exists,
                    not_null,
                    default,
                    depends_on,
                    generation,
                    identity_sequence: _,
                    generated_expr,
                    generated_expr_sql,
                } => {
                    if let Some(existing_col) = rel.columns.iter().find(|c| c.name == *name) {
                        if *if_not_exists {
                            return MutationResult::Skipped;
                        }
                        return MutationResult::Conflict {
                            reason: format!(
                                "column '{}' already exists with type {}; this statement adds it again with type {}",
                                name,
                                existing_col.data_type.as_deref().unwrap_or("unknown"),
                                ty.as_deref().unwrap_or("unknown")
                            ),
                        };
                    }
                    rel.apply_column_action(&ColumnAction::Add {
                        name: name.clone(),
                        data_type: ty.clone(),
                        not_null: *not_null,
                        default: default.clone(),
                    });
                    if *not_null {
                        deferred_not_null.push((name.clone(), true));
                    }
                    if let Some(column) = rel.columns.iter_mut().find(|column| column.name == *name)
                    {
                        column.type_id = action_type_id.clone();
                        if matches!(
                            generation,
                            crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored
                                | crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual
                        ) {
                            column.generated = Some(true);
                        }
                    }
                    match generation {
                        crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored
                        | crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual => {
                            rel.generated_columns.insert(
                                name.clone(),
                                crate::_internal::model::relation::GeneratedColumnState {
                                    kind: match generation {
                                        crate::_internal::analysis::facts::ColumnGeneration::GeneratedStored => crate::_internal::model::relation::GeneratedColumnKind::Stored,
                                        crate::_internal::analysis::facts::ColumnGeneration::GeneratedVirtual => crate::_internal::model::relation::GeneratedColumnKind::Virtual,
                                        _ => unreachable!("generated kind checked above"),
                                    },
                                    expression: generated_expr_sql.clone(),
                                },
                            );
                        }
                        crate::_internal::analysis::facts::ColumnGeneration::IdentityAlways => {
                            rel.identity_columns.insert(
                                name.clone(),
                                crate::_internal::model::relation::IdentityGeneration::Always,
                            );
                        }
                        crate::_internal::analysis::facts::ColumnGeneration::IdentityByDefault => {
                            rel.identity_columns.insert(
                                name.clone(),
                                crate::_internal::model::relation::IdentityGeneration::ByDefault,
                            );
                        }
                        _ => {}
                    }

                    if let Some((sequence_id, column_name, _, _)) = &implicit_add
                        && column_name == name
                        && let Some(column) =
                            rel.columns.iter_mut().find(|column| column.name == *name)
                    {
                        column.default = Some(Self::sequence_nextval_default(sequence_id));
                        column.default_expr_text = Some(format!(
                            "nextval('{}.{}'::regclass)",
                            sequence_id.schema, sequence_id.name
                        ));
                        column.is_nullable = false;
                    }

                    if let Some((source_table, source_col)) = depends_on {
                        self.snapshot_graph();
                        self.local.graph.add_edge(DependencyEdge::new(
                            alter.id.clone(),
                            source_table.clone(),
                            DependencyKind::ColumnGeneratedFrom {
                                column: name.clone(),
                                depends_on_column: source_col.clone(),
                            },
                        ));
                    }
                    if let Some(expr) = generated_expr
                        && let Some(references) = expr.referenced_columns()
                    {
                        self.snapshot_graph();
                        for depends_on_column in references {
                            self.local.graph.add_edge(DependencyEdge::new(
                                alter.id.clone(),
                                alter.id.clone(),
                                DependencyKind::ColumnGeneratedFrom {
                                    column: name.clone(),
                                    depends_on_column,
                                },
                            ));
                        }
                    }
                }
                AlterTableActionMutation::DropColumn {
                    name, if_exists, ..
                } => {
                    if !rel.has_column(name) {
                        if *if_exists {
                            // Column doesn't exist and IF EXISTS was specified: no-op
                            return MutationResult::Skipped;
                        }
                        return MutationResult::Conflict {
                            reason: format!(
                                "column '{}' does not exist on relation '{}'",
                                name, alter.id
                            ),
                        };
                    }
                    rel.apply_column_action(&ColumnAction::Drop { name: name.clone() });
                    if !drop_column_statistics.is_empty() {
                        rel.extended_statistics
                            .retain(|id, _| !drop_column_statistics.contains(id));
                    }
                    for generated_column in &cascade_generated_columns {
                        if rel.has_column(generated_column) {
                            rel.apply_column_action(&ColumnAction::Drop {
                                name: generated_column.clone(),
                            });
                        }
                    }
                }
                AlterTableActionMutation::RenameColumn { from, to } => {
                    rel.apply_column_action(&ColumnAction::Rename {
                        from: from.clone(),
                        to: to.clone(),
                    });
                }
                AlterTableActionMutation::SetNotNull { column } => {
                    rel.apply_column_action(&ColumnAction::SetNotNull {
                        name: column.clone(),
                    });
                    deferred_not_null.push((column.clone(), true));
                }
                AlterTableActionMutation::DropNotNull { column } => {
                    rel.apply_column_action(&ColumnAction::DropNotNull {
                        name: column.clone(),
                    });
                    deferred_not_null.push((column.clone(), false));
                }
                AlterTableActionMutation::SetType { column, ty, .. } => {
                    rel.apply_column_action(&ColumnAction::SetType {
                        name: column.clone(),
                        data_type: ty.clone(),
                    });
                    if let Some(column) = rel.columns.iter_mut().find(|entry| entry.name == *column)
                    {
                        column.type_id = action_type_id.clone();
                    }
                }
                AlterTableActionMutation::SetDefault { column, default } => {
                    rel.apply_column_action(&ColumnAction::SetDefault {
                        name: column.clone(),
                        default: default.clone(),
                    });
                }
                AlterTableActionMutation::SetStorage { column, mode } => {
                    rel.apply_column_action(&ColumnAction::SetStorage {
                        name: column.clone(),
                        mode: mode.clone(),
                    });
                }
                AlterTableActionMutation::SetCompression { column, method } => {
                    rel.apply_column_action(&ColumnAction::SetCompression {
                        name: column.clone(),
                        method: method.clone(),
                    });
                }
                AlterTableActionMutation::SetStatistics { column, target } => {
                    rel.apply_column_action(&ColumnAction::SetStatistics {
                        name: column.clone(),
                        target: *target,
                    });
                }
                AlterTableActionMutation::SetColumnOptions { column, attributes } => {
                    rel.apply_column_action(&ColumnAction::SetOptions {
                        name: column.clone(),
                        options: attributes
                            .iter()
                            .map(|attribute| (attribute.name.clone(), attribute.value.clone()))
                            .collect(),
                    });
                }
                AlterTableActionMutation::ResetColumnOptions { column, names } => {
                    rel.apply_column_action(&ColumnAction::ResetOptions {
                        name: column.clone(),
                        names: names.clone(),
                    });
                }
                AlterTableActionMutation::DropGeneratedExpression { column, .. } => {
                    if let Some(entry) = rel.columns.iter_mut().find(|entry| entry.name == *column)
                    {
                        entry.generated = Some(false);
                    }
                    rel.generated_columns.remove(column);
                }
                AlterTableActionMutation::AddForeignKey {
                    constraint_name,
                    to_table,
                    from_columns,
                    to_columns,
                    not_valid,
                } => {
                    let constraint_name = constraint_name.clone().unwrap_or_else(|| {
                        self.next_generated_constraint_name_avoiding(
                            &alter.id,
                            &alter.id.name,
                            Some(&from_columns.join("_")),
                            "fkey",
                            &HashSet::new(),
                        )
                    });
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name.clone(),
                            kind: ConstraintKind::ForeignKey,
                            validated: !not_valid,
                            definition: None,
                            backing_index: None,
                        },
                    );
                    if *not_valid {
                        self.snapshot_pending_validation();
                        self.local
                            .pending_validation
                            .insert((alter.id.clone(), constraint_name.clone()));
                    }
                    self.snapshot_graph();
                    self.local.graph.add_edge(DependencyEdge::new(
                        alter.id.clone(),
                        to_table.clone(),
                        DependencyKind::ForeignKey {
                            constraint_name: Some(constraint_name),
                            from_columns: from_columns.clone(),
                            to_columns: effective_fk_target_columns
                                .clone()
                                .unwrap_or_else(|| to_columns.clone()),
                            operator_evidence: None,
                            from_generation: generation,
                        },
                    ));
                }
                AlterTableActionMutation::DropConstraint { name, .. } => {
                    self.snapshot_constraint(&alter.id, name);
                    let removed_constraint = self
                        .local
                        .constraints
                        .remove(&(alter.id.clone(), name.clone()));
                    if let Some(index) = removed_constraint
                        .as_ref()
                        .filter(|constraint| {
                            matches!(
                                constraint.kind,
                                ConstraintKind::PrimaryKey
                                    | ConstraintKind::Unique
                                    | ConstraintKind::Exclusion
                            )
                        })
                        .and_then(|constraint| constraint.backing_index.as_ref())
                    {
                        self.snapshot_relation(&alter.id);
                        if let Some(RelationOverlay::Present(relation)) =
                            self.local.relations.get_mut(&alter.id)
                        {
                            relation.clear_index_settings(&index.name);
                        }
                        self.snapshot_graph_full();
                        self.local.graph.retain_edges(|edge| {
                            !(edge.dependent == *index
                                && matches!(edge.kind, DependencyKind::IndexOnRelation { .. }))
                        });
                    }
                    if let Some(ref c) = removed_constraint
                        && c.kind == crate::_internal::model::constraint::ConstraintKind::NotNull
                    {
                        // A not-null constraint guards exactly one column; PG18
                        // allows it to be dropped by name like any other
                        // constraint, which releases the column's nullability.
                        let resolution_graph = self.local.graph.clone();
                        let guarded_column: Option<String> =
                            self.local.graph.edges().iter().find_map(|edge| {
                                if resolution_graph.resolve_rename(&edge.dependent) != &alter.id {
                                    return None;
                                }
                                if let DependencyKind::ConstraintOnRelation {
                                    constraint_name,
                                    columns,
                                    is_primary: false,
                                    ..
                                } = &edge.kind
                                    && constraint_name == name
                                    && columns.len() == 1
                                {
                                    Some(columns[0].clone())
                                } else {
                                    None
                                }
                            });
                        if let Some(column) = guarded_column {
                            self.snapshot_relation(&alter.id);
                            if let Some(RelationOverlay::Present(rel)) =
                                self.local.relations.get_mut(&alter.id)
                            {
                                if let Some(col) = rel.columns.iter_mut().find(|c| c.name == column)
                                {
                                    col.is_nullable = true;
                                }
                            }
                        }
                    }
                    if self
                        .local
                        .pending_validation
                        .contains(&(alter.id.clone(), name.clone()))
                    {
                        self.snapshot_pending_validation();
                        self.local
                            .pending_validation
                            .remove(&(alter.id.clone(), name.clone()));
                    }
                    if self
                        .baseline_foreign_keys
                        .contains(&(alter.id.clone(), name.clone()))
                    {
                        self.snapshot_baseline_foreign_keys();
                        self.baseline_foreign_keys
                            .remove(&(alter.id.clone(), name.clone()));
                    }
                    self.snapshot_graph_full();
                    let resolution_graph = self.local.graph.clone();
                    self.local.graph.retain_edges(|e| {
                        let dependent = resolution_graph.resolve_rename(&e.dependent);
                        match &e.kind {
                            DependencyKind::ForeignKey {
                                constraint_name, ..
                            } => {
                                !(dependent == &alter.id && constraint_name.as_ref() == Some(name))
                            }
                            DependencyKind::ConstraintOnRelation {
                                constraint_name, ..
                            } => !(dependent == &alter.id && constraint_name == name),
                            DependencyKind::ConstraintDependency {
                                constraint_name, ..
                            } => !(dependent == &alter.id && constraint_name == name),
                            _ => true,
                        }
                    });
                }
                AlterTableActionMutation::RenameConstraint { old_name, new_name } => {
                    self.snapshot_constraint(&alter.id, old_name);
                    self.snapshot_constraint(&alter.id, new_name);
                    if let Some(mut constraint) = self
                        .local
                        .constraints
                        .remove(&(alter.id.clone(), old_name.clone()))
                    {
                        constraint.name = new_name.clone();
                        self.local
                            .constraints
                            .insert((alter.id.clone(), new_name.clone()), constraint);
                    }
                    if self
                        .local
                        .pending_validation
                        .contains(&(alter.id.clone(), old_name.clone()))
                    {
                        self.snapshot_pending_validation();
                        self.local
                            .pending_validation
                            .remove(&(alter.id.clone(), old_name.clone()));
                        self.local
                            .pending_validation
                            .insert((alter.id.clone(), new_name.clone()));
                    }
                    if self
                        .baseline_foreign_keys
                        .contains(&(alter.id.clone(), old_name.clone()))
                    {
                        self.snapshot_baseline_foreign_keys();
                        self.baseline_foreign_keys
                            .remove(&(alter.id.clone(), old_name.clone()));
                        self.baseline_foreign_keys
                            .insert((alter.id.clone(), new_name.clone()));
                    }
                    self.snapshot_graph_full();
                    self.local
                        .graph
                        .rename_constraint(&alter.id, old_name, new_name);
                }
                AlterTableActionMutation::AddCheckConstraint {
                    constraint_name,
                    definition,
                    columns,
                    columns_complete,
                    not_valid,
                } => {
                    let constraint_name = constraint_name.clone().unwrap_or_else(|| {
                        self.next_generated_constraint_name_avoiding(
                            &alter.id,
                            &alter.id.name,
                            (*columns_complete && columns.len() == 1).then(|| columns[0].as_str()),
                            "check",
                            &HashSet::new(),
                        )
                    });
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name.clone(),
                            kind: ConstraintKind::Check,
                            validated: !not_valid,
                            definition: Some(definition.clone()),
                            backing_index: None,
                        },
                    );
                    if *not_valid {
                        self.snapshot_pending_validation();
                        self.local
                            .pending_validation
                            .insert((alter.id.clone(), constraint_name.clone()));
                    }
                    if !relation_columns_known || !columns_complete {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    } else {
                        self.snapshot_graph();
                        self.local.graph.add_edge(DependencyEdge::new(
                            alter.id.clone(),
                            alter.id.clone(),
                            DependencyKind::ConstraintDependency {
                                constraint_name,
                                columns: columns.clone(),
                            },
                        ));
                    }
                }
                AlterTableActionMutation::AddUniqueConstraint {
                    constraint_name,
                    columns,
                    using_index,
                } => {
                    let constraint_name = constraint_name
                        .clone()
                        .or_else(|| using_index.as_ref().map(|index| index.name.clone()))
                        .unwrap_or_else(|| {
                            self.next_generated_constraint_name_avoiding(
                                &alter.id,
                                &alter.id.name,
                                None,
                                "key",
                                &HashSet::new(),
                            )
                        });
                    let backing_index = Some(ObjectId::new(&alter.id.schema, &constraint_name));
                    if let Some(index) = using_index {
                        self.adopt_index_for_constraint(index, &alter.id, &constraint_name);
                    } else {
                        self.snapshot_graph();
                        self.local.graph.add_edge(DependencyEdge::new(
                            ObjectId::new(&alter.id.schema, &constraint_name),
                            alter.id.clone(),
                            Self::constraint_index_dependency(columns.clone(), true),
                        ));
                    }
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name.clone(),
                            kind: ConstraintKind::Unique,
                            validated: true,
                            definition: None,
                            backing_index,
                        },
                    );
                    if columns.is_empty() || !relation_columns_known {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    } else {
                        self.snapshot_graph();
                        self.local.graph.add_edge(DependencyEdge::new(
                            alter.id.clone(),
                            alter.id.clone(),
                            DependencyKind::ConstraintOnRelation {
                                constraint_name,
                                columns: columns.clone(),
                                is_primary: false,
                            },
                        ));
                    }
                }
                AlterTableActionMutation::AddPrimaryKeyConstraint {
                    constraint_name,
                    columns,
                    using_index,
                } => {
                    let constraint_name = constraint_name
                        .clone()
                        .or_else(|| using_index.as_ref().map(|index| index.name.clone()))
                        .unwrap_or_else(|| {
                            self.next_generated_constraint_name_avoiding(
                                &alter.id,
                                &alter.id.name,
                                None,
                                "pkey",
                                &HashSet::new(),
                            )
                        });
                    let backing_index = Some(ObjectId::new(&alter.id.schema, &constraint_name));
                    if let Some(index) = using_index {
                        self.adopt_index_for_constraint(index, &alter.id, &constraint_name);
                    } else {
                        self.snapshot_graph();
                        self.local.graph.add_edge(DependencyEdge::new(
                            ObjectId::new(&alter.id.schema, &constraint_name),
                            alter.id.clone(),
                            Self::constraint_index_dependency(columns.clone(), true),
                        ));
                    }
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name.clone(),
                            kind: ConstraintKind::PrimaryKey,
                            validated: true,
                            definition: None,
                            backing_index,
                        },
                    );
                    if columns.is_empty() || !relation_columns_known {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    } else {
                        self.snapshot_graph();
                        self.local.graph.add_edge(DependencyEdge::new(
                            alter.id.clone(),
                            alter.id.clone(),
                            DependencyKind::ConstraintOnRelation {
                                constraint_name,
                                columns: columns.clone(),
                                is_primary: true,
                            },
                        ));
                        for column in columns.iter() {
                            if let Some(RelationOverlay::Present(relation)) =
                                self.local.relations.get_mut(&alter.id)
                            {
                                relation.apply_column_action(&ColumnAction::SetNotNull {
                                    name: column.clone(),
                                });
                            }
                            self.register_not_null_constraint(&alter.id, column);
                        }
                    }
                }
                AlterTableActionMutation::AddExcludeConstraint {
                    constraint_name,
                    columns,
                    columns_complete,
                } => {
                    let constraint_name = constraint_name.clone().unwrap_or_else(|| {
                        self.next_generated_constraint_name_avoiding(
                            &alter.id,
                            &alter.id.name,
                            None,
                            "excl",
                            &HashSet::new(),
                        )
                    });
                    let backing_index = ObjectId::new(&alter.id.schema, &constraint_name);
                    if self.relation_namespace_is_taken(&backing_index) {
                        return MutationResult::Conflict {
                            reason: format!("relation '{}' already exists", backing_index),
                        };
                    }
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name.clone(),
                            kind: ConstraintKind::Exclusion,
                            validated: true,
                            definition: None,
                            backing_index: Some(backing_index.clone()),
                        },
                    );
                    if !relation_columns_known || !columns_complete {
                        self.taint(
                            EvidenceCode::CatalogCoverageIncomplete,
                            EvidenceScope::Chain,
                        );
                    } else {
                        self.snapshot_graph_full();
                        self.local.graph.add_edge(DependencyEdge::new(
                            backing_index,
                            alter.id.clone(),
                            DependencyKind::IndexOnRelation {
                                using_method: None,
                                key_columns: columns.clone(),
                                included_columns: Vec::new(),
                                dependency_columns: columns.clone(),
                                dependency_columns_known: true,
                                has_expression_keys: true,
                                has_predicate: false,
                                is_concurrent: false,
                                is_unique: false,
                                is_immediate: true,
                                is_valid: true,
                                is_ready: true,
                                is_live: true,
                                has_default_sort_order: false,
                                has_default_opclasses: false,
                                has_default_collations: false,
                                eligibility_known: false,
                            },
                        ));
                        self.local.graph.add_edge(DependencyEdge::new(
                            alter.id.clone(),
                            alter.id.clone(),
                            DependencyKind::ConstraintDependency {
                                constraint_name,
                                columns: columns.clone(),
                            },
                        ));
                    }
                }
                AlterTableActionMutation::ValidateConstraint { constraint_name } => {
                    self.snapshot_constraint(&alter.id, constraint_name);
                    if let Some(constraint) = self
                        .local
                        .constraints
                        .get_mut(&(alter.id.clone(), constraint_name.clone()))
                    {
                        constraint.validated = true;
                    }
                    if self
                        .local
                        .pending_validation
                        .contains(&(alter.id.clone(), constraint_name.clone()))
                    {
                        self.snapshot_pending_validation();
                        self.local
                            .pending_validation
                            .remove(&(alter.id.clone(), constraint_name.clone()));
                    }
                }
                AlterTableActionMutation::AttachPartition { child, .. } => {
                    // Validation above rejects cyclic attachments before state mutation.
                    if self.local.graph.check_partition_cycle(&alter.id, child) {
                        return MutationResult::Conflict {
                            reason: format!(
                                "attaching partition '{}' to '{}' would create a partition cycle",
                                child, alter.id
                            ),
                        };
                    } else {
                        self.snapshot_graph();
                        self.local.graph.add_edge(DependencyEdge::new(
                            child.clone(),
                            alter.id.clone(),
                            DependencyKind::PartitionOf,
                        ));
                    }
                }
                AlterTableActionMutation::DetachPartition { child, mode } => {
                    self.snapshot_graph_full();
                    match mode {
                        crate::_internal::analysis::facts::DetachPartitionMode::Immediate
                        | crate::_internal::analysis::facts::DetachPartitionMode::Finalize => {
                            let kind = match mode {
                                crate::_internal::analysis::facts::DetachPartitionMode::Immediate => {
                                    DependencyKind::PartitionOf
                                }
                                crate::_internal::analysis::facts::DetachPartitionMode::Finalize => {
                                    DependencyKind::PartitionDetachPending
                                }
                                crate::_internal::analysis::facts::DetachPartitionMode::Concurrently => {
                                    unreachable!("concurrent detach is handled separately")
                                }
                            };
                            self.local.graph.retain_edges(|edge| {
                                !(edge.kind == kind
                                    && edge.dependent == *child
                                    && edge.referenced == alter.id)
                            });
                        }
                        crate::_internal::analysis::facts::DetachPartitionMode::Concurrently => {
                            self.local.graph.retain_edges(|edge| {
                                !(matches!(edge.kind, DependencyKind::PartitionOf)
                                    && edge.dependent == *child
                                    && edge.referenced == alter.id)
                            });
                            // PostgreSQL retains a CHECK duplicating the
                            // partition predicate on concurrent detach
                            // (DetachAddConstraintIfNeeded). Reproduce its
                            // exact deparse; otherwise stay conservative.
                            match self.retained_check_for_detached_partition(&alter.id, child) {
                                RetainedCheckSynthesis::NoCheck => {}
                                RetainedCheckSynthesis::CantResolve => {
                                    self.taint(
                                        EvidenceCode::UnsupportedSemantics,
                                        EvidenceScope::Chain,
                                    );
                                }
                                RetainedCheckSynthesis::Definition(definition) => {
                                    self.register_retained_partition_check(child, definition);
                                }
                            }
                        }
                    }
                }
                AlterTableActionMutation::InheritTable { parent } => {
                    self.snapshot_graph();
                    self.local.graph.add_edge(DependencyEdge::new(
                        alter.id.clone(),
                        parent.clone(),
                        DependencyKind::InheritanceOf,
                    ));
                }
                AlterTableActionMutation::NoInheritTable { parent } => {
                    self.snapshot_graph_full();
                    self.local.graph.retain_edges(|edge| {
                        !(edge.dependent == alter.id
                            && edge.referenced == *parent
                            && matches!(edge.kind, DependencyKind::InheritanceOf))
                    });
                }
                AlterTableActionMutation::SetTablespace { tablespace } => {
                    rel.tablespace = Some(tablespace.clone());
                }
                AlterTableActionMutation::SetAccessMethod { access_method } => {
                    rel.access_method = access_method.clone();
                }
                AlterTableActionMutation::SetPersistence { persistence } => {
                    rel.persistence = persistence.clone();
                }
                AlterTableActionMutation::SetCluster { index } => {
                    rel.cluster_index = index.as_ref().map(|index| index.name.clone());
                }
                AlterTableActionMutation::SetRowSecurity { enabled } => {
                    rel.row_security = Some(*enabled);
                }
                AlterTableActionMutation::SetForceRowSecurity { enabled } => {
                    rel.force_row_security = Some(*enabled);
                }
                AlterTableActionMutation::SetReplicaIdentity { option } => {
                    rel.replica_identity = Some(match option {
                        crate::_internal::analysis::mutations::ReplicaIdentityMutation::Default =>
                            "DEFAULT".to_string(),
                        crate::_internal::analysis::mutations::ReplicaIdentityMutation::Full =>
                            "FULL".to_string(),
                        crate::_internal::analysis::mutations::ReplicaIdentityMutation::Nothing =>
                            "NOTHING".to_string(),
                        crate::_internal::analysis::mutations::ReplicaIdentityMutation::UsingIndex(index) =>
                            format!("USING INDEX {}", index.name),
                    });
                }
                AlterTableActionMutation::SetOfType { type_id } => {
                    rel.of_type = type_id.clone();
                }
                AlterTableActionMutation::SetTableOptions { attributes } => {
                    for attribute in attributes {
                        rel.table_options
                            .insert(attribute.name.clone(), attribute.value.clone());
                    }
                }
                AlterTableActionMutation::ResetTableOptions { names } => {
                    for name in names {
                        rel.table_options.remove(name);
                    }
                }
                AlterTableActionMutation::SetGeneratedExpression {
                    column,
                    expression_sql,
                    ..
                } => {
                    if let Some(generated) = rel.generated_columns.get_mut(column) {
                        generated.expression = Some(expression_sql.clone());
                    }
                }
                AlterTableActionMutation::AlterColumnInheritance
                | AlterTableActionMutation::PartitionReshape => {
                    // These forms have a typed parse but change physical or
                    // inheritance metadata that RelationState cannot yet
                    // represent. Never leave subsequent statements exact.
                    self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
                }
                _ => {}
            }
        }
        for (column, register) in deferred_not_null {
            if register {
                self.register_not_null_constraint(&alter.id, &column);
            } else {
                self.drop_not_null_constraint(&alter.id, &column);
            }
        }
        match &alter.action {
            AlterTableActionMutation::InheritTable { parent }
            | AlterTableActionMutation::NoInheritTable { parent } => {
                let columns = match self.local.relations.get(parent) {
                    Some(RelationOverlay::Present(parent)) => parent
                        .columns
                        .iter()
                        .map(|column| column.name.clone())
                        .collect::<Vec<_>>(),
                    _ => Vec::new(),
                };
                let adding = matches!(alter.action, AlterTableActionMutation::InheritTable { .. });
                let mut incomplete = false;
                self.snapshot_relation(&alter.id);
                if let Some(RelationOverlay::Present(relation)) =
                    self.local.relations.get_mut(&alter.id)
                {
                    for column in columns {
                        let Some(provenance) = relation.column_inheritance.get_mut(&column) else {
                            incomplete = true;
                            continue;
                        };
                        let count = if adding {
                            provenance.parent_count.checked_add(1)
                        } else {
                            provenance.parent_count.checked_sub(1)
                        };
                        if let Some(count) = count {
                            provenance.parent_count = count;
                            if count == 0 {
                                provenance.is_local = true;
                            }
                        } else {
                            relation.column_inheritance.remove(&column);
                            incomplete = true;
                        }
                    }
                }
                if incomplete {
                    self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    );
                }
            }
            AlterTableActionMutation::AttachPartition { child, bound, .. } => {
                self.invalidate_descendant_partition_predicates(child);
                let canonical_bound = bound.as_deref().map(canonical_partition_bound);
                let generated_partition_constraint = self
                    .local
                    .relations
                    .get(child)
                    .and_then(|overlay| match overlay {
                        RelationOverlay::Present(relation) => Some(relation),
                        RelationOverlay::Dropped => None,
                    })
                    .and_then(|relation| {
                        let parent_strategy = self.local.relations.get(&alter.id).and_then(
                            |overlay| match overlay {
                                RelationOverlay::Present(parent) => {
                                    parent.partition_type.as_deref()
                                }
                                RelationOverlay::Dropped => None,
                            },
                        )?;
                        let keys = self.partition_key_columns(&alter.id)?;
                        if canonical_bound
                            .as_deref()
                            .is_some_and(|value| value.eq_ignore_ascii_case("DEFAULT"))
                        {
                            return self.synthesize_default_partition_constraint(&alter.id);
                        }
                        self.synthesize_partition_check(
                            parent_strategy,
                            canonical_bound.as_deref()?,
                            &keys,
                            relation,
                        )
                    });
                self.snapshot_relation(child);
                if let Some(RelationOverlay::Present(relation)) =
                    self.local.relations.get_mut(child)
                {
                    relation.partition_bound = canonical_bound;
                    relation.partition_constraint = generated_partition_constraint;
                    for column in &relation.columns {
                        relation.column_inheritance.insert(
                            column.name.clone(),
                            crate::_internal::model::relation::ColumnInheritance {
                                parent_count: 1,
                                is_local: false,
                            },
                        );
                    }
                }
                self.refresh_default_partition_constraints(&alter.id);
                self.ensure_partition_indexes_and_constraints(&alter.id, child);
                let result = self.clone_row_triggers_to_partition(&alter.id, child);
                debug_assert!(matches!(result, MutationResult::Applied));
                if !matches!(result, MutationResult::Applied) {
                    return result;
                }
            }
            AlterTableActionMutation::DetachPartition { child, .. } => {
                // The retained CHECK for a concurrent detach is synthesized in
                // the apply arm; this block only resets partition metadata.
                self.invalidate_descendant_partition_predicates(child);
                self.snapshot_relation(child);
                if let Some(RelationOverlay::Present(relation)) =
                    self.local.relations.get_mut(child)
                {
                    relation.partition_bound = None;
                    relation.partition_constraint = None;
                    for column in &relation.columns {
                        relation.column_inheritance.insert(
                            column.name.clone(),
                            crate::_internal::model::relation::ColumnInheritance {
                                parent_count: 0,
                                is_local: true,
                            },
                        );
                    }
                }
                self.remove_partition_trigger_clones(&alter.id, child);
            }
            _ => {}
        }
        if let AlterTableActionMutation::SetDefault { column, default } = &alter.action {
            self.snapshot_graph_full();
            self.local.graph.retain_edges(|edge| {
                !matches!(
                    &edge.kind,
                    DependencyKind::ColumnDefaultOnSequence { column: edge_column }
                        if edge.dependent == alter.id && edge_column == column
                )
            });
            if let Some(default) = default {
                let matching_sequences = self
                    .local
                    .sequences
                    .iter()
                    .filter_map(|(id, overlay)| {
                        matches!(overlay, SequenceOverlay::Present(_)).then_some(id.clone())
                    })
                    .filter(|id| Self::expression_references_sequence(default, id))
                    .collect::<Vec<_>>();
                match matching_sequences.as_slice() {
                    [sequence] => self.local.graph.add_edge(DependencyEdge::new(
                        alter.id.clone(),
                        sequence.clone(),
                        DependencyKind::ColumnDefaultOnSequence {
                            column: column.clone(),
                        },
                    )),
                    [] if Self::expression_contains_nextval(default) => self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    ),
                    _ => self.taint(
                        EvidenceCode::CatalogCoverageIncomplete,
                        EvidenceScope::Chain,
                    ),
                }
            }
        }
        match &alter.action {
            AlterTableActionMutation::SetGeneratedExpression { column, expr, .. } => {
                let references = expr
                    .referenced_columns()
                    .expect("generated expression was validated before state mutation");
                self.snapshot_graph_full();
                self.local.graph.retain_edges(|edge| {
                    !matches!(
                        &edge.kind,
                        DependencyKind::ColumnGeneratedFrom { column: generated_column, .. }
                            if edge.dependent == alter.id
                                && edge.referenced == alter.id
                                && generated_column == column
                    )
                });
                for source_column in references {
                    self.local.graph.add_edge(DependencyEdge::new(
                        alter.id.clone(),
                        alter.id.clone(),
                        DependencyKind::ColumnGeneratedFrom {
                            column: column.clone(),
                            depends_on_column: source_column,
                        },
                    ));
                }
            }
            AlterTableActionMutation::DropGeneratedExpression { column, .. } => {
                self.snapshot_graph_full();
                self.local.graph.retain_edges(|edge| {
                    !matches!(
                        &edge.kind,
                        DependencyKind::ColumnGeneratedFrom { column: generated_column, .. }
                            if edge.dependent == alter.id
                                && edge.referenced == alter.id
                                && generated_column == column
                    )
                });
            }
            _ => {}
        }
        if let AlterTableActionMutation::RenameColumn { from, to } = &alter.action {
            self.rename_relation_column_metadata(&alter.id, from, to);
            for descendant in recursive_rename_descendants {
                self.rename_relation_column_metadata(&descendant, from, to);
            }

            // Publication column lists are catalog identities, not merely
            // display text. PostgreSQL follows a renamed column in an
            // explicit publication list, so keep the modeled scope aligned.
            let publication_updates: Vec<(String, Vec<usize>)> = self
                .local
                .publications
                .iter()
                .filter_map(|(name, overlay)| {
                    let crate::_internal::model::replication::PublicationOverlay::Present(publication) =
                        overlay
                    else {
                        return None;
                    };
                    let indexes = match &publication.scope {
                        crate::_internal::analysis::facts::PublicationScope::Explicit(objects) => objects
                            .iter()
                            .enumerate()
                            .filter_map(|(index, object)| {
                                let crate::_internal::analysis::facts::PublicationObjectFact::Table {
                                    name: table_name,
                                    columns: Some(columns),
                                    ..
                                } = object
                                else {
                                    return None;
                                };
                                (self.resolve_relation_id(table_name) == alter.id
                                    && columns.iter().any(|column| column == from))
                                .then_some(index)
                            })
                            .collect::<Vec<_>>(),
                        _ => Vec::new(),
                    };
                    (!indexes.is_empty()).then(|| (name.clone(), indexes))
                })
                .collect();
            for (publication_name, object_indexes) in publication_updates {
                self.snapshot_publication(&publication_name);
                if let Some(crate::_internal::model::replication::PublicationOverlay::Present(
                    publication,
                )) = self.local.publications.get_mut(&publication_name)
                    && let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
                        &mut publication.scope
                {
                    for index in object_indexes {
                        if let Some(
                            crate::_internal::analysis::facts::PublicationObjectFact::Table {
                                columns: Some(columns),
                                ..
                            },
                        ) = objects.get_mut(index)
                        {
                            for column in columns {
                                if column == from {
                                    *column = to.clone();
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Some((sequence_id, column_name, kind, identity_options)) = implicit_add {
            let default_parameters = self
                .local
                .relations
                .get(&alter.id)
                .and_then(|overlay| match overlay {
                    RelationOverlay::Present(table) => {
                        Some(Self::default_column_sequence_parameters(
                            table
                                .get_column(&column_name)
                                .and_then(|column| column.data_type.as_deref()),
                            &table.persistence,
                        ))
                    }
                    RelationOverlay::Dropped => None,
                })
                .unwrap_or_default();
            let parameters = match identity_options.as_ref() {
                Some(options) => {
                    let Some(parameters) =
                        Self::apply_identity_sequence_options(default_parameters, options)
                    else {
                        return MutationResult::Conflict {
                            reason: format!(
                                "identity sequence options for '{}.{}' are invalid",
                                alter.id, column_name
                            ),
                        };
                    };
                    parameters
                }
                None => default_parameters,
            };
            self.snapshot_sequence(&sequence_id);
            self.snapshot_generation_counter();
            self.local.generation_counter += 1;
            self.local.sequences.insert(
                sequence_id.clone(),
                SequenceOverlay::Present(SequenceState {
                    id: sequence_id.clone(),
                    owner: self
                        .local
                        .relations
                        .get(&alter.id)
                        .and_then(|overlay| match overlay {
                            RelationOverlay::Present(table) => Some(table.owner.clone()),
                            RelationOverlay::Dropped => None,
                        })
                        .unwrap_or_else(|| ObjectId::new("", &self.local.current_role)),
                    owned_by: Some((alter.id.clone(), column_name.clone())),
                    kind,
                    parameters,
                    generation: self.local.generation_counter,
                }),
            );
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                sequence_id,
                alter.id.clone(),
                DependencyKind::SequenceOwnedBy {
                    column: column_name,
                },
            ));
        }
        if matches!(alter.action, AlterTableActionMutation::DropColumn { .. })
            && !drop_column_constraints.is_empty()
        {
            self.remove_dropped_constraints(&HashSet::new(), &drop_column_constraints);
            self.snapshot_graph_full();
            let resolution_graph = self.local.graph.clone();
            self.local.graph.retain_edges(|edge| {
                let dependent = resolution_graph.resolve_rename(&edge.dependent);
                match &edge.kind {
                    DependencyKind::ForeignKey {
                        constraint_name: Some(name),
                        ..
                    } => !drop_column_constraints.contains(&(dependent.clone(), name.clone())),
                    DependencyKind::ConstraintOnRelation {
                        constraint_name: name,
                        ..
                    } => !drop_column_constraints.contains(&(dependent.clone(), name.clone())),
                    DependencyKind::ConstraintDependency {
                        constraint_name: name,
                        ..
                    } => !drop_column_constraints.contains(&(dependent.clone(), name.clone())),
                    _ => {
                        // The preflight above has already rejected unknown
                        // column-bearing edges; this arm keeps unrelated
                        // topology intact.
                        true
                    }
                }
            });
        }
        if !cascade_view_roots.is_empty() {
            let views = cascade_view_roots.into_iter().collect::<Vec<_>>();
            // Preflight established a column-level dependency and CASCADE;
            // this applies the recursive view/index closure PostgreSQL drops.
            let _ = self.apply_drop_relation_family(&views, true, "view");
        }
        if let AlterTableActionMutation::DropColumn { name, .. } = &alter.action {
            let resolved_table = self.local.graph.resolve_rename(&alter.id).clone();
            let resolution_graph = self.local.graph.clone();
            if self.local.graph.edges().iter().any(|edge| {
                resolution_graph.resolve_rename(&edge.dependent) == &resolved_table
                    && matches!(
                        &edge.kind,
                        DependencyKind::ColumnGeneratedFrom { column, .. }
                            | DependencyKind::ColumnDefaultOnSequence { column }
                            if column == name || cascade_generated_columns.contains(column)
                    )
            }) {
                self.snapshot_graph_full();
                self.local.graph.retain_edges(|edge| {
                    !(resolution_graph.resolve_rename(&edge.dependent) == &resolved_table
                        && matches!(
                            &edge.kind,
                            DependencyKind::ColumnGeneratedFrom { column, .. }
                                | DependencyKind::ColumnDefaultOnSequence { column }
                                if column == name || cascade_generated_columns.contains(column)
                        ))
                });
            }
        }
        if matches!(alter.action, AlterTableActionMutation::DropColumn { .. })
            && !drop_column_indexes.is_empty()
        {
            self.snapshot_graph_full();
            self.local.graph.retain_edges(|edge| {
                !(matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                    && drop_column_indexes.contains(&edge.dependent))
            });
        }
        match &alter.action {
            AlterTableActionMutation::DropColumn { name, .. } => {
                self.drop_not_null_constraint(&alter.id, name);
                for sequence_id in owned_sequences_for_column {
                    self.snapshot_sequence(&sequence_id);
                    self.local
                        .sequences
                        .insert(sequence_id.clone(), SequenceOverlay::Dropped);
                    self.snapshot_graph_full();
                    self.local.graph.retain_edges(|edge| {
                        !(matches!(edge.kind, DependencyKind::SequenceOwnedBy { .. })
                            && edge.dependent == sequence_id)
                    });
                }
            }
            AlterTableActionMutation::RenameColumn { from, to } => {
                self.snapshot_graph_full();
                let resolved_table = self.local.graph.resolve_rename(&alter.id).clone();
                self.local
                    .graph
                    .rename_index_column(&resolved_table, from, to);
                for sequence_id in owned_sequences_for_column {
                    self.snapshot_sequence(&sequence_id);
                    if let Some(SequenceOverlay::Present(sequence)) =
                        self.local.sequences.get_mut(&sequence_id)
                        && let Some((_, column)) = &mut sequence.owned_by
                    {
                        *column = to.clone();
                    }
                    self.snapshot_graph_full();
                    self.local
                        .graph
                        .rename_owned_sequence_column(&sequence_id, from, to);
                }
            }
            _ => {}
        }
        MutationResult::Applied
    }

    /// Return the key definitions that can be proved for a relation.
    /// `None` means a key exists but its columns (or index eligibility) are
    /// not represented by the current cache/model; callers must taint rather
    /// than invent a matching foreign-key target in that case.
    fn unique_keys_for_relation(&self, id: &ObjectId) -> Option<Vec<(Vec<String>, bool)>> {
        let resolved = self.local.graph.resolve_rename(id);
        if self.baseline_relation_is_known(resolved)
            && self
                .local
                .relations
                .get(resolved)
                .is_some_and(|overlay| {
                    matches!(overlay, RelationOverlay::Present(relation) if relation.columns.is_empty())
                })
        {
            return None;
        }
        let mut keys = Vec::new();
        let mut unknown = false;
        for edge in self.local.graph.edges() {
            if edge.dependent != *resolved {
                continue;
            }
            match &edge.kind {
                DependencyKind::ConstraintOnRelation {
                    columns,
                    is_primary,
                    ..
                } => {
                    if columns.is_empty() {
                        unknown = true;
                    } else {
                        keys.push((columns.clone(), *is_primary));
                    }
                }
                DependencyKind::IndexOnRelation {
                    is_unique: true, ..
                } => unknown = true,
                _ => {}
            }
        }
        if !keys.is_empty() {
            return Some(keys);
        }
        if unknown
            || self
                .local
                .constraints
                .iter()
                .any(|((table, _), constraint)| {
                    table == resolved
                        && matches!(
                            constraint.kind,
                            ConstraintKind::PrimaryKey | ConstraintKind::Unique
                        )
                })
        {
            None
        } else {
            Some(Vec::new())
        }
    }

    pub(super) fn apply_rename_relation(&mut self, rename: &Rename) -> MutationResult {
        let renames_relation = self.relation_is_present(&rename.old_id);
        let renames_index = self.index_is_present(&rename.old_id);
        if renames_index && rename.old_id.name != rename.new_id.name {
            for constraint in self.local.constraints.values().filter(|constraint| {
                constraint.backing_index.as_ref() == Some(&rename.old_id)
                    && matches!(
                        constraint.kind,
                        ConstraintKind::PrimaryKey
                            | ConstraintKind::Unique
                            | ConstraintKind::Exclusion
                    )
            }) {
                if constraint.name != rename.new_id.name
                    && self
                        .local
                        .constraints
                        .contains_key(&(constraint.table_id.clone(), rename.new_id.name.clone()))
                {
                    return MutationResult::Conflict {
                        reason: format!(
                            "constraint '{}' already exists on relation '{}'",
                            rename.new_id.name, constraint.table_id
                        ),
                    };
                }
            }
        }
        match self.relation_or_index_lookup(&rename.old_id) {
            RelationLookup::Present => {}
            _ if self.baseline_covers_family_object(
                &rename.old_id,
                crate::_internal::db::cache::CatalogFamily::Relations,
            ) || self.baseline_covers_family_object(
                &rename.old_id,
                crate::_internal::db::cache::CatalogFamily::Indexes,
            ) =>
            {
                return MutationResult::Conflict {
                    reason: format!("relation '{}' does not exist", rename.old_id),
                };
            }
            RelationLookup::Tombstone
            | RelationLookup::AuthoritativelyAbsent
            | RelationLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            }
            RelationLookup::WrongKind => {
                unreachable!("relation renames accept every modeled relation kind")
            }
        }
        if rename.old_id != rename.new_id && self.relation_namespace_is_taken(&rename.new_id) {
            return MutationResult::Conflict {
                reason: format!("relation '{}' already exists", rename.new_id),
            };
        }
        if rename.old_id.schema != rename.new_id.schema
            && !self.schema_is_present(&rename.new_id.schema)
        {
            if self.schema_absence_is_authoritative(&rename.new_id.schema) {
                return MutationResult::Conflict {
                    reason: format!("schema '{}' does not exist", rename.new_id.schema),
                };
            }
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
            return MutationResult::Skipped;
        }

        let schema_move = rename.old_id.schema != rename.new_id.schema;
        let associated_sequence_moves: Vec<(ObjectId, ObjectId)> = if schema_move {
            self.local
                .sequences
                .iter()
                .filter_map(|(id, overlay)| {
                    let SequenceOverlay::Present(sequence) = overlay else {
                        return None;
                    };
                    sequence
                        .owned_by
                        .as_ref()
                        .is_some_and(|(table, _)| table == &rename.old_id)
                        .then(|| {
                            (
                                id.clone(),
                                ObjectId::new(rename.new_id.schema.clone(), id.name.clone()),
                            )
                        })
                })
                .collect()
        } else {
            Vec::new()
        };
        let associated_index_moves: Vec<(ObjectId, ObjectId)> = if schema_move {
            self.local
                .graph
                .edges()
                .iter()
                .filter(|edge| {
                    matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                        && edge.referenced == rename.old_id
                })
                .map(|edge| {
                    (
                        edge.dependent.clone(),
                        ObjectId::new(rename.new_id.schema.clone(), edge.dependent.name.clone()),
                    )
                })
                .collect()
        } else {
            Vec::new()
        };
        for (old_id, new_id) in associated_sequence_moves
            .iter()
            .chain(&associated_index_moves)
        {
            if old_id != new_id && self.relation_namespace_is_taken(new_id) {
                return MutationResult::Conflict {
                    reason: format!("associated object '{}' already exists", new_id),
                };
            }
        }

        let publication_scope_updates: Vec<(String, Vec<usize>)> = self
            .local
            .publications
            .iter()
            .filter_map(|(publication_name, overlay)| {
                let crate::_internal::model::replication::PublicationOverlay::Present(publication) =
                    overlay
                else {
                    return None;
                };
                let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
                    &publication.scope
                else {
                    return None;
                };
                let indexes = objects
                    .iter()
                    .enumerate()
                    .filter_map(|(index, object)| {
                        let crate::_internal::analysis::facts::PublicationObjectFact::Table {
                            name,
                            ..
                        } = object
                        else {
                            return None;
                        };
                        (self.resolve_relation_id(name) == rename.old_id).then_some(index)
                    })
                    .collect::<Vec<_>>();
                (!indexes.is_empty()).then(|| (publication_name.clone(), indexes))
            })
            .collect();

        self.snapshot_namespace();
        if let Some(RelationOverlay::Present(mut state)) =
            self.local.relations.remove(&rename.old_id)
        {
            state.id = rename.new_id.clone();
            self.local
                .relations
                .insert(rename.new_id.clone(), RelationOverlay::Present(state));
        }
        let owned_sequence_ids: Vec<ObjectId> = self
            .local
            .sequences
            .iter()
            .filter_map(|(id, overlay)| match overlay {
                SequenceOverlay::Present(sequence)
                    if sequence
                        .owned_by
                        .as_ref()
                        .is_some_and(|(table, _)| table == &rename.old_id) =>
                {
                    Some(id.clone())
                }
                _ => None,
            })
            .collect();
        for sequence_id in owned_sequence_ids {
            self.snapshot_sequence(&sequence_id);
            if let Some(SequenceOverlay::Present(sequence)) =
                self.local.sequences.get_mut(&sequence_id)
                && let Some((table, _)) = &mut sequence.owned_by
            {
                *table = rename.new_id.clone();
            }
        }
        for (old_sequence_id, new_sequence_id) in &associated_sequence_moves {
            self.snapshot_sequence(old_sequence_id);
            self.snapshot_sequence(new_sequence_id);
            let Some(SequenceOverlay::Present(mut sequence)) =
                self.local.sequences.remove(old_sequence_id)
            else {
                continue;
            };
            sequence.id = new_sequence_id.clone();
            if let Some((table, _)) = &mut sequence.owned_by {
                *table = rename.new_id.clone();
            }
            self.local
                .sequences
                .insert(new_sequence_id.clone(), SequenceOverlay::Present(sequence));
            self.local
                .graph
                .propagate_sequence_rename(old_sequence_id, new_sequence_id);
            self.local.graph.add_edge(DependencyEdge::new(
                old_sequence_id.clone(),
                new_sequence_id.clone(),
                DependencyKind::RenameTo,
            ));
        }
        for (old_index_id, new_index_id) in &associated_index_moves {
            self.local
                .graph
                .propagate_index_rename(old_index_id, new_index_id);
            self.rename_index_catalog_references(old_index_id, new_index_id);
            self.local.graph.add_edge(DependencyEdge::new(
                old_index_id.clone(),
                new_index_id.clone(),
                DependencyKind::RenameTo,
            ));
        }
        let triggers_to_move: Vec<(ObjectId, crate::_internal::model::trigger::TriggerState)> =
            self.local
                .triggers
                .iter()
                .filter_map(|(id, overlay)| match overlay {
                    TriggerOverlay::Present(trigger) if trigger.table_id == rename.old_id => {
                        Some((id.clone(), trigger.clone()))
                    }
                    _ => None,
                })
                .collect();
        for (old_trigger_id, mut trigger) in triggers_to_move {
            let new_trigger_id = Self::trigger_key(&rename.new_id, &trigger.name);
            self.local.triggers.remove(&old_trigger_id);
            trigger.id = new_trigger_id.clone();
            trigger.table_id = rename.new_id.clone();
            self.local
                .triggers
                .insert(new_trigger_id.clone(), TriggerOverlay::Present(trigger));
            self.local
                .graph
                .propagate_trigger_rename(&old_trigger_id, &new_trigger_id);
            self.local.graph.add_edge(DependencyEdge::new(
                old_trigger_id,
                new_trigger_id,
                DependencyKind::RenameTo,
            ));
        }
        let constraints_to_move: Vec<(String, ConstraintState)> = self
            .local
            .constraints
            .iter()
            .filter(|((table_id, _), _)| table_id == &rename.old_id)
            .map(|((_, name), constraint)| (name.clone(), constraint.clone()))
            .collect();
        for (name, mut constraint) in constraints_to_move {
            self.snapshot_constraint(&rename.old_id, &name);
            self.snapshot_constraint(&rename.new_id, &name);
            self.local
                .constraints
                .remove(&(rename.old_id.clone(), name.clone()));
            constraint.table_id = rename.new_id.clone();
            self.local
                .constraints
                .insert((rename.new_id.clone(), name), constraint);
        }

        for (publication_name, object_indexes) in publication_scope_updates {
            self.snapshot_publication(&publication_name);
            if let Some(crate::_internal::model::replication::PublicationOverlay::Present(
                publication,
            )) = self.local.publications.get_mut(&publication_name)
                && let crate::_internal::analysis::facts::PublicationScope::Explicit(objects) =
                    &mut publication.scope
            {
                for index in object_indexes {
                    let Some(crate::_internal::analysis::facts::PublicationObjectFact::Table {
                        name,
                        ..
                    }) = objects.get_mut(index)
                    else {
                        continue;
                    };
                    let name_quoted = name.name.quoted;
                    let schema_quoted = name.schema.as_ref().is_some_and(|schema| schema.quoted);
                    name.name = crate::_internal::ast::identifiers::Ident::new(
                        rename.new_id.name.clone(),
                        name_quoted,
                    );
                    if name.schema.is_some() || rename.old_id.schema != rename.new_id.schema {
                        name.schema = Some(crate::_internal::ast::identifiers::Ident::new(
                            rename.new_id.schema.clone(),
                            schema_quoted,
                        ));
                    }
                }
            }
        }
        self.local.pending_validation = std::mem::take(&mut self.local.pending_validation)
            .into_iter()
            .map(|(table, name)| {
                if table == rename.old_id {
                    (rename.new_id.clone(), name)
                } else {
                    (table, name)
                }
            })
            .collect();
        self.local.graph.add_edge(DependencyEdge::new(
            rename.old_id.clone(),
            rename.new_id.clone(),
            DependencyKind::RenameTo,
        ));
        if renames_relation {
            self.local
                .graph
                .propagate_relation_rename(&rename.old_id, &rename.new_id);
        }
        if renames_index {
            self.local
                .graph
                .propagate_index_rename(&rename.old_id, &rename.new_id);
            self.rename_index_catalog_references(&rename.old_id, &rename.new_id);
        }

        if renames_relation {
            if self.baseline_relations.remove(&rename.old_id) {
                self.baseline_relations.insert(rename.new_id.clone());
            }
            if self.baseline_fk_dependencies.remove(&rename.old_id) {
                self.baseline_fk_dependencies.insert(rename.new_id.clone());
            }
            self.baseline_foreign_keys = std::mem::take(&mut self.baseline_foreign_keys)
                .into_iter()
                .map(|(table, name)| {
                    if table == rename.old_id {
                        (rename.new_id.clone(), name)
                    } else {
                        (table, name)
                    }
                })
                .collect();
        }
        if renames_index && self.baseline_indexes.remove(&rename.old_id) {
            self.baseline_indexes.insert(rename.new_id.clone());
        }
        for (old_sequence_id, new_sequence_id) in &associated_sequence_moves {
            if self.baseline_sequences.remove(old_sequence_id) {
                self.baseline_sequences.insert(new_sequence_id.clone());
            }
        }
        for (old_index_id, new_index_id) in &associated_index_moves {
            if self.baseline_indexes.remove(old_index_id) {
                self.baseline_indexes.insert(new_index_id.clone());
            }
        }

        MutationResult::Applied
    }

    // The caller takes a namespace snapshot before changing these coupled identities.
    fn rename_index_catalog_references(&mut self, old: &ObjectId, new: &ObjectId) {
        let constraints = self
            .local
            .constraints
            .values()
            .filter(|constraint| constraint.backing_index.as_ref() == Some(old))
            .cloned()
            .collect::<Vec<_>>();
        for mut constraint in constraints {
            let old_name = constraint.name.clone();
            let owns_index = matches!(
                constraint.kind,
                ConstraintKind::PrimaryKey | ConstraintKind::Unique | ConstraintKind::Exclusion
            );
            if owns_index && old.name != new.name {
                constraint.name = new.name.clone();
            }
            self.local
                .constraints
                .remove(&(constraint.table_id.clone(), old_name.clone()));
            constraint.backing_index = Some(new.clone());
            if old_name != constraint.name {
                self.local.graph.rename_constraint(
                    &constraint.table_id,
                    &old_name,
                    &constraint.name,
                );
            }
            self.local.constraints.insert(
                (constraint.table_id.clone(), constraint.name.clone()),
                constraint,
            );
        }
        if old.name == new.name {
            return;
        }
        let old_replica = format!("USING INDEX {}", old.name);
        for (id, overlay) in &mut self.local.relations {
            let RelationOverlay::Present(relation) = overlay else {
                continue;
            };
            if id.schema != old.schema {
                continue;
            }
            if relation.cluster_index.as_deref() == Some(old.name.as_str()) {
                relation.cluster_index = Some(new.name.clone());
            }
            if relation.replica_identity.as_deref() == Some(old_replica.as_str()) {
                relation.replica_identity = Some(format!("USING INDEX {}", new.name));
            }
        }
    }

    pub(super) fn apply_change_relation_owner(
        &mut self,
        id: &ObjectId,
        new_owner: &crate::_internal::analysis::facts::RoleFact,
    ) -> MutationResult {
        let Some((owner, known)) = self.role_fact_identity(new_owner) else {
            self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Chain);
            return MutationResult::Skipped;
        };
        if !known {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }
        if known && self.local.roles_known && self.present_role(&owner).is_none() {
            return MutationResult::Conflict {
                reason: format!("role '{}' does not exist", owner),
            };
        }
        if known && !self.local.roles_known {
            self.taint(
                EvidenceCode::CatalogCoverageIncomplete,
                EvidenceScope::Chain,
            );
        }
        match self.relation_lookup(id, |_| true) {
            RelationLookup::Present => {
                let owner_id = ObjectId::new("", owner.clone());
                self.snapshot_relation(id);
                {
                    let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(id)
                    else {
                        unreachable!("relation lookup established presence")
                    };
                    relation.owner = owner_id.clone();
                }
                self.transfer_owned_sequence_owners(id, &owner_id);
                MutationResult::Applied
            }
            RelationLookup::WrongKind => {
                unreachable!("all present relation kinds accept owner changes")
            }
            RelationLookup::Tombstone | RelationLookup::AuthoritativelyAbsent => {
                MutationResult::Conflict {
                    reason: format!("relation '{}' does not exist", id),
                }
            }
            RelationLookup::Unknown => {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                MutationResult::Skipped
            }
        }
    }

    /// PostgreSQL transfers ownership of sequences owned by table columns
    /// together with the table. Keep this dependent metadata synchronized for
    /// both ALTER TABLE OWNER and the direct relation-owner mutation path.
    fn transfer_owned_sequence_owners(&mut self, table: &ObjectId, owner: &ObjectId) {
        let owned_sequence_ids: Vec<ObjectId> = self
            .local
            .sequences
            .iter()
            .filter_map(|(sequence_id, overlay)| {
                let SequenceOverlay::Present(sequence) = overlay else {
                    return None;
                };
                sequence
                    .owned_by
                    .as_ref()
                    .is_some_and(|(owned_table, _)| owned_table == table)
                    .then_some(sequence_id.clone())
            })
            .collect();
        for sequence_id in owned_sequence_ids {
            self.snapshot_sequence(&sequence_id);
            if let Some(SequenceOverlay::Present(sequence)) =
                self.local.sequences.get_mut(&sequence_id)
            {
                sequence.owner = owner.clone();
            }
        }
    }

    fn invalidate_descendant_partition_predicates(&mut self, root: &ObjectId) {
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
    fn register_retained_partition_check(&mut self, child: &ObjectId, definition: String) {
        use squawk_syntax::ast::{AstNode, SourceFile, Target};
        let parsed = SourceFile::parse(&format!("SELECT {definition}"));
        let columns = if parsed.errors().is_empty() && parsed.tree().stmts().count() == 1 {
            parsed
                .tree()
                .syntax()
                .descendants()
                .find_map(Target::cast)
                .and_then(|target| target.expr())
                .and_then(|expr| {
                    crate::_internal::analysis::expr_visitor::ExprVisitor::convert(expr)
                        .referenced_columns()
                })
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

    fn retained_check_for_detached_partition(
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
    /// Plain identifiers and quoted identifiers are accepted; expressions and
    /// opclass/collation annotations return `None`, because PostgreSQL then
    /// deparses the retained predicate in terms of the expression, not a
    /// column.
    fn partition_key_columns(&self, parent: &ObjectId) -> Option<Vec<(String, String)>> {
        use squawk_syntax::ast::{AstNode, Expr, PartitionBy, SourceFile};
        let Some(RelationOverlay::Present(parent)) = self.local.relations.get(parent) else {
            return None;
        };
        let partition_by = parent.partition_by.as_deref()?;
        let parsed = SourceFile::parse(&format!("CREATE TABLE __key () {partition_by}"));
        if !parsed.errors().is_empty() || parsed.tree().stmts().count() != 1 {
            return None;
        }
        let partition = parsed
            .tree()
            .syntax()
            .descendants()
            .find_map(PartitionBy::cast)?;
        let mut columns = Vec::new();
        for item in partition.partition_item_list()?.partition_items() {
            if item.collate().is_some()
                || item.op_class_ref().is_some()
                || item.attribute_list().is_some()
                || item.nulls_order().is_some()
            {
                return None;
            }
            let Expr::NameRef(name) = item.expr()? else {
                return None;
            };
            columns.push((name.text().to_string(), name.syntax().text().to_string()));
        }
        if columns.is_empty() {
            None
        } else {
            Some(columns)
        }
    }

    /// Fold PostgreSQL's `eval_const_expressions` normalizations of a LIST
    /// partition predicate into their retained-CHECK forms:
    /// `= ANY (ARRAY[...])` becomes an array constant and a single
    /// `= true`/`= false` becomes the bare column / `NOT <column>`.
    /// Single-datum non-boolean predicates are already in final form and are
    /// passed through unchanged.
    fn fold_list_partition_predicate(&self, predicate: &str, child: &ObjectId) -> Option<String> {
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
            let mapped = elements_for_array(&values, &array_type)?;
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
    fn synthesize_partition_check(
        &self,
        strategy: &str,
        bound: &str,
        keys: &[(String, String)],
        relation: &RelationState,
    ) -> Option<String> {
        if keys.len() != 1 {
            return None;
        }
        let (key_name, key) = &keys[0];
        let column_type = relation
            .columns
            .iter()
            .find(|column| &column.name == key_name)
            .and_then(|column| column.data_type.as_deref())?;
        let comparison_left = if column_type.starts_with("character varying") {
            format!("({key})::text")
        } else {
            key.clone()
        };
        if strategy.eq_ignore_ascii_case("RANGE") {
            let lower = extract_paren_group(bound, "FROM (")?;
            let upper = extract_paren_group(bound, "TO (")?;
            let lower_datums = split_top_level(&lower, ',');
            let upper_datums = split_top_level(&upper, ',');
            if lower_datums.len() != upper_datums.len() || lower_datums.len() != keys.len() {
                return None;
            }
            let lower = lower_datums[0].trim();
            let upper = upper_datums[0].trim();
            let mut clauses = vec![format!("({key} IS NOT NULL)")];
            if !lower.eq_ignore_ascii_case("MINVALUE") {
                let literal = deparse_partition_literal(column_type, lower)?;
                clauses.push(format!("({comparison_left} >= {literal})"));
            }
            if !upper.eq_ignore_ascii_case("MAXVALUE") {
                let literal = deparse_partition_literal(column_type, upper)?;
                clauses.push(format!("({comparison_left} < {literal})"));
            }
            Some(format!("({})", clauses.join(" AND ")))
        } else if strategy.eq_ignore_ascii_case("LIST") {
            let inner = extract_paren_group(bound, "IN (")?;
            let datums = split_top_level(&inner, ',');
            match datums.as_slice() {
                [single] => {
                    let literal = deparse_partition_literal(column_type, single.trim())?;
                    if column_type == "boolean" {
                        let narrow = if literal == "true" {
                            key.clone()
                        } else if literal == "false" {
                            format!("(NOT {key})")
                        } else {
                            return None;
                        };
                        return Some(format!("(({key} IS NOT NULL) AND {narrow})"));
                    }
                    Some(format!(
                        "(({key} IS NOT NULL) AND ({comparison_left} = {literal}))"
                    ))
                }
                [] => None,
                _ => {
                    let mut values = Vec::new();
                    for datum in datums {
                        values.push(decode_sql_literal(datum.trim())?);
                    }
                    let mapped = elements_for_array(&values, column_type)?;
                    if matches!(column_type, "integer" | "smallint" | "bigint") {
                        return Some(format!(
                            "(({key} IS NOT NULL) AND ({comparison_left} = ANY (ARRAY[{}])))",
                            mapped.join(", ")
                        ));
                    }
                    let array_text = serialize_array_literal(&mapped);
                    Some(format!(
                        "(({key} IS NOT NULL) AND ({comparison_left} = ANY ('{array_text}'::{column_type}[])))"
                    ))
                }
            }
        } else {
            None
        }
    }

    fn synthesize_default_partition_constraint(&self, parent: &ObjectId) -> Option<String> {
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
                let predicate = self.synthesize_partition_check(strategy, bound, &keys, child)?;
                let predicate = if predicate.starts_with("((") && predicate.ends_with("))") {
                    let inner = &predicate[1..predicate.len() - 1];
                    if let Some(separator) = inner.find(") AND (") {
                        let first = &inner[..separator + 1];
                        let rest = &inner[separator + 6..];
                        format!("({first} AND ({rest}))")
                    } else {
                        predicate
                    }
                } else {
                    predicate
                };
                Some(predicate)
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

    fn refresh_default_partition_constraints(&mut self, parent: &ObjectId) {
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

/// Match PostgreSQL's stable `pg_get_expr(relpartbound, ...)` spelling for
/// the bound forms represented by the typed Squawk node.
fn canonical_partition_bound(bound: &str) -> String {
    let trimmed = bound.trim();
    if trimmed.eq_ignore_ascii_case("DEFAULT") {
        return "DEFAULT".into();
    }
    let upper = trimmed.to_ascii_uppercase();
    if upper.starts_with("FOR VALUES IN (") {
        let inner = &trimmed["FOR VALUES IN (".len()..trimmed.len().saturating_sub(1)];
        let values = split_top_level(inner, ',')
            .into_iter()
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(", ");
        return format!("FOR VALUES IN ({values})");
    }
    if upper.starts_with("FOR VALUES FROM (")
        && let (Some(from), Some(to)) = (
            extract_paren_group(trimmed, "FROM ("),
            extract_paren_group(trimmed, "TO ("),
        )
    {
        let from = split_top_level(&from, ',')
            .into_iter()
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(", ");
        let to = split_top_level(&to, ',')
            .into_iter()
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(", ");
        return format!("FOR VALUES FROM ({from}) TO ({to})");
    }
    if upper.starts_with("FOR VALUES WITH (")
        && let Some(inner) = extract_paren_group(trimmed, "WITH (")
    {
        let values = split_top_level(&inner, ',')
            .into_iter()
            .map(str::trim)
            .map(|value| {
                let mut words = value.splitn(2, char::is_whitespace);
                let key = words.next().unwrap_or_default().to_ascii_lowercase();
                let rest = words.next().unwrap_or_default().trim();
                format!("{key} {rest}")
            })
            .collect::<Vec<_>>()
            .join(", ");
        return format!("FOR VALUES WITH ({values})");
    }
    trimmed.to_string()
}

/// Whether PostgreSQL retains a CHECK constraint on `DETACH PARTITION
/// CONCURRENTLY` and whether the local model can reproduce its exact text.
#[derive(Debug)]
enum RetainedCheckSynthesis {
    /// HASH partitions never gain a retained constraint.
    NoCheck,
    /// Exact `pg_get_expr(conbin)` text of the retained CHECK.
    Definition(String),
    /// The predicate is not representable exactly; callers keep the
    /// conservative `UnsupportedSemantics` taint.
    CantResolve,
}

/// Split `input` on `separator` at the top nesting level of `()`, `[]`, `{}`
/// and single-quoted SQL string literals (with doubled-quote handling).
fn split_top_level(input: &str, separator: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth: i32 = 0;
    let mut chars = input.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
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
            _ => {}
        }
        if ch == separator && depth <= 0 {
            parts.push(&input[start..index]);
            start = index + ch.len_utf8();
        }
    }
    parts.push(&input[start..]);
    parts
}

/// Return the SQL string value of a bound/constraint literal token, unwrapping
/// a leading `'...'` (doubled quotes) and any `::type` suffix. Bare tokens
/// (numbers, booleans, identifiers) pass through unchanged.
fn decode_sql_literal(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let raw = raw.split("::").next().unwrap_or(raw).trim();
    if let Some(inner) = raw.strip_prefix('\'') {
        let mut value = String::new();
        let mut chars = inner.char_indices().peekable();
        while let Some((_, ch)) = chars.next() {
            if ch == '\'' {
                match chars.peek() {
                    Some((_, '\'')) => {
                        chars.next();
                        value.push('\'');
                    }
                    _ => return Some(value),
                }
            } else {
                value.push(ch);
            }
        }
        None
    } else if !raw.chars().any(|ch| matches!(ch, '(' | ')' | '\'')) {
        Some(raw.to_string())
    } else {
        None
    }
}

/// Extract the balanced parenthesized content following `needle` (which must
/// end with `(`), returning the group's inner text.
fn extract_paren_group(input: &str, needle: &str) -> Option<String> {
    let lowercase = input.to_ascii_lowercase();
    let needle_lower = needle.to_ascii_lowercase();
    let start = lowercase.find(&needle_lower)?;
    // `needle` ends with `(`, so the group content begins right after it.
    let content = &input[start + needle.len()..];
    let mut depth = 0i32;
    let mut chars = content.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        match ch {
            '(' => depth += 1,
            ')' => {
                if depth == 0 {
                    return Some(content[..index].to_string());
                }
                depth -= 1;
            }
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
            _ => {}
        }
    }
    None
}

/// Choose the array element type for a folded `ARRAY[...]` constant. When
/// elements carry homogeneous `::type` casts that cast is used; otherwise the
/// key column type applies. Mixed casts conservatively fail (`None`).
fn array_element_type(elements: &[&str], fallback: &str) -> Option<String> {
    let first_cast = elements
        .first()?
        .split("::")
        .nth(1)
        .map(str::trim)
        .map(str::to_owned);
    for element in elements.iter().skip(1) {
        let cast = element.split("::").nth(1).map(str::trim).map(str::to_owned);
        if cast != first_cast {
            return None;
        }
    }
    Some(first_cast.unwrap_or_else(|| fallback.to_string()))
}

/// Render partition-list values in the array-constant element syntax for the
/// key column type (`t`/`f` for booleans, otherwise the element text as-is).
fn elements_for_array(values: &[String], column_type: &str) -> Option<Vec<String>> {
    match column_type {
        "boolean" => values
            .iter()
            .map(|value| {
                if value.eq_ignore_ascii_case("true") {
                    Some("t".to_string())
                } else if value.eq_ignore_ascii_case("false") {
                    Some("f".to_string())
                } else {
                    None
                }
            })
            .collect(),
        "integer" | "smallint" | "bigint" | "numeric" | "text" | "name" | "citext" => {
            Some(values.to_vec())
        }
        type_name
            if type_name.starts_with("character varying")
                || type_name.starts_with("character(")
                || type_name.starts_with("bpchar") =>
        {
            Some(values.to_vec())
        }
        _ => None,
    }
}

/// Serialize array element values into the `{...}` array-literal text with
/// PostgreSQL's element quoting (double quotes around elements containing
/// specials, `"` and `\` backslash-escaped) and single-quote doubling for the
/// enclosing string literal.
fn serialize_array_literal(values: &[String]) -> String {
    let inner = values
        .iter()
        .map(|value| {
            let special = value.is_empty()
                || value.contains([',', '"', '\\', '{', '}'])
                || value.starts_with(' ')
                || value.ends_with(' ')
                || value.starts_with('\n')
                || value.ends_with('\n');
            let token = if special {
                let mut quoted = String::from("\"");
                for ch in value.chars() {
                    if ch == '"' || ch == '\\' {
                        quoted.push('\\');
                    }
                    quoted.push(ch);
                }
                quoted.push('"');
                quoted
            } else {
                value.to_string()
            };
            token.replace('\'', "''")
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{inner}}}")
}

/// Fold a single-datum boolean LIST predicate (`X = true` -> `X`,
/// `X = false` -> `NOT X`). Non-boolean single-datum predicates are already in
/// final form and are returned unchanged.
fn fold_boolean_equality(predicate: &str) -> Option<String> {
    let equality = predicate
        .find("= true")
        .map(|position| (position, "= true", true))
        .or_else(|| {
            predicate
                .find("= false")
                .map(|position| (position, "= false", false))
        });
    let Some((position, needle, is_true)) = equality else {
        return Some(predicate.to_string());
    };
    let open = predicate[..position].rfind('(')?;
    let variable = predicate[open + 1..position].trim();
    if variable.is_empty() || !variable.chars().all(|ch| ch.is_alphanumeric() || ch == '_') {
        return None;
    }
    let after = &predicate[position + needle.len()..];
    let close = after.find(')')?;
    let replacement = if is_true {
        variable.to_string()
    } else {
        format!("(NOT {variable})")
    };
    Some(format!(
        "{}{}{}",
        &predicate[..open],
        replacement,
        &after[close + 1..]
    ))
}

/// Extract the column variable referenced by an `= ANY (...)`/`= true` clause
/// from a fully-deparsed predicate (`((col IS NOT NULL) AND (col = ...))`).
fn predicate_column_name(predicate: &str) -> Option<String> {
    let start = predicate.find(" IS NOT NULL)")?;
    let open = predicate[..start].rfind('(')?;
    let name = predicate[open + 1..start].trim();
    if name.is_empty() || !name.chars().all(|ch| ch.is_alphanumeric() || ch == '_') {
        None
    } else {
        Some(name.to_string())
    }
}

/// Deparse a single bound literal exactly as `get_const_expr`/`ruleutils`
/// would for the column's data type: booleans bare, INT4 bare when
/// non-negative and quoted otherwise, smallint/bigint/real/double always
/// quoted, numeric quoted unless it looks like a float literal, and
/// text-like/uuid/ISO-date values quoted with a `::type` cast.
fn deparse_partition_literal(data_type: &str, raw: &str) -> Option<String> {
    let decoded = decode_sql_literal(raw)?;
    match data_type {
        "boolean" => {
            if decoded.eq_ignore_ascii_case("true") {
                Some("true".to_string())
            } else if decoded.eq_ignore_ascii_case("false") {
                Some("false".to_string())
            } else {
                None
            }
        }
        "integer" => {
            let value: i64 = decoded.parse().ok()?;
            if (i32::MIN as i64..=i32::MAX as i64).contains(&value) {
                if value >= 0 {
                    Some(value.to_string())
                } else {
                    Some(format!("'{}'::integer", value))
                }
            } else {
                None
            }
        }
        "smallint" => {
            let value: i16 = decoded.parse().ok()?;
            Some(format!("'{}'::smallint", value))
        }
        "bigint" => {
            let value: i64 = decoded.parse().ok()?;
            Some(format!("'{}'::bigint", value))
        }
        "numeric" => {
            if numeric_float_like(&decoded) {
                Some(decoded)
            } else {
                Some(format!("'{}'::numeric", decoded))
            }
        }
        "real" | "double precision" => {
            if numeric_float_like(&decoded) {
                Some(format!("'{}'::{}", decoded, data_type))
            } else {
                None
            }
        }
        "date" => {
            if decoded.len() == 10
                && decoded.as_bytes()[4] == b'-'
                && decoded.as_bytes()[7] == b'-'
                && decoded
                    .chars()
                    .enumerate()
                    .all(|(index, ch)| (index == 4 || index == 7) || ch.is_ascii_digit())
            {
                Some(format!("'{}'::date", decoded))
            } else {
                None
            }
        }
        "uuid" => {
            if decoded.len() == 36
                && decoded.as_bytes()[8] == b'-'
                && decoded.as_bytes()[13] == b'-'
                && decoded.as_bytes()[18] == b'-'
                && decoded.as_bytes()[23] == b'-'
                && decoded
                    .chars()
                    .all(|ch| ch.is_ascii_hexdigit() || ch == '-')
            {
                Some(format!("'{}'::uuid", decoded))
            } else {
                None
            }
        }
        type_name
            if type_name == "text"
                || type_name == "name"
                || type_name == "citext"
                || type_name.starts_with("character varying")
                || type_name.starts_with("character(")
                || type_name.starts_with("bpchar") =>
        {
            Some(format!("'{}'::{}", decoded.replace('\'', "''"), data_type))
        }
        _ => None,
    }
}

/// `get_const_expr` prints a NUMERIC constant bare when it looks like a float
/// literal (starts with a digit and contains `.`, `e`, or `E`).
fn numeric_float_like(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_digit()
        && value[first.len_utf8()..]
            .chars()
            .any(|ch| matches!(ch, '.' | 'e' | 'E'))
}
