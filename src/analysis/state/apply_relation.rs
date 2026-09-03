use super::{AnalysisState, CascadeResult, MutationResult, ObjectLookup, RelationOverlay};
use crate::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::analysis::facts::TableConstraintFact;
use crate::analysis::graph::{DependencyEdge, DependencyKind};
use crate::analysis::mutations::{
    AlterTable, AlterTableActionMutation, CreateTable, DropTable, PersistenceMutation, Rename,
};
use crate::ast::identifiers::ObjectId;
use crate::model::constraint::{ConstraintKind, ConstraintState};
use crate::model::relation::{ColumnAction, RelationKind, RelationState};
use crate::model::sequence::{SequenceKind, SequenceOverlay, SequenceState};
use crate::model::trigger::TriggerOverlay;
use std::collections::HashSet;

type RelationLookup = ObjectLookup;

impl AnalysisState {
    fn relation_or_index_lookup(&self, id: &ObjectId) -> RelationLookup {
        if self.relation_is_present(id) || self.index_is_present(id) {
            RelationLookup::Present
        } else if matches!(self.local.relations.get(id), Some(RelationOverlay::Dropped)) {
            RelationLookup::Tombstone
        } else if self.baseline_covers_family_object(id, crate::db::cache::CatalogFamily::Relations)
            || self.baseline_covers_family_object(id, crate::db::cache::CatalogFamily::Indexes)
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
            && !self.baseline_has_coverage(crate::db::cache::CatalogFamily::Dependencies)
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
            self.baseline_scoped_family_object(id, crate::db::cache::CatalogFamily::Relations)
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
                && !self.baseline_has_coverage(crate::db::cache::CatalogFamily::Dependencies)
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
                    DependencyKind::InheritanceOf | DependencyKind::PartitionOf
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
                let crate::model::replication::PublicationOverlay::Present(publication) = overlay
                else {
                    return None;
                };
                let crate::analysis::facts::PublicationScope::Explicit(objects) =
                    &publication.scope
                else {
                    return None;
                };
                let retained = objects
                    .iter()
                    .filter(|object| {
                        let crate::analysis::facts::PublicationObjectFact::Table { name, .. } =
                            object
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
            if let Some(crate::model::replication::PublicationOverlay::Present(publication)) =
                self.local.publications.get_mut(&publication_name)
                && let crate::analysis::facts::PublicationScope::Explicit(objects) =
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

    pub(super) fn apply_create_table(&mut self, create: &CreateTable) -> MutationResult {
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

        let mut column_names = HashSet::new();
        for column in &create.columns {
            if !column_names.insert(column.name.clone()) {
                return MutationResult::Conflict {
                    reason: format!("column '{}' specified more than once", column.name),
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

        if let Some(parent_id) = &create.partition_of
            && let Err(result) = self.ensure_relation_target(
                parent_id,
                |kind| *kind == RelationKind::Table,
                format!("partition parent relation '{}' does not exist", parent_id),
                format!("partition parent '{}' is not a table", parent_id),
            )
        {
            return result;
        }
        if let Some(parent_id) = &create.partition_of {
            let Some(RelationOverlay::Present(parent)) = self.local.relations.get(parent_id) else {
                self.taint(EvidenceCode::UnknownObjectState, EvidenceScope::Chain);
                return MutationResult::Skipped;
            };
            if parent.partition_type.is_none() {
                return MutationResult::Conflict {
                    reason: format!("partition parent '{}' is not partitioned", parent_id),
                };
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

        // PostgreSQL chooses all implicit sequence names before the
        // table becomes visible. Reserve them up front so a collision
        // or malformed statement cannot leave partial local state.
        let mut reserved_sequences = HashSet::new();
        let mut implicit_sequences = Vec::new();
        for column in &create.columns {
            let kind = match column.generation {
                crate::analysis::facts::ColumnGeneration::Serial => Some(SequenceKind::SerialLike),
                crate::analysis::facts::ColumnGeneration::Identity => Some(SequenceKind::Identity),
                crate::analysis::facts::ColumnGeneration::Ordinary => None,
            };
            if let Some(kind) = kind {
                let sequence_id =
                    self.next_implicit_sequence_id(&create.id, &column.name, &reserved_sequences);
                reserved_sequences.insert(sequence_id.clone());
                implicit_sequences.push((sequence_id, column.name.clone(), kind));
            }
        }

        // Resolve every constraint name before mutating the relation. PostgreSQL
        // rejects duplicate names atomically, while a state map would otherwise
        // silently overwrite the earlier inline constraint.
        let mut reserved_constraint_names = HashSet::new();
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
                self.next_generated_constraint_name_avoiding(
                    &create.id,
                    &create.id.name,
                    None,
                    "pkey",
                    &reserved_constraint_names,
                )
            })
        });
        if let Some(name) = &primary_key_constraint_name
            && !reserved_constraint_names.insert(name.clone())
        {
            return MutationResult::Conflict {
                reason: format!("constraint '{}' is specified more than once", name),
            };
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
                self.next_generated_constraint_name_avoiding(
                    &create.id,
                    &create.id.name,
                    Some(&columns.join("_")),
                    "key",
                    &reserved_constraint_names,
                )
            });
            if !reserved_constraint_names.insert(name.clone()) {
                return MutationResult::Conflict {
                    reason: format!("constraint '{}' is specified more than once", name),
                };
            }
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
            let (kind, explicit_name, label, columns, columns_complete) = match constraint {
                TableConstraintFact::Check {
                    constraint_name,
                    columns,
                    columns_complete,
                } => (
                    ConstraintKind::Check,
                    constraint_name,
                    "check",
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
                    "excl",
                    columns,
                    columns_complete,
                ),
                _ => continue,
            };
            let name = explicit_name.clone().unwrap_or_else(|| {
                self.next_generated_constraint_name_avoiding(
                    &create.id,
                    &create.id.name,
                    None,
                    label,
                    &reserved_constraint_names,
                )
            });
            if !reserved_constraint_names.insert(name.clone()) {
                return MutationResult::Conflict {
                    reason: format!("constraint '{}' is specified more than once", name),
                };
            }
            inline_constraint_names.push((kind, name, columns.clone(), *columns_complete));
        }

        self.snapshot_relation(&create.id);

        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;

        let resolved_persistence = match create.persistence {
            PersistenceMutation::Permanent => crate::model::relation::Persistence::Permanent,
            PersistenceMutation::Temporary => crate::model::relation::Persistence::Temporary,
            PersistenceMutation::Unlogged => crate::model::relation::Persistence::Unlogged,
        };

        let mut rel_state = RelationState::new(
            create.id.clone(),
            ObjectId::new("", &self.local.current_role),
            generation,
            if create.as_select { None } else { Some(0) },
            RelationKind::Table,
            resolved_persistence,
            self.local.transactions.len(),
        );

        if create.as_select {
            // CTAS derives its columns from a query that is intentionally not
            // represented in the current fact model. Keep the relation
            // identity for the destructive-operation rule, but make later
            // column-targeting transitions conservative.
            self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
        }

        // Store partition strategy information
        rel_state.partition_type = create
            .partition_by
            .as_ref()
            .and_then(|partition_by| partition_by.split_whitespace().nth(2))
            .and_then(|strategy| strategy.split('(').next())
            .map(str::to_uppercase)
            .or_else(|| {
                create.partition_of.as_ref().and_then(|parent_id| {
                    self.local.relations.get(parent_id).and_then(|r| {
                        if let RelationOverlay::Present(rel) = r {
                            rel.partition_type.clone()
                        } else {
                            None
                        }
                    })
                })
            });
        rel_state.partition_by = create.partition_by.clone();

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

        for col in &create.columns {
            let is_pk = col.is_primary_key || pk_columns.contains(col.name.as_str());
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
                column.type_id = column
                    .data_type
                    .as_deref()
                    .and_then(|raw| self.resolve_type_reference(raw));
            }
        }

        for (sequence_id, column_name, _) in &implicit_sequences {
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

        for (sequence_id, column_name, kind) in implicit_sequences {
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
            self.snapshot_constraint(&create.id, &name);
            self.local.constraints.insert(
                (create.id.clone(), name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name: name.clone(),
                    kind: ConstraintKind::PrimaryKey,
                    validated: true,
                    backing_index: None,
                },
            );
        }

        for (name, columns) in unique_constraint_names {
            self.snapshot_constraint(&create.id, &name);
            self.local.constraints.insert(
                (create.id.clone(), name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name: name.clone(),
                    kind: ConstraintKind::Unique,
                    validated: true,
                    backing_index: None,
                },
            );
            self.snapshot_graph();
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
        for (kind, name, columns, columns_complete) in inline_constraint_names {
            self.snapshot_constraint(&create.id, &name);
            self.local.constraints.insert(
                (create.id.clone(), name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name: name.clone(),
                    kind,
                    validated: true,
                    backing_index: None,
                },
            );
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
            }
            AlterTableActionMutation::SetNotNull { column }
            | AlterTableActionMutation::DropNotNull { column }
            | AlterTableActionMutation::SetType { column, .. }
            | AlterTableActionMutation::SetDefault { column, .. }
                if !relation.has_column(column) =>
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "column '{}' does not exist on relation '{}'",
                        column, alter.id
                    ),
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
                            crate::db::cache::CatalogFamily::Relations,
                        ) {
                        MutationResult::Skipped
                    } else if self.baseline_covers_family_object(
                        &alter.id,
                        crate::db::cache::CatalogFamily::Relations,
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
                constraint_name, ..
            } => {
                let name = constraint_name.clone().unwrap_or_else(|| {
                    self.next_generated_constraint_name_avoiding(
                        &alter.id,
                        &alter.id.name,
                        None,
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
                    (matches!(edge.kind, DependencyKind::PartitionOf) && edge.dependent == *child)
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
            }
            AlterTableActionMutation::DetachPartition { child } => {
                if let Err(result) = self.ensure_relation_target(
                    child,
                    |kind| *kind == RelationKind::Table,
                    format!("partition child relation '{}' does not exist", child),
                    format!("partition child '{}' is not a table", child),
                ) {
                    return result;
                }
                if !self.local.graph.edges().iter().any(|edge| {
                    matches!(edge.kind, DependencyKind::PartitionOf)
                        && edge.dependent == *child
                        && edge.referenced == alter.id
                }) {
                    return MutationResult::Conflict {
                        reason: format!(
                            "partition '{}' is not attached to parent '{}'",
                            child, alter.id
                        ),
                    };
                }
            }
            // These are fully typed, but their physical storage details are
            // intentionally outside the schema state. Preserve the modeled
            // relation while recording that the post-statement physical
            // state is not represented; returning Applied without evidence
            // would falsely claim an exact transition.
            AlterTableActionMutation::SetStorage { .. }
            | AlterTableActionMutation::SetAccessMethod => {
                self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Statement);
                return MutationResult::Applied;
            }
            AlterTableActionMutation::Opaque => {
                self.taint(EvidenceCode::UnsupportedSemantics, EvidenceScope::Chain);
                return MutationResult::Applied;
            }
            _ => {}
        }

        let trigger_mode = match &alter.action {
            AlterTableActionMutation::DisableTrigger { trigger_name } => Some((
                trigger_name.as_deref(),
                crate::model::trigger::TriggerEnableMode::Disabled,
            )),
            AlterTableActionMutation::EnableTrigger { trigger_name } => Some((
                trigger_name.as_deref(),
                crate::model::trigger::TriggerEnableMode::Origin,
            )),
            _ => None,
        };
        if let Some((trigger_name, enabled_mode)) = trigger_mode {
            let all = trigger_name.is_none_or(|name| name.eq_ignore_ascii_case("all"));
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
                name, generation, ..
            } => match generation {
                crate::analysis::facts::ColumnGeneration::Serial => Some((
                    self.next_implicit_sequence_id(&alter.id, name, &HashSet::new()),
                    name.clone(),
                    SequenceKind::SerialLike,
                )),
                crate::analysis::facts::ColumnGeneration::Identity => Some((
                    self.next_implicit_sequence_id(&alter.id, name, &HashSet::new()),
                    name.clone(),
                    SequenceKind::Identity,
                )),
                crate::analysis::facts::ColumnGeneration::Ordinary => None,
            },
            _ => None,
        };
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
                        crate::analysis::evidence::EvidenceScope::Chain,
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
        let mut cascade_generated_columns: HashSet<String> = HashSet::new();
        let mut cascade_view_roots: HashSet<ObjectId> = HashSet::new();
        if let AlterTableActionMutation::DropColumn { name, cascade, .. } = &alter.action {
            let resolved_table = self.local.graph.resolve_rename(&alter.id).clone();
            if self.baseline_relation_is_known(&resolved_table)
                && (!self.baseline_has_coverage(crate::db::cache::CatalogFamily::Dependencies)
                    || self.baseline_scoped_family_object(
                        &resolved_table,
                        crate::db::cache::CatalogFamily::Relations,
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
                        if columns.is_empty() {
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
        let rel_overlay = self.local.relations.get_mut(&alter.id);
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
                    generation: _,
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
                    if let Some(column) = rel.columns.iter_mut().find(|column| column.name == *name)
                    {
                        column.type_id = action_type_id.clone();
                    }

                    if let Some((sequence_id, column_name, _)) = &implicit_add
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
                }
                AlterTableActionMutation::DropNotNull { column } => {
                    rel.apply_column_action(&ColumnAction::DropNotNull {
                        name: column.clone(),
                    });
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
                    if let Some(ref c) = removed_constraint
                        && c.kind == crate::model::constraint::ConstraintKind::NotNull
                    {
                        self.snapshot_relation(&alter.id);
                        if let Some(RelationOverlay::Present(rel)) =
                            self.local.relations.get_mut(&alter.id)
                        {
                            if let Some(col) = rel.columns.iter_mut().find(|c| c.name == *name) {
                                col.is_nullable = true;
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
                    self.snapshot_graph();
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
                        .rename_foreign_key_constraint(&alter.id, old_name, new_name);
                }
                AlterTableActionMutation::AddCheckConstraint {
                    constraint_name,
                    columns,
                    columns_complete,
                    not_valid,
                } => {
                    let constraint_name = constraint_name.clone().unwrap_or_else(|| {
                        self.next_generated_constraint_name_avoiding(
                            &alter.id,
                            &alter.id.name,
                            None,
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
                    let backing_index = using_index
                        .as_ref()
                        .map(|index| ObjectId::new(index.schema.clone(), constraint_name.clone()));
                    if let Some(index) = using_index {
                        self.adopt_index_for_constraint(index, &alter.id, &constraint_name);
                    }
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name.clone(),
                            kind: ConstraintKind::Unique,
                            validated: true,
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
                    let backing_index = using_index
                        .as_ref()
                        .map(|index| ObjectId::new(index.schema.clone(), constraint_name.clone()));
                    if let Some(index) = using_index {
                        self.adopt_index_for_constraint(index, &alter.id, &constraint_name);
                    }
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name.clone(),
                            kind: ConstraintKind::PrimaryKey,
                            validated: true,
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
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name.clone(),
                            kind: ConstraintKind::Exclusion,
                            validated: true,
                            backing_index: None,
                        },
                    );
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
                AlterTableActionMutation::DetachPartition { child } => {
                    self.snapshot_graph();
                    self.local.graph.retain_edges(|e| {
                        !(matches!(e.kind, DependencyKind::PartitionOf)
                            && e.dependent == *child
                            && e.referenced == alter.id)
                    });
                }
                _ => {}
            }
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
        if let AlterTableActionMutation::RenameColumn { from, to } = &alter.action {
            self.snapshot_graph_full();
            self.local
                .graph
                .rename_column_dependencies(&alter.id, from, to);

            // Publication column lists are catalog identities, not merely
            // display text. PostgreSQL follows a renamed column in an
            // explicit publication list, so keep the modeled scope aligned.
            let publication_updates: Vec<(String, Vec<usize>)> = self
                .local
                .publications
                .iter()
                .filter_map(|(name, overlay)| {
                    let crate::model::replication::PublicationOverlay::Present(publication) =
                        overlay
                    else {
                        return None;
                    };
                    let indexes = match &publication.scope {
                        crate::analysis::facts::PublicationScope::Explicit(objects) => objects
                            .iter()
                            .enumerate()
                            .filter_map(|(index, object)| {
                                let crate::analysis::facts::PublicationObjectFact::Table {
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
                if let Some(crate::model::replication::PublicationOverlay::Present(publication)) =
                    self.local.publications.get_mut(&publication_name)
                    && let crate::analysis::facts::PublicationScope::Explicit(objects) =
                        &mut publication.scope
                {
                    for index in object_indexes {
                        if let Some(crate::analysis::facts::PublicationObjectFact::Table {
                            columns: Some(columns),
                            ..
                        }) = objects.get_mut(index)
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
        if let Some((sequence_id, column_name, kind)) = implicit_add {
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
            AlterTableActionMutation::DropColumn { .. } => {
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
        match self.relation_or_index_lookup(&rename.old_id) {
            RelationLookup::Present => {}
            _ if self.baseline_covers_family_object(
                &rename.old_id,
                crate::db::cache::CatalogFamily::Relations,
            ) || self.baseline_covers_family_object(
                &rename.old_id,
                crate::db::cache::CatalogFamily::Indexes,
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
                let crate::model::replication::PublicationOverlay::Present(publication) = overlay
                else {
                    return None;
                };
                let crate::analysis::facts::PublicationScope::Explicit(objects) =
                    &publication.scope
                else {
                    return None;
                };
                let indexes = objects
                    .iter()
                    .enumerate()
                    .filter_map(|(index, object)| {
                        let crate::analysis::facts::PublicationObjectFact::Table { name, .. } =
                            object
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
            self.local.graph.add_edge(DependencyEdge::new(
                old_index_id.clone(),
                new_index_id.clone(),
                DependencyKind::RenameTo,
            ));
        }
        let triggers_to_move: Vec<(ObjectId, crate::model::trigger::TriggerState)> = self
            .local
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
            if let Some(crate::model::replication::PublicationOverlay::Present(publication)) =
                self.local.publications.get_mut(&publication_name)
                && let crate::analysis::facts::PublicationScope::Explicit(objects) =
                    &mut publication.scope
            {
                for index in object_indexes {
                    let Some(crate::analysis::facts::PublicationObjectFact::Table { name, .. }) =
                        objects.get_mut(index)
                    else {
                        continue;
                    };
                    let name_quoted = name.name.quoted;
                    let schema_quoted = name.schema.as_ref().is_some_and(|schema| schema.quoted);
                    name.name = crate::ast::identifiers::Ident::new(
                        rename.new_id.name.clone(),
                        name_quoted,
                    );
                    if name.schema.is_some() || rename.old_id.schema != rename.new_id.schema {
                        name.schema = Some(crate::ast::identifiers::Ident::new(
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

    pub(super) fn apply_change_relation_owner(
        &mut self,
        id: &ObjectId,
        new_owner: &crate::analysis::facts::RoleFact,
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
}
