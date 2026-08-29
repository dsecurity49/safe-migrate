use super::{
    AnalysisState, CascadeResult, Confidence, MutationResult, ObjectLookup, RelationOverlay,
};
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
        } else if self.baseline_available && self.baseline_covers_object(id) {
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
        match self.relation_lookup(&drop_table.id, |kind| *kind == RelationKind::Table) {
            RelationLookup::Present => {}
            RelationLookup::WrongKind => {
                return MutationResult::Conflict {
                    reason: format!("'{}' is not a table", drop_table.id),
                };
            }
            _ if drop_table.if_exists => return MutationResult::Skipped,
            RelationLookup::AuthoritativelyAbsent => {
                return MutationResult::Conflict {
                    reason: format!("table '{}' does not exist", drop_table.id),
                };
            }
            RelationLookup::Tombstone
                if self.baseline_available && self.baseline_covers_object(&drop_table.id) =>
            {
                return MutationResult::Conflict {
                    reason: format!("table '{}' does not exist", drop_table.id),
                };
            }
            RelationLookup::Tombstone | RelationLookup::Unknown => {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
                return MutationResult::Skipped;
            }
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

        let resolved_drop = resolve(&drop_table.id);
        let mut dropped_relations = HashSet::from([resolved_drop.clone()]);

        if drop_table.cascade {
            let local_closure;
            let closure = match precomputed_cascade {
                Some(c) => c,
                None => {
                    local_closure = self.get_cascade_closure(&drop_table.id);
                    &local_closure
                }
            };
            dropped_relations = closure.dropped_relations.clone();

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
                matches!(e.kind, DependencyKind::ViewDependency { .. })
                    && resolve(&e.referenced) == resolved_drop
            });
            let has_fk_deps = self.local.graph.edges().iter().any(|e| {
                matches!(e.kind, DependencyKind::ForeignKey { .. })
                    && resolve(&e.referenced) == resolved_drop
                    && resolve(&e.dependent) != resolved_drop
            });
            let has_partition_deps = self.local.graph.edges().iter().any(|e| {
                matches!(e.kind, DependencyKind::PartitionOf)
                    && resolve(&e.referenced) == resolved_drop
            });

            if has_view_deps || has_fk_deps || has_partition_deps {
                return MutationResult::Conflict {
                    reason: format!(
                        "relation '{}' still has dependent objects; use CASCADE",
                        drop_table.id
                    ),
                };
            }

            self.snapshot_relation(&drop_table.id);
            self.local
                .relations
                .insert(drop_table.id.clone(), RelationOverlay::Dropped);

            self.snapshot_graph_full();
            self.local.graph.retain_edges(|e| {
                !(matches!(e.kind, DependencyKind::SequenceOwnedBy { .. })
                    && resolve(&e.referenced) == resolved_drop)
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

        let constraints_to_drop: Vec<(ObjectId, String)> = self
            .local
            .constraints
            .keys()
            .filter(|(table_id, _)| dropped_relations.contains(&resolve(table_id)))
            .cloned()
            .collect();
        for (table_id, name) in constraints_to_drop {
            self.snapshot_constraint(&table_id, &name);
            self.local.constraints.remove(&(table_id, name));
        }

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

        self.snapshot_graph_full();
        self.local.graph.retain_edges(|e| {
            if let DependencyKind::PartitionOf = e.kind {
                resolve(&e.referenced) != resolved_drop && resolve(&e.dependent) != resolved_drop
            } else {
                true
            }
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
        if create.if_not_exists && self.relation_namespace_is_taken(&create.id) {
            return MutationResult::Skipped;
        }
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::Conflict {
                reason: format!("relation '{}' already exists", create.id),
            };
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

        // Store partition strategy information
        rel_state.partition_type = create
            .partition_by
            .as_ref()
            .and_then(|pb| pb.split_whitespace().nth(2).map(|s| s.to_uppercase()))
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
        if let Some(explicit_name) = primary_key_name {
            let name = explicit_name.unwrap_or_else(|| {
                self.next_generated_constraint_name(&create.id, &create.id.name, None, "pkey")
            });
            self.snapshot_constraint(&create.id, &name);
            self.local.constraints.insert(
                (create.id.clone(), name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name,
                    kind: ConstraintKind::PrimaryKey,
                    validated: true,
                },
            );
        }

        let unique_constraints = create
            .columns
            .iter()
            .filter(|column| column.is_unique)
            .map(|column| {
                (
                    column.unique_constraint_name.as_ref(),
                    vec![column.name.as_str()],
                )
            })
            .chain(create.table_constraints.iter().filter_map(|constraint| {
                if let TableConstraintFact::Unique {
                    constraint_name,
                    columns,
                } = constraint
                {
                    Some((
                        constraint_name.as_ref(),
                        columns.iter().map(String::as_str).collect(),
                    ))
                } else {
                    None
                }
            }))
            .collect::<Vec<_>>();
        for (explicit_name, columns) in unique_constraints {
            let name = explicit_name.cloned().unwrap_or_else(|| {
                self.next_generated_constraint_name(
                    &create.id,
                    &create.id.name,
                    Some(&columns.join("_")),
                    "key",
                )
            });
            self.snapshot_constraint(&create.id, &name);
            self.local.constraints.insert(
                (create.id.clone(), name.clone()),
                ConstraintState {
                    table_id: create.id.clone(),
                    name,
                    kind: ConstraintKind::Unique,
                    validated: true,
                },
            );
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

        for fk in &create.foreign_keys {
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                fk.to_table.clone(),
                DependencyKind::ForeignKey {
                    constraint_name: fk.constraint_name.clone(),
                    from_columns: fk.from_columns.clone(),
                    to_columns: fk.to_columns.clone(),
                    from_generation: generation,
                },
            ));
        }
        MutationResult::Applied
    }

    pub(super) fn apply_alter_table(&mut self, alter: &AlterTable) -> MutationResult {
        if self.relation_lookup(&alter.id, |kind| *kind == RelationKind::Table)
            == ObjectLookup::WrongKind
        {
            return MutationResult::Conflict {
                reason: format!("object '{}' is not a table", alter.id),
            };
        }

        if let AlterTableActionMutation::OwnerTo { new_owner } = &alter.action {
            let Some((owner, known)) = self.role_fact_identity(new_owner) else {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
                return MutationResult::Skipped;
            };
            if !known {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
            }
            self.snapshot_relation(&alter.id);
            return match self.local.relations.get_mut(&alter.id) {
                Some(RelationOverlay::Present(relation)) => {
                    relation.owner = ObjectId::new("", owner);
                    MutationResult::Applied
                }
                _ => MutationResult::Conflict {
                    reason: format!("relation '{}' does not exist", alter.id),
                },
            };
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

        if let AlterTableActionMutation::AddForeignKey {
            to_table,
            from_columns,
            to_columns,
            ..
        } = &alter.action
        {
            if let Some(RelationOverlay::Present(child)) = self.local.relations.get(&alter.id)
                && let Some(column) = from_columns.iter().find(|column| !child.has_column(column))
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key column '{}' does not exist on relation '{}'",
                        column, alter.id
                    ),
                };
            }

            let Some(RelationOverlay::Present(parent)) = self.local.relations.get(to_table) else {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key references relation '{}' which does not exist",
                        to_table
                    ),
                };
            };
            if let Some(column) = to_columns.iter().find(|column| !parent.has_column(column)) {
                return MutationResult::Conflict {
                    reason: format!(
                        "foreign key references column '{}.{}' which does not exist",
                        to_table, column
                    ),
                };
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
            let Some(edge) = self.local.graph.edges().iter().find(|edge| {
                matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                    && edge.dependent == *index
            }) else {
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
                has_predicate,
                is_unique,
                eligibility_known,
                ..
            } = &edge.kind
                && *eligibility_known
                && (!is_unique || *has_predicate)
            {
                return MutationResult::Conflict {
                    reason: format!(
                        "constraint index '{}' must be unique and non-partial",
                        index
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
                AlterTableActionMutation::DropColumn { name, if_exists } => {
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
                    if !rel.has_column(column) {
                        self.local.confidence = Confidence::Tainted;
                    }
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
                    if !rel.has_column(column) {
                        self.local.confidence = Confidence::Tainted;
                    }
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
                        format!("{}_{}_fkey", alter.id.name, from_columns.join("_"))
                    });
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name.clone(),
                            kind: ConstraintKind::ForeignKey,
                            validated: !not_valid,
                        },
                    );
                    self.snapshot_graph();
                    self.local.graph.add_edge(DependencyEdge::new(
                        alter.id.clone(),
                        to_table.clone(),
                        DependencyKind::ForeignKey {
                            constraint_name: Some(constraint_name),
                            from_columns: from_columns.clone(),
                            to_columns: to_columns.clone(),
                            from_generation: generation,
                        },
                    ));
                }
                AlterTableActionMutation::DropConstraint { name } => {
                    self.snapshot_constraint(&alter.id, name);
                    self.local
                        .constraints
                        .remove(&(alter.id.clone(), name.clone()));
                    self.snapshot_graph();
                    self.local.graph.retain_edges(|e| {
                        if let DependencyKind::ForeignKey {
                            constraint_name, ..
                        } = &e.kind
                        {
                            !(e.dependent == alter.id && constraint_name.as_ref() == Some(name))
                        } else {
                            true
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
                    self.snapshot_graph_full();
                    self.local.graph.mutate_edges(|edges| {
                        for edge in edges {
                            if edge.dependent == alter.id
                                && let DependencyKind::ForeignKey {
                                    constraint_name, ..
                                } = &mut edge.kind
                                && constraint_name.as_deref() == Some(old_name)
                            {
                                *constraint_name = Some(new_name.clone());
                            }
                        }
                    });
                }
                AlterTableActionMutation::AddCheckConstraint {
                    constraint_name,
                    not_valid,
                } => {
                    let constraint_name = constraint_name
                        .clone()
                        .unwrap_or_else(|| format!("{}_check", alter.id.name));
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name,
                            kind: ConstraintKind::Check,
                            validated: !not_valid,
                        },
                    );
                }
                AlterTableActionMutation::AddUniqueConstraint {
                    constraint_name,
                    using_index,
                } => {
                    let constraint_name = constraint_name
                        .clone()
                        .or_else(|| using_index.as_ref().map(|index| index.name.clone()))
                        .unwrap_or_else(|| format!("{}_key", alter.id.name));
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name,
                            kind: ConstraintKind::Unique,
                            validated: true,
                        },
                    );
                }
                AlterTableActionMutation::AddPrimaryKeyConstraint {
                    constraint_name,
                    using_index,
                } => {
                    let constraint_name = constraint_name
                        .clone()
                        .or_else(|| using_index.as_ref().map(|index| index.name.clone()))
                        .unwrap_or_else(|| format!("{}_pkey", alter.id.name));
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name,
                            kind: ConstraintKind::PrimaryKey,
                            validated: true,
                        },
                    );
                }
                AlterTableActionMutation::AddExcludeConstraint { constraint_name } => {
                    let constraint_name = constraint_name
                        .clone()
                        .unwrap_or_else(|| format!("{}_excl", alter.id.name));
                    self.snapshot_constraint(&alter.id, &constraint_name);
                    self.local.constraints.insert(
                        (alter.id.clone(), constraint_name.clone()),
                        ConstraintState {
                            table_id: alter.id.clone(),
                            name: constraint_name,
                            kind: ConstraintKind::Exclusion,
                            validated: true,
                        },
                    );
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
                }
                AlterTableActionMutation::AttachPartition { child, .. } => {
                    // Reject attachments that would make partition ancestry cyclic.
                    if self.local.graph.check_partition_cycle(&alter.id, child) {
                        self.snapshot_confidence();
                        self.local.confidence = Confidence::Tainted;
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
            AlterTableActionMutation::RenameColumn { to, .. } => {
                for sequence_id in owned_sequences_for_column {
                    self.snapshot_sequence(&sequence_id);
                    if let Some(SequenceOverlay::Present(sequence)) =
                        self.local.sequences.get_mut(&sequence_id)
                        && let Some((_, column)) = &mut sequence.owned_by
                    {
                        *column = to.clone();
                    }
                    self.snapshot_graph_full();
                    self.local.graph.mutate_edges(|edges| {
                        for edge in edges {
                            if edge.dependent == sequence_id
                                && let DependencyKind::SequenceOwnedBy { column } = &mut edge.kind
                            {
                                *column = to.clone();
                            }
                        }
                    });
                }
            }
            _ => {}
        }
        MutationResult::Applied
    }

    pub(super) fn apply_rename_relation(&mut self, rename: &Rename) -> MutationResult {
        let renames_relation = self.relation_is_present(&rename.old_id);
        let renames_index = self.index_is_present(&rename.old_id);
        match self.relation_or_index_lookup(&rename.old_id) {
            RelationLookup::Present => {}
            _ if self.baseline_covers_object(&rename.old_id) => {
                return MutationResult::Conflict {
                    reason: format!("relation '{}' does not exist", rename.old_id),
                };
            }
            RelationLookup::Tombstone
            | RelationLookup::AuthoritativelyAbsent
            | RelationLookup::Unknown => {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
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
            self.snapshot_confidence();
            self.local.confidence = Confidence::Tainted;
            return MutationResult::Skipped;
        }

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
                .propagate_rename(&old_trigger_id, &new_trigger_id);
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
        self.local
            .graph
            .propagate_rename(&rename.old_id, &rename.new_id);

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

        MutationResult::Applied
    }

    pub(super) fn apply_change_relation_owner(
        &mut self,
        id: &ObjectId,
        new_owner: &crate::analysis::facts::RoleFact,
    ) -> MutationResult {
        let Some((owner, known)) = self.role_fact_identity(new_owner) else {
            self.snapshot_confidence();
            self.local.confidence = Confidence::Tainted;
            return MutationResult::Skipped;
        };
        if !known {
            self.snapshot_confidence();
            self.local.confidence = Confidence::Tainted;
        }
        match self.relation_lookup(id, |_| true) {
            RelationLookup::Present => {
                self.snapshot_relation(id);
                let Some(RelationOverlay::Present(relation)) = self.local.relations.get_mut(id)
                else {
                    unreachable!("relation lookup established presence")
                };
                relation.owner = ObjectId::new("", owner);
                MutationResult::Applied
            }
            RelationLookup::WrongKind => {
                unreachable!("all present relation kinds accept owner changes")
            }
            RelationLookup::Tombstone
            | RelationLookup::AuthoritativelyAbsent
            | RelationLookup::Unknown => MutationResult::Conflict {
                reason: format!("relation '{}' does not exist", id),
            },
        }
    }
}
