use super::{AnalysisState, Confidence, MutationResult, ObjectLookup, RelationOverlay};
use crate::analysis::graph::{DependencyEdge, DependencyKind};
use crate::analysis::mutations::{
    AlterSequenceActionMutation, AlterSequenceMutation, CreateSequenceMutation,
    DropSequenceMutation,
};
use crate::ast::identifiers::ObjectId;
use crate::model::sequence::{SequenceKind, SequenceOverlay, SequenceState};

type SequenceLookup = ObjectLookup;

impl AnalysisState {
    fn sequence_lookup(&self, id: &ObjectId) -> SequenceLookup {
        match self.local.sequences.get(id) {
            Some(SequenceOverlay::Present(_)) => SequenceLookup::Present,
            Some(SequenceOverlay::Dropped) => SequenceLookup::Tombstone,
            None if self.baseline_available && self.baseline_covers_object(id) => {
                SequenceLookup::AuthoritativelyAbsent
            }
            None => SequenceLookup::Unknown,
        }
    }

    pub(super) fn apply_create_sequence(
        &mut self,
        create: &CreateSequenceMutation,
    ) -> MutationResult {
        if create.if_not_exists && self.relation_namespace_is_taken(&create.id) {
            return MutationResult::Skipped;
        }
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::Conflict {
                reason: format!("relation '{}' already exists", create.id),
            };
        }
        if let Some((table_id, column)) = &create.owned_by {
            if table_id.schema != create.id.schema {
                return MutationResult::Conflict {
                    reason: "sequence must be in the same schema as its owning table".to_string(),
                };
            }
            match self.local.relations.get(table_id) {
                Some(RelationOverlay::Present(table)) => {
                    if !table.has_column(column) {
                        return MutationResult::Conflict {
                            reason: format!("column '{}.{}' does not exist", table_id, column),
                        };
                    }
                    if self.local.current_role_known && table.owner.name != self.local.current_role
                    {
                        return MutationResult::Conflict {
                            reason: "sequence and table must have the same owner".to_string(),
                        };
                    }
                }
                _ if self.baseline_covers_object(table_id) && self.baseline_available => {
                    return MutationResult::Conflict {
                        reason: format!("relation '{}' does not exist", table_id),
                    };
                }
                _ => {
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                }
            }
        }
        self.snapshot_sequence(&create.id);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;
        self.local.sequences.insert(
            create.id.clone(),
            SequenceOverlay::Present(SequenceState {
                id: create.id.clone(),
                owner: ObjectId::new("", self.local.current_role.clone()),
                owned_by: create.owned_by.clone(),
                kind: if create.owned_by.is_some() {
                    SequenceKind::Owned
                } else {
                    SequenceKind::Standalone
                },
                generation,
            }),
        );
        if let Some((table_id, column)) = &create.owned_by {
            self.snapshot_graph();
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                table_id.clone(),
                DependencyKind::SequenceOwnedBy {
                    column: column.clone(),
                },
            ));
        }
        MutationResult::Applied
    }

    pub(super) fn apply_alter_sequence(&mut self, alter: &AlterSequenceMutation) -> MutationResult {
        match self.sequence_lookup(&alter.id) {
            SequenceLookup::Present => {}
            _ if alter.if_exists => return MutationResult::Skipped,
            SequenceLookup::AuthoritativelyAbsent => {
                return MutationResult::Conflict {
                    reason: format!("sequence '{}' does not exist", alter.id),
                };
            }
            SequenceLookup::Tombstone
                if self.baseline_available && self.baseline_covers_object(&alter.id) =>
            {
                return MutationResult::Conflict {
                    reason: format!("sequence '{}' does not exist", alter.id),
                };
            }
            SequenceLookup::Tombstone | SequenceLookup::Unknown => {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
                return MutationResult::Skipped;
            }
            SequenceLookup::WrongKind => unreachable!("sequence lookup has no kind predicate"),
        }
        let current = match self.local.sequences.get(&alter.id) {
            Some(SequenceOverlay::Present(sequence)) => sequence.clone(),
            _ => unreachable!("presence checked above"),
        };
        match &alter.action {
            AlterSequenceActionMutation::OwnedBy(owned_by) => {
                if current.kind == SequenceKind::Identity {
                    return MutationResult::Conflict {
                        reason: "cannot change ownership of an identity sequence".to_string(),
                    };
                }
                if let Some((table_id, column)) = owned_by {
                    if table_id.schema != alter.id.schema {
                        return MutationResult::Conflict {
                            reason: "sequence must be in the same schema as its owning table"
                                .to_string(),
                        };
                    }
                    let Some(RelationOverlay::Present(table)) = self.local.relations.get(table_id)
                    else {
                        return MutationResult::Conflict {
                            reason: format!("relation '{}' does not exist", table_id),
                        };
                    };
                    if !table.has_column(column) {
                        return MutationResult::Conflict {
                            reason: format!("column '{}.{}' does not exist", table_id, column),
                        };
                    }
                    if table.owner != current.owner {
                        return MutationResult::Conflict {
                            reason: "sequence and table must have the same owner".to_string(),
                        };
                    }
                }
                self.snapshot_sequence(&alter.id);
                self.snapshot_graph();
                self.local.graph.retain_edges(|edge| {
                    !(matches!(edge.kind, DependencyKind::SequenceOwnedBy { .. })
                        && edge.dependent == alter.id)
                });
                if let Some(SequenceOverlay::Present(sequence)) =
                    self.local.sequences.get_mut(&alter.id)
                {
                    sequence.owned_by = owned_by.clone();
                    sequence.kind = if owned_by.is_some() {
                        SequenceKind::Owned
                    } else {
                        SequenceKind::Standalone
                    };
                }
                if let Some((table_id, column)) = owned_by {
                    self.local.graph.add_edge(DependencyEdge::new(
                        alter.id.clone(),
                        table_id.clone(),
                        DependencyKind::SequenceOwnedBy {
                            column: column.clone(),
                        },
                    ));
                }
                MutationResult::Applied
            }
            AlterSequenceActionMutation::OwnerTo(owner) => {
                if current.kind == SequenceKind::Identity {
                    return MutationResult::Conflict {
                        reason: "cannot alter an identity sequence independently".to_string(),
                    };
                }
                let Some((owner_name, known)) = self.role_fact_identity(owner) else {
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Skipped;
                };
                if known && self.local.roles_known && self.present_role(&owner_name).is_none() {
                    return MutationResult::Conflict {
                        reason: format!("role '{}' does not exist", owner_name),
                    };
                }
                if let Some((table_id, _)) = &current.owned_by
                    && let Some(RelationOverlay::Present(table)) =
                        self.local.relations.get(table_id)
                    && table.owner.name != owner_name
                {
                    return MutationResult::Conflict {
                        reason: "sequence and table must have the same owner".to_string(),
                    };
                }
                self.snapshot_sequence(&alter.id);
                if let Some(SequenceOverlay::Present(sequence)) =
                    self.local.sequences.get_mut(&alter.id)
                {
                    sequence.owner = ObjectId::new("", owner_name);
                }
                MutationResult::Applied
            }
            AlterSequenceActionMutation::RenameTo(new_id)
            | AlterSequenceActionMutation::SetSchema(new_id) => {
                if current.kind == SequenceKind::Identity {
                    return MutationResult::Conflict {
                        reason: "cannot alter an identity sequence independently".to_string(),
                    };
                }
                if self.relation_namespace_is_taken(new_id) {
                    return MutationResult::Conflict {
                        reason: format!("relation '{}' already exists", new_id),
                    };
                }
                if let Some((table_id, _)) = &current.owned_by
                    && table_id.schema != new_id.schema
                {
                    return MutationResult::Conflict {
                        reason: "sequence must be in the same schema as its owning table"
                            .to_string(),
                    };
                }
                self.snapshot_namespace();
                let mut moved = current;
                moved.id = new_id.clone();
                self.local.sequences.remove(&alter.id);
                self.local
                    .sequences
                    .insert(new_id.clone(), SequenceOverlay::Present(moved));
                self.local.graph.propagate_rename(&alter.id, new_id);
                self.local.graph.add_edge(DependencyEdge::new(
                    alter.id.clone(),
                    new_id.clone(),
                    DependencyKind::RenameTo,
                ));
                if self.baseline_sequences.remove(&alter.id) {
                    self.baseline_sequences.insert(new_id.clone());
                }
                MutationResult::Applied
            }
            AlterSequenceActionMutation::Other => MutationResult::Applied,
        }
    }

    pub(super) fn apply_drop_sequence(&mut self, drop: &DropSequenceMutation) -> MutationResult {
        if !drop.if_exists {
            for id in &drop.ids {
                match self.sequence_lookup(id) {
                    SequenceLookup::AuthoritativelyAbsent => {
                        return MutationResult::Conflict {
                            reason: format!("sequence '{}' does not exist", id),
                        };
                    }
                    SequenceLookup::Tombstone
                        if self.baseline_available && self.baseline_covers_object(id) =>
                    {
                        return MutationResult::Conflict {
                            reason: format!("sequence '{}' does not exist", id),
                        };
                    }
                    SequenceLookup::Tombstone | SequenceLookup::Unknown => {
                        self.snapshot_confidence();
                        self.local.confidence = Confidence::Tainted;
                    }
                    SequenceLookup::Present => continue,
                    SequenceLookup::WrongKind => {
                        unreachable!("sequence lookup has no kind predicate")
                    }
                }
            }
        }
        let present: Vec<ObjectId> = drop
            .ids
            .iter()
            .filter(|id| self.sequence_is_present(id))
            .cloned()
            .collect();
        if present.is_empty() {
            return MutationResult::Skipped;
        }
        for id in &present {
            let Some(SequenceOverlay::Present(sequence)) = self.local.sequences.get(id) else {
                continue;
            };
            if sequence.kind == SequenceKind::Identity {
                return MutationResult::Conflict {
                    reason: format!("cannot drop identity sequence '{}' independently", id),
                };
            }
            if sequence.kind == SequenceKind::SerialLike && !drop.cascade {
                return MutationResult::Conflict {
                    reason: format!("sequence '{}' still has dependent defaults", id),
                };
            }
        }
        if drop.cascade {
            let serial_owners: Vec<(ObjectId, String)> = present
                .iter()
                .filter_map(|id| match self.local.sequences.get(id) {
                    Some(SequenceOverlay::Present(sequence))
                        if sequence.kind == SequenceKind::SerialLike =>
                    {
                        sequence.owned_by.clone()
                    }
                    _ => None,
                })
                .collect();
            for (table_id, column) in serial_owners {
                self.snapshot_relation(&table_id);
                if let Some(RelationOverlay::Present(table)) =
                    self.local.relations.get_mut(&table_id)
                    && let Some(column) = table.columns.iter_mut().find(|item| item.name == column)
                {
                    column.default = None;
                    column.default_expr_text = None;
                }
            }
        }
        for id in &present {
            self.snapshot_sequence(id);
            self.local
                .sequences
                .insert(id.clone(), SequenceOverlay::Dropped);
        }
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|edge| {
            !(matches!(edge.kind, DependencyKind::SequenceOwnedBy { .. })
                && present.contains(&edge.dependent))
        });
        MutationResult::Applied
    }
}
