use super::{AnalysisState, MutationResult, ObjectLookup, RelationOverlay};
use crate::analysis::graph::{DependencyEdge, DependencyKind};
use crate::analysis::mutations::{
    CreatePolicyMutation, CreateTriggerMutation, DropPolicyMutation, DropTriggerMutation,
    RenameTriggerMutation,
};
use crate::ast::identifiers::ObjectId;
use crate::model::trigger::{TriggerEnableMode, TriggerOverlay, TriggerState};

type TriggerLookup = ObjectLookup;

impl AnalysisState {
    fn trigger_lookup(&self, id: &ObjectId) -> TriggerLookup {
        match self.local.triggers.get(id) {
            Some(TriggerOverlay::Present(_)) => TriggerLookup::Present,
            Some(TriggerOverlay::Dropped) => TriggerLookup::Tombstone,
            None if self.baseline_available && self.baseline_covers_object(id) => {
                TriggerLookup::AuthoritativelyAbsent
            }
            None => TriggerLookup::Unknown,
        }
    }

    pub(super) fn apply_create_policy(
        &mut self,
        create_policy: &CreatePolicyMutation,
    ) -> MutationResult {
        self.snapshot_relation(&create_policy.table);
        if let Some(RelationOverlay::Present(rel)) =
            self.local.relations.get_mut(&create_policy.table)
        {
            if rel.policies.contains(&create_policy.name) {
                return MutationResult::Conflict {
                    reason: format!(
                        "policy '{}' already exists on relation '{}'",
                        create_policy.name, create_policy.table
                    ),
                };
            }
            rel.policies.insert(create_policy.name.clone());
        } else {
            return MutationResult::Conflict {
                reason: format!("relation '{}' does not exist", create_policy.table),
            };
        }
        MutationResult::Applied
    }

    pub(super) fn apply_drop_policy(&mut self, drop_policy: &DropPolicyMutation) -> MutationResult {
        self.snapshot_relation(&drop_policy.table);
        if let Some(RelationOverlay::Present(rel)) =
            self.local.relations.get_mut(&drop_policy.table)
        {
            if !rel.policies.contains(&drop_policy.name) {
                return if drop_policy.if_exists {
                    MutationResult::Skipped
                } else {
                    MutationResult::Conflict {
                        reason: format!(
                            "policy '{}' does not exist on relation '{}'",
                            drop_policy.name, drop_policy.table
                        ),
                    }
                };
            }
            rel.policies.remove(&drop_policy.name);
        } else {
            return MutationResult::Conflict {
                reason: format!("relation '{}' does not exist", drop_policy.table),
            };
        }
        MutationResult::Applied
    }

    pub(super) fn apply_create_trigger(
        &mut self,
        create_trigger: &CreateTriggerMutation,
    ) -> MutationResult {
        let trigger_id = Self::trigger_key(&create_trigger.table, &create_trigger.name);
        if self.trigger_lookup(&trigger_id) == TriggerLookup::Present {
            return MutationResult::Conflict {
                reason: format!(
                    "trigger '{}' already exists on relation '{}'",
                    create_trigger.name, create_trigger.table
                ),
            };
        }
        self.snapshot_trigger(&trigger_id);
        self.local.triggers.insert(
            trigger_id.clone(),
            TriggerOverlay::Present(TriggerState {
                name: create_trigger.name.clone(),
                id: trigger_id.clone(),
                table_id: create_trigger.table.clone(),
                enabled_mode: TriggerEnableMode::Origin,
                generation: self.local.generation_counter,
            }),
        );
        self.snapshot_relation(&create_trigger.table);
        if let Some(RelationOverlay::Present(rel)) =
            self.local.relations.get_mut(&create_trigger.table)
        {
            rel.triggers.insert(create_trigger.name.clone());
        }
        self.snapshot_graph_full();
        self.local.graph.add_edge(DependencyEdge::new(
            trigger_id.clone(),
            create_trigger.table.clone(),
            DependencyKind::TriggerOnTable {
                trigger_id: trigger_id.clone(),
                function_id: create_trigger.function_id.clone(),
            },
        ));
        MutationResult::Applied
    }

    pub(super) fn apply_drop_trigger(
        &mut self,
        drop_trigger: &DropTriggerMutation,
    ) -> MutationResult {
        let trigger_id = Self::trigger_key(&drop_trigger.table, &drop_trigger.name);
        if self.trigger_lookup(&trigger_id) != TriggerLookup::Present {
            return if drop_trigger.if_exists {
                MutationResult::Skipped
            } else {
                MutationResult::Conflict {
                    reason: format!(
                        "trigger '{}' does not exist on relation '{}'",
                        drop_trigger.name, drop_trigger.table
                    ),
                }
            };
        }
        self.snapshot_trigger(&trigger_id);
        self.local
            .triggers
            .insert(trigger_id.clone(), TriggerOverlay::Dropped);
        self.snapshot_relation(&drop_trigger.table);
        if let Some(RelationOverlay::Present(rel)) =
            self.local.relations.get_mut(&drop_trigger.table)
        {
            rel.triggers.remove(&drop_trigger.name);
        }
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|edge| {
            !(matches!(edge.kind, DependencyKind::TriggerOnTable { .. })
                && edge.dependent == trigger_id)
        });
        MutationResult::Applied
    }

    pub(super) fn apply_rename_trigger(
        &mut self,
        rename_trigger: &RenameTriggerMutation,
    ) -> MutationResult {
        let old_id = Self::trigger_key(&rename_trigger.table, &rename_trigger.name);
        let new_id = Self::trigger_key(&rename_trigger.table, &rename_trigger.new_name);
        let Some(TriggerOverlay::Present(mut trigger)) = self.local.triggers.get(&old_id).cloned()
        else {
            return MutationResult::Conflict {
                reason: format!(
                    "trigger '{}' does not exist on relation '{}'",
                    rename_trigger.name, rename_trigger.table
                ),
            };
        };
        if old_id != new_id && self.trigger_lookup(&new_id) == TriggerLookup::Present {
            return MutationResult::Conflict {
                reason: format!(
                    "trigger '{}' already exists on relation '{}'",
                    rename_trigger.new_name, rename_trigger.table
                ),
            };
        }
        self.snapshot_trigger(&old_id);
        self.snapshot_trigger(&new_id);
        self.snapshot_relation(&rename_trigger.table);
        self.snapshot_graph_full();
        self.local.triggers.remove(&old_id);
        trigger.id = new_id.clone();
        trigger.name = rename_trigger.new_name.clone();
        self.local
            .triggers
            .insert(new_id.clone(), TriggerOverlay::Present(trigger));
        if let Some(RelationOverlay::Present(relation)) =
            self.local.relations.get_mut(&rename_trigger.table)
        {
            relation.triggers.remove(&rename_trigger.name);
            relation.triggers.insert(rename_trigger.new_name.clone());
        }
        self.local.graph.propagate_rename(&old_id, &new_id);
        self.local.graph.add_edge(DependencyEdge::new(
            old_id,
            new_id,
            DependencyKind::RenameTo,
        ));
        MutationResult::Applied
    }
}
