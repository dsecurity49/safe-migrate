use super::{
    AnalysisState, CascadeResult, Confidence, MutationResult, ObjectLookup, RelationOverlay,
};
use crate::analysis::graph::{DependencyEdge, DependencyKind};
use crate::analysis::mutations::{
    CreateIndex, CreateMaterializedView, CreateView, DropIndex, DropMaterializedViewMutation,
    DropViewMutation, RefreshMaterializedViewMutation,
};
use crate::ast::identifiers::ObjectId;
use crate::model::relation::{Persistence, RelationKind, RelationState};
use std::collections::HashSet;

type RelationLookup = ObjectLookup;
type IndexLookup = ObjectLookup;

impl AnalysisState {
    fn validate_view_dependencies(
        &mut self,
        dependent: &ObjectId,
        dependencies: &[ObjectId],
    ) -> Result<(), MutationResult> {
        for dependency in dependencies {
            // Recursive views are represented by a self-reference in some
            // PostgreSQL catalog versions. It does not identify an external
            // object that must already exist.
            if dependency == dependent {
                continue;
            }
            self.ensure_relation_target(
                dependency,
                |_| true,
                format!("view dependency relation '{}' does not exist", dependency),
                format!("view dependency '{}' is not a relation", dependency),
            )?;
        }
        Ok(())
    }

    pub(crate) fn cascade_for_relations(&self, roots: &[ObjectId]) -> CascadeResult {
        let mut cascade = CascadeResult::default();
        for root in roots {
            let closure = self.get_cascade_closure(root);
            cascade.dropped_relations.extend(closure.dropped_relations);
            cascade.dropped_indexes.extend(closure.dropped_indexes);
            cascade
                .dropped_constraints
                .extend(closure.dropped_constraints);
        }
        cascade
    }

    fn remove_dropped_relation_edges(
        &mut self,
        dropped_relations: &HashSet<ObjectId>,
        dropped_indexes: &HashSet<ObjectId>,
    ) {
        self.snapshot_graph_full();
        let resolution_graph = self.local.graph.clone();
        self.local.graph.retain_edges(|edge| {
            let dependent = resolution_graph.resolve_rename(&edge.dependent);
            let referenced = resolution_graph.resolve_rename(&edge.referenced);
            if dropped_indexes.contains(dependent) {
                return false;
            }
            if dropped_relations.contains(dependent) {
                return false;
            }
            if dropped_relations.contains(referenced) {
                return false;
            }
            true
        });
    }

    fn has_external_view_dependents(&self, roots: &HashSet<ObjectId>) -> bool {
        self.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::ViewDependency { .. })
                && roots.contains(self.local.graph.resolve_rename(&edge.referenced))
                && !roots.contains(self.local.graph.resolve_rename(&edge.dependent))
        })
    }

    fn apply_drop_relation_family(
        &mut self,
        present: &[ObjectId],
        cascade: bool,
        kind_name: &str,
    ) -> MutationResult {
        let roots = present.iter().cloned().collect::<HashSet<_>>();
        if !cascade && self.has_external_view_dependents(&roots) {
            return MutationResult::Conflict {
                reason: format!(
                    "relation '{}' still has dependent views; use CASCADE",
                    present
                        .first()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| kind_name.to_string())
                ),
            };
        }

        let cascade_result = cascade.then(|| self.cascade_for_relations(present));
        if let Some(result) = &cascade_result
            && result
                .dropped_relations
                .iter()
                .any(|id| !self.relation_is_present(id))
        {
            // A scoped cache can expose a dependency edge for a relation whose
            // metadata was intentionally omitted. CASCADE will remove that
            // relation in PostgreSQL, but the simulator cannot reproduce its
            // full state, so the result is necessarily tainted.
            self.snapshot_confidence();
            self.local.confidence = Confidence::Tainted;
        }
        let all_dropped_relations = cascade_result
            .as_ref()
            .map(|result| result.dropped_relations.clone())
            .unwrap_or_else(|| roots.clone());
        let dropped_relations = all_dropped_relations
            .iter()
            .filter(|id| self.relation_is_present(id))
            .cloned()
            .collect::<HashSet<_>>();
        let dropped_indexes = cascade_result
            .as_ref()
            .map(|result| result.dropped_indexes.clone())
            .unwrap_or_default();
        let dropped_constraints = cascade_result
            .as_ref()
            .map(|result| result.dropped_constraints.clone())
            .unwrap_or_default();

        for id in &dropped_relations {
            self.snapshot_relation(id);
            self.local
                .relations
                .insert(id.clone(), RelationOverlay::Dropped);
        }
        let resolution_graph = self.local.graph.clone();
        let triggers_to_drop = self
            .local
            .triggers
            .iter()
            .filter_map(|(id, overlay)| {
                let crate::model::trigger::TriggerOverlay::Present(trigger) = overlay else {
                    return None;
                };
                dropped_relations
                    .contains(resolution_graph.resolve_rename(&trigger.table_id))
                    .then(|| id.clone())
            })
            .collect::<Vec<_>>();
        for trigger_id in triggers_to_drop {
            self.snapshot_trigger(&trigger_id);
            self.local
                .triggers
                .insert(trigger_id, crate::model::trigger::TriggerOverlay::Dropped);
        }
        // Even when a scoped cache omitted a dependent view, its dependency
        // edge is known and PostgreSQL CASCADE removes that edge. Use the full
        // closure for topology cleanup while only marking modeled overlays.
        self.remove_dropped_constraints(&all_dropped_relations, &dropped_constraints);
        self.remove_dropped_relation_edges(&all_dropped_relations, &dropped_indexes);
        MutationResult::Applied
    }

    fn index_lookup(&self, id: &ObjectId) -> IndexLookup {
        if self.local.graph.edges().iter().any(|edge| {
            matches!(edge.kind, DependencyKind::IndexOnRelation { .. }) && edge.dependent == *id
        }) {
            IndexLookup::Present
        } else if self.baseline_available && self.baseline_covers_object(id) {
            IndexLookup::AuthoritativelyAbsent
        } else {
            IndexLookup::Unknown
        }
    }

    pub(super) fn apply_create_view(&mut self, create: &CreateView) -> MutationResult {
        if let Err(result) = self.ensure_schema_target(&create.id.schema) {
            return result;
        }
        let existing_view = matches!(
            self.relation_lookup(&create.id, |kind| *kind == RelationKind::View),
            RelationLookup::Present
        );
        if self.relation_namespace_is_taken(&create.id) && (!create.or_replace || !existing_view) {
            return MutationResult::Conflict {
                reason: format!("relation '{}' already exists", create.id),
            };
        }
        if let Err(result) = self.validate_view_dependencies(&create.id, &create.depends_on) {
            return result;
        }
        let owner = self
            .local
            .relations
            .get(&create.id)
            .and_then(|overlay| match overlay {
                RelationOverlay::Present(relation) => Some(relation.owner.clone()),
                RelationOverlay::Dropped => None,
            })
            .unwrap_or_else(|| ObjectId::new("", &self.local.current_role));
        self.snapshot_relation(&create.id);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;
        let mut relation = if existing_view {
            match self.local.relations.get(&create.id) {
                Some(RelationOverlay::Present(existing)) => existing.clone(),
                _ => unreachable!("existing view lookup established presence"),
            }
        } else {
            RelationState::new(
                create.id.clone(),
                owner,
                generation,
                None,
                RelationKind::View,
                Persistence::Permanent,
                self.local.transactions.len(),
            )
        };
        // CREATE OR REPLACE VIEW keeps the relation identity, ownership,
        // privileges, triggers, and other relation metadata. Only the
        // generation records the replacement in the simulated state.
        relation.id = create.id.clone();
        relation.generation = generation;
        relation.kind = RelationKind::View;
        relation.persistence = Persistence::Permanent;
        self.local
            .relations
            .insert(create.id.clone(), RelationOverlay::Present(relation));
        self.snapshot_graph_full();
        if existing_view {
            self.local.graph.retain_edges(|edge| {
                !(matches!(edge.kind, DependencyKind::ViewDependency { .. })
                    && edge.dependent == create.id)
            });
        }
        for dependency in &create.depends_on {
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                dependency.clone(),
                DependencyKind::ViewDependency {
                    view_generation: generation,
                },
            ));
        }
        MutationResult::Applied
    }

    pub(super) fn apply_create_materialized_view(
        &mut self,
        create: &CreateMaterializedView,
    ) -> MutationResult {
        if let Err(result) = self.ensure_schema_target(&create.id.schema) {
            return result;
        }
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::Conflict {
                reason: format!("relation '{}' already exists", create.id),
            };
        }
        if let Err(result) = self.validate_view_dependencies(&create.id, &create.depends_on) {
            return result;
        }
        self.snapshot_relation(&create.id);
        self.snapshot_generation_counter();
        self.local.generation_counter += 1;
        let generation = self.local.generation_counter;
        self.local.relations.insert(
            create.id.clone(),
            RelationOverlay::Present(RelationState::new(
                create.id.clone(),
                ObjectId::new("", &self.local.current_role),
                generation,
                None,
                RelationKind::MaterializedView,
                Persistence::Permanent,
                self.local.transactions.len(),
            )),
        );
        self.snapshot_graph_full();
        for dependency in &create.depends_on {
            self.local.graph.add_edge(DependencyEdge::new(
                create.id.clone(),
                dependency.clone(),
                DependencyKind::ViewDependency {
                    view_generation: generation,
                },
            ));
        }
        MutationResult::Applied
    }

    pub(super) fn apply_refresh_materialized_view(
        &mut self,
        refresh: &RefreshMaterializedViewMutation,
    ) -> MutationResult {
        match self.relation_lookup(&refresh.id, |kind| *kind == RelationKind::MaterializedView) {
            RelationLookup::Present => MutationResult::Applied,
            RelationLookup::WrongKind => MutationResult::Conflict {
                reason: format!("'{}' is not a materialized view", refresh.id),
            },
            RelationLookup::AuthoritativelyAbsent | RelationLookup::Tombstone => {
                MutationResult::Conflict {
                    reason: format!("materialized view '{}' does not exist", refresh.id),
                }
            }
            RelationLookup::Unknown => {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
                MutationResult::Skipped
            }
        }
    }

    pub(super) fn apply_create_index(&mut self, create: &CreateIndex) -> MutationResult {
        if let Err(result) = self.ensure_schema_target(&create.id.schema) {
            return result;
        }
        if create.if_not_exists && self.index_lookup(&create.id) == IndexLookup::Present {
            return MutationResult::Skipped;
        }
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::Conflict {
                reason: format!("relation '{}' already exists", create.id),
            };
        }
        if let Err(result) = self.ensure_relation_target(
            &create.table,
            |kind| matches!(kind, RelationKind::Table | RelationKind::MaterializedView),
            format!("index target relation '{}' does not exist", create.table),
            format!("index target '{}' cannot be indexed", create.table),
        ) {
            return result;
        }
        self.snapshot_graph();
        self.local.graph.add_edge(DependencyEdge::new(
            create.id.clone(),
            create.table.clone(),
            DependencyKind::IndexOnRelation {
                using_method: create.using_method.clone(),
                has_predicate: create.has_predicate,
                is_concurrent: create.concurrently,
                is_unique: create.unique,
                eligibility_known: true,
            },
        ));
        MutationResult::Applied
    }

    pub(super) fn apply_drop_view(&mut self, drop: &DropViewMutation) -> MutationResult {
        let mut present = Vec::new();
        let mut unknown_target = false;
        for id in &drop.ids {
            match self.relation_lookup(id, |kind| *kind == RelationKind::View) {
                RelationLookup::Present => present.push(id.clone()),
                RelationLookup::WrongKind => {
                    return MutationResult::Conflict {
                        reason: format!("'{}' is not a view", id),
                    };
                }
                RelationLookup::AuthoritativelyAbsent if drop.if_exists => {}
                RelationLookup::AuthoritativelyAbsent => {
                    return MutationResult::Conflict {
                        reason: format!("view '{}' does not exist", id),
                    };
                }
                RelationLookup::Tombstone if drop.if_exists => {}
                RelationLookup::Tombstone => {
                    return MutationResult::Conflict {
                        reason: format!("view '{}' does not exist", id),
                    };
                }
                RelationLookup::Unknown => {
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                    unknown_target = true;
                }
            }
        }
        // PostgreSQL resolves all names in a multi-target DROP before
        // executing the statement.  Do not remove known targets when another
        // target is outside a scoped/incomplete baseline.
        if unknown_target {
            return MutationResult::Skipped;
        }
        if present.is_empty() {
            return MutationResult::Skipped;
        }
        self.apply_drop_relation_family(&present, drop.cascade, "view")
    }

    pub(super) fn apply_drop_materialized_view(
        &mut self,
        drop: &DropMaterializedViewMutation,
    ) -> MutationResult {
        let mut present = Vec::new();
        let mut unknown_target = false;
        for id in &drop.ids {
            match self.relation_lookup(id, |kind| *kind == RelationKind::MaterializedView) {
                RelationLookup::Present => present.push(id.clone()),
                RelationLookup::WrongKind => {
                    return MutationResult::Conflict {
                        reason: format!("'{}' is not a materialized view", id),
                    };
                }
                RelationLookup::AuthoritativelyAbsent if drop.if_exists => {}
                RelationLookup::AuthoritativelyAbsent => {
                    return MutationResult::Conflict {
                        reason: format!("materialized view '{}' does not exist", id),
                    };
                }
                RelationLookup::Tombstone if drop.if_exists => {}
                RelationLookup::Tombstone => {
                    return MutationResult::Conflict {
                        reason: format!("materialized view '{}' does not exist", id),
                    };
                }
                RelationLookup::Unknown => {
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                    unknown_target = true;
                }
            }
        }
        if unknown_target {
            return MutationResult::Skipped;
        }
        if present.is_empty() {
            return MutationResult::Skipped;
        }
        self.apply_drop_relation_family(&present, drop.cascade, "materialized view")
    }

    pub(super) fn apply_drop_index(&mut self, drop: &DropIndex) -> MutationResult {
        // PostgreSQL resolves every target before it applies a multi-index
        // DROP. Preflight the complete statement so a later invalid target
        // cannot leave an earlier index removed from simulated state.
        let mut targets = Vec::new();
        for id in &drop.ids {
            match self.index_lookup(id) {
                IndexLookup::Present => {
                    if !targets.contains(id) {
                        targets.push(id.clone());
                    }
                }
                IndexLookup::AuthoritativelyAbsent if drop.if_exists => {}
                IndexLookup::AuthoritativelyAbsent => {
                    return MutationResult::Conflict {
                        reason: format!("index '{}' does not exist", id),
                    };
                }
                IndexLookup::Unknown => {
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                    return MutationResult::Skipped;
                }
                IndexLookup::WrongKind | IndexLookup::Tombstone => {
                    unreachable!("indexes have no overlay kind or tombstone")
                }
            }
        }

        if targets.is_empty() {
            return MutationResult::Skipped;
        }

        for id in &targets {
            let Some(index_edge) = self.local.graph.edges().iter().find(|edge| {
                matches!(edge.kind, DependencyKind::IndexOnRelation { .. }) && edge.dependent == *id
            }) else {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
                return MutationResult::Skipped;
            };
            let referenced_table = self.local.graph.resolve_rename(&index_edge.referenced);
            let backs_constraint =
                self.local
                    .constraints
                    .iter()
                    .any(|((table, name), constraint)| {
                        name == &id.name
                            && self.local.graph.resolve_rename(table) == referenced_table
                            && matches!(
                                constraint.kind,
                                crate::model::constraint::ConstraintKind::PrimaryKey
                                    | crate::model::constraint::ConstraintKind::Unique
                            )
                    });
            if backs_constraint {
                return MutationResult::Conflict {
                    reason: format!(
                        "cannot drop index '{}' because a constraint requires it",
                        id
                    ),
                };
            }
            if matches!(
                index_edge.kind,
                DependencyKind::IndexOnRelation {
                    eligibility_known: false,
                    ..
                }
            ) {
                self.snapshot_confidence();
                self.local.confidence = Confidence::Tainted;
                return MutationResult::Skipped;
            }
        }
        self.snapshot_graph();
        self.local.graph.retain_edges(|edge| {
            !(matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                && targets.contains(&edge.dependent))
        });
        MutationResult::Applied
    }
}
