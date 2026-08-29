use super::{AnalysisState, Confidence, MutationResult, ObjectLookup, RelationOverlay};
use crate::analysis::graph::{DependencyEdge, DependencyKind};
use crate::analysis::mutations::{
    CreateIndex, CreateMaterializedView, CreateView, DropIndex, DropMaterializedViewMutation,
    DropViewMutation, RefreshMaterializedViewMutation,
};
use crate::ast::identifiers::ObjectId;
use crate::model::relation::{Persistence, RelationKind, RelationState};

type RelationLookup = ObjectLookup;
type IndexLookup = ObjectLookup;

impl AnalysisState {
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
        if self.relation_namespace_is_taken(&create.id) {
            let is_replaceable_view = self
                .relation_lookup(&create.id, |kind| *kind == RelationKind::View)
                == RelationLookup::Present;
            if !create.or_replace || !is_replaceable_view {
                return MutationResult::Conflict {
                    reason: format!("relation '{}' already exists", create.id),
                };
            }
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
                RelationKind::View,
                Persistence::Permanent,
                self.local.transactions.len(),
            )),
        );
        self.snapshot_graph();
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
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::Conflict {
                reason: format!("relation '{}' already exists", create.id),
            };
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
        self.snapshot_graph();
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
        _refresh: &RefreshMaterializedViewMutation,
    ) -> MutationResult {
        MutationResult::Applied
    }

    pub(super) fn apply_create_index(&mut self, create: &CreateIndex) -> MutationResult {
        if create.if_not_exists && self.index_lookup(&create.id) == IndexLookup::Present {
            return MutationResult::Skipped;
        }
        if self.relation_namespace_is_taken(&create.id) {
            return MutationResult::Conflict {
                reason: format!("relation '{}' already exists", create.id),
            };
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
        for id in &drop.ids {
            match self.relation_lookup(id, |kind| *kind == RelationKind::View) {
                RelationLookup::Present => present.push(id.clone()),
                RelationLookup::WrongKind => {
                    return MutationResult::Conflict {
                        reason: format!("'{}' is not a view", id),
                    };
                }
                _ if drop.if_exists => {}
                RelationLookup::AuthoritativelyAbsent => {
                    return MutationResult::Conflict {
                        reason: format!("view '{}' does not exist", id),
                    };
                }
                RelationLookup::Tombstone
                    if self.baseline_available && self.baseline_covers_object(id) =>
                {
                    return MutationResult::Conflict {
                        reason: format!("view '{}' does not exist", id),
                    };
                }
                RelationLookup::Tombstone | RelationLookup::Unknown => {
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                }
            }
        }
        if present.is_empty() {
            return MutationResult::Skipped;
        }
        for id in &present {
            self.snapshot_relation(id);
            self.local
                .relations
                .insert(id.clone(), RelationOverlay::Dropped);
        }
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|edge| {
            !(matches!(edge.kind, DependencyKind::ViewDependency { .. })
                && present.contains(&edge.dependent))
        });
        MutationResult::Applied
    }

    pub(super) fn apply_drop_materialized_view(
        &mut self,
        drop: &DropMaterializedViewMutation,
    ) -> MutationResult {
        let mut present = Vec::new();
        for id in &drop.ids {
            match self.relation_lookup(id, |kind| *kind == RelationKind::MaterializedView) {
                RelationLookup::Present => present.push(id.clone()),
                RelationLookup::WrongKind => {
                    return MutationResult::Conflict {
                        reason: format!("'{}' is not a materialized view", id),
                    };
                }
                _ if drop.if_exists => {}
                RelationLookup::AuthoritativelyAbsent => {
                    return MutationResult::Conflict {
                        reason: format!("materialized view '{}' does not exist", id),
                    };
                }
                RelationLookup::Tombstone
                    if self.baseline_available && self.baseline_covers_object(id) =>
                {
                    return MutationResult::Conflict {
                        reason: format!("materialized view '{}' does not exist", id),
                    };
                }
                RelationLookup::Tombstone | RelationLookup::Unknown => {
                    self.snapshot_confidence();
                    self.local.confidence = Confidence::Tainted;
                }
            }
        }
        if present.is_empty() {
            return MutationResult::Skipped;
        }
        for id in &present {
            self.snapshot_relation(id);
            self.local
                .relations
                .insert(id.clone(), RelationOverlay::Dropped);
        }
        self.snapshot_graph_full();
        self.local.graph.retain_edges(|edge| {
            !((matches!(edge.kind, DependencyKind::ViewDependency { .. })
                && present.contains(&edge.dependent))
                || (matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                    && present.contains(&edge.referenced)))
        });
        MutationResult::Applied
    }

    pub(super) fn apply_drop_index(&mut self, drop: &DropIndex) -> MutationResult {
        match self.index_lookup(&drop.id) {
            IndexLookup::Present => {}
            _ if drop.if_exists => return MutationResult::Skipped,
            IndexLookup::AuthoritativelyAbsent => {
                return MutationResult::Conflict {
                    reason: format!("index '{}' does not exist", drop.id),
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
        self.snapshot_graph();
        self.local.graph.retain_edges(|edge| {
            !(matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                && edge.dependent == drop.id)
        });
        MutationResult::Applied
    }
}
