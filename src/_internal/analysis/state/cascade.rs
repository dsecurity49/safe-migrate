use super::*;

impl AnalysisState {
    pub(crate) fn get_cascade_closure(&self, target_oid: &ObjectId) -> CascadeResult {
        let mut result = CascadeResult::default();
        let mut visited = HashSet::new();
        self.walk_cascade(target_oid, &mut visited, &mut result);
        result
    }

    /// Dependency edges that carry an object generation are only valid while
    /// their dependent relation is the same incarnation that created the edge.
    /// A drop/recreate sequence must not inherit view/FK metadata from the
    /// previous incarnation. Baseline rows use generation zero and are
    /// validated the same way. An absent overlay is deliberately treated as
    /// unknown rather than stale so scoped-cache omissions remain conservative
    /// and can still produce the existing catalog-coverage evidence.
    pub(super) fn dependency_edge_is_current(&self, edge: &DependencyEdge) -> bool {
        let (generation, dependent) = match &edge.kind {
            DependencyKind::ForeignKey {
                from_generation, ..
            } => (*from_generation, &edge.dependent),
            DependencyKind::ViewDependency {
                view_generation, ..
            } => (*view_generation, &edge.dependent),
            DependencyKind::TriggerOnTable {
                trigger_generation,
                trigger_id,
                ..
            } => (*trigger_generation, trigger_id),
            _ => return true,
        };
        let resolved_dependent = self.local.graph.resolve_rename(dependent);
        match &edge.kind {
            DependencyKind::TriggerOnTable { .. } => {
                match self.local.triggers.get(resolved_dependent) {
                    Some(TriggerOverlay::Present(trigger)) => trigger.generation == generation,
                    Some(TriggerOverlay::Dropped) => false,
                    None => true,
                }
            }
            _ => match self.local.relations.get(resolved_dependent) {
                Some(RelationOverlay::Present(relation)) => relation.generation == generation,
                Some(RelationOverlay::Dropped) => false,
                None => true,
            },
        }
    }

    pub(super) fn walk_cascade(
        &self,
        current: &ObjectId,
        visited: &mut HashSet<ObjectId>,
        result: &mut CascadeResult,
    ) {
        let resolved_current = self.local.graph.resolve_rename(current).clone();

        if !visited.insert(resolved_current.clone()) {
            return;
        }

        result.dropped_relations.insert(resolved_current.clone());

        if self.local.graph.cascade_index_is_worthwhile() {
            for edge in self.local.graph.cascade_edges(&resolved_current) {
                self.walk_cascade_edge(edge, &resolved_current, visited, result);
            }
        } else {
            for edge in self.local.graph.edges() {
                self.walk_cascade_edge(edge, &resolved_current, visited, result);
            }
        }
    }

    pub(super) fn walk_cascade_edge(
        &self,
        edge: &DependencyEdge,
        resolved_current: &ObjectId,
        visited: &mut HashSet<ObjectId>,
        result: &mut CascadeResult,
    ) {
        if !self.dependency_edge_is_current(edge) {
            return;
        }
        match &edge.kind {
            DependencyKind::ViewDependency { .. } => {
                if self.local.graph.resolve_rename(&edge.referenced) == resolved_current {
                    let resolved_view_id = self.local.graph.resolve_rename(&edge.dependent).clone();
                    if !visited.contains(&resolved_view_id) {
                        self.walk_cascade(&resolved_view_id, visited, result);
                    }
                }
            }
            DependencyKind::IndexOnRelation { .. } => {
                if self.local.graph.resolve_rename(&edge.referenced) == resolved_current {
                    result
                        .dropped_indexes
                        .insert(self.local.graph.resolve_rename(&edge.dependent).clone());
                }
            }
            DependencyKind::ForeignKey {
                constraint_name, ..
            } => {
                if self.local.graph.resolve_rename(&edge.referenced) == resolved_current
                    && let Some(cname) = constraint_name
                {
                    result.dropped_constraints.insert((
                        self.local.graph.resolve_rename(&edge.dependent).clone(),
                        cname.clone(),
                    ));
                }
            }
            DependencyKind::InheritanceOf | DependencyKind::PartitionOf
                if self.local.graph.resolve_rename(&edge.referenced) == resolved_current =>
            {
                let resolved_child = self.local.graph.resolve_rename(&edge.dependent).clone();
                if !visited.contains(&resolved_child) {
                    self.walk_cascade(&resolved_child, visited, result);
                }
            }
            _ => {}
        }
    }
}
