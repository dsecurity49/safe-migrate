use crate::ast::identifiers::ObjectId;
use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq)]
pub enum DependencyKind {
    ForeignKey {
        constraint_name: Option<String>,
        from_columns: Vec<String>,
        to_columns: Vec<String>,
        /// Catalog-selected equality operators for an exact synchronized FK.
        /// Local migrations use `None` until PostgreSQL operator resolution is
        /// proven from typed catalog evidence.
        operator_evidence: Option<ForeignKeyOperatorEvidence>,
        from_generation: u64,
    },
    ViewDependency {
        view_generation: u64,
        /// `Some` is a catalog-proven column dependency. `None` is used for
        /// relation-level baseline evidence and locally parsed views whose
        /// expression-column dependencies are not modeled yet.
        referenced_column: Option<String>,
    },
    IndexOnRelation {
        using_method: Option<String>,
        key_columns: Vec<String>,
        included_columns: Vec<String>,
        dependency_columns: Vec<String>,
        dependency_columns_known: bool,
        has_expression_keys: bool,
        has_predicate: bool,
        is_concurrent: bool,
        is_unique: bool,
        is_valid: bool,
        is_ready: bool,
        is_live: bool,
        has_default_sort_order: bool,
        has_default_opclasses: bool,
        has_default_collations: bool,
        eligibility_known: bool,
    },
    /// A primary-key/unique constraint whose ordered key columns are known.
    /// V8 hydration and local mutations share this edge; legacy or incomplete
    /// cache construction must still remain conservative.
    ConstraintOnRelation {
        constraint_name: String,
        columns: Vec<String>,
        is_primary: bool,
    },
    /// A check/exclusion constraint's expression dependency columns.
    ConstraintDependency {
        constraint_name: String,
        columns: Vec<String>,
    },
    RenameTo,
    /// Traditional `CREATE TABLE ... INHERITS (...)` relationship.
    ///
    /// It shares PostgreSQL's drop dependency behaviour with a partition, but
    /// must remain distinct: partition-only lifecycle checks do not apply to
    /// ordinary table inheritance.
    InheritanceOf,
    PartitionOf,
    SequenceOwnedBy {
        column: String,
    },
    ColumnGeneratedFrom {
        column: String,
        depends_on_column: String,
    },
    ColumnDefaultOnSequence {
        column: String,
    },
    TriggerOnTable {
        trigger_id: ObjectId,
        function_id: ObjectId,
    },
    PublicationIncludes {
        publication_name: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ForeignKeyOperatorEvidence {
    pub pk_fk: Vec<String>,
    pub pk_pk: Vec<String>,
    pub fk_fk: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DependencyEdge {
    pub dependent: ObjectId,
    pub referenced: ObjectId,
    pub kind: DependencyKind,
}

impl DependencyEdge {
    pub fn new(dependent: ObjectId, referenced: ObjectId, kind: DependencyKind) -> Self {
        Self {
            dependent,
            referenced,
            kind,
        }
    }
}

#[derive(Debug, Default)]
pub struct DependencyGraph {
    edges: Vec<DependencyEdge>,
    indexes: OnceCell<GraphIndexes>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct GraphIndexes {
    rename_by_source: HashMap<ObjectId, usize>,
    by_resolved_referenced: HashMap<ObjectId, Vec<usize>>,
}

impl Clone for DependencyGraph {
    fn clone(&self) -> Self {
        Self {
            edges: self.edges.clone(),
            // Indexes are derived state. Avoid duplicating them in statement
            // checkpoints; the clone builds them only if a lookup needs them.
            indexes: OnceCell::new(),
        }
    }
}

impl DependencyGraph {
    const CASCADE_INDEX_MIN_EDGES: usize = 1_024;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn edges(&self) -> &[DependencyEdge] {
        &self.edges
    }

    pub fn add_edge(&mut self, edge: DependencyEdge) {
        self.edges.push(edge);
        self.invalidate_indexes();
    }

    pub(crate) fn retain_edges(&mut self, mut keep: impl FnMut(&DependencyEdge) -> bool) {
        self.edges.retain(|edge| keep(edge));
        self.invalidate_indexes();
    }

    pub(crate) fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.edges.truncate(len);
        self.invalidate_indexes();
    }

    pub(crate) fn replace_edges(&mut self, edges: Vec<DependencyEdge>) {
        self.edges = edges;
        self.invalidate_indexes();
    }

    pub(crate) fn mutate_edges(&mut self, mutate: impl FnOnce(&mut [DependencyEdge])) {
        mutate(&mut self.edges);
        self.invalidate_indexes();
    }

    /// Confirms that every derived lookup points at the canonical edge list.
    /// This is intentionally cheap to call from invariant tests, not hot paths.
    pub fn indexes_are_valid(&self) -> bool {
        self.indexes() == &Self::build_indexes(&self.edges)
    }

    fn invalidate_indexes(&mut self) {
        self.indexes.take();
    }

    fn indexes(&self) -> &GraphIndexes {
        self.indexes
            .get_or_init(|| Self::build_indexes(&self.edges))
    }

    fn build_indexes(edges: &[DependencyEdge]) -> GraphIndexes {
        let mut indexes = GraphIndexes::default();
        for (index, edge) in edges.iter().enumerate() {
            if matches!(edge.kind, DependencyKind::RenameTo) {
                indexes
                    .rename_by_source
                    .entry(edge.dependent.clone())
                    .or_insert(index);
            }
        }

        for (index, edge) in edges.iter().enumerate() {
            let referenced = Self::resolve_rename_with(edges, &indexes, &edge.referenced).clone();
            indexes
                .by_resolved_referenced
                .entry(referenced)
                .or_default()
                .push(index);
        }
        indexes
    }

    fn resolve_rename_with<'a>(
        edges: &'a [DependencyEdge],
        indexes: &GraphIndexes,
        id: &'a ObjectId,
    ) -> &'a ObjectId {
        let mut current = id;
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(current.clone()) {
                return id;
            }
            match indexes.rename_by_source.get(current) {
                Some(index) => current = &edges[*index].referenced,
                None => return current,
            }
        }
    }

    fn resolved_referenced_edges(&self, id: &ObjectId) -> impl Iterator<Item = &DependencyEdge> {
        let target = self.resolve_rename(id);
        self.indexes()
            .by_resolved_referenced
            .get(target)
            .into_iter()
            .flatten()
            .map(|index| &self.edges[*index])
    }

    pub fn cascade_edges(&self, id: &ObjectId) -> Vec<&DependencyEdge> {
        if self.edges.len() < Self::CASCADE_INDEX_MIN_EDGES {
            let target = self.resolve_rename(id);
            return self
                .edges
                .iter()
                .filter(|edge| {
                    matches!(
                        edge.kind,
                        DependencyKind::ViewDependency { .. }
                            | DependencyKind::IndexOnRelation { .. }
                            | DependencyKind::ForeignKey { .. }
                            | DependencyKind::InheritanceOf
                            | DependencyKind::PartitionOf
                    ) && self.resolve_rename(&edge.referenced) == target
                })
                .collect();
        }
        self.resolved_referenced_edges(id)
            .filter(|edge| {
                matches!(
                    edge.kind,
                    DependencyKind::ViewDependency { .. }
                        | DependencyKind::IndexOnRelation { .. }
                        | DependencyKind::ForeignKey { .. }
                        | DependencyKind::InheritanceOf
                        | DependencyKind::PartitionOf
                )
            })
            .collect()
    }

    pub(crate) fn cascade_index_is_worthwhile(&self) -> bool {
        self.edges.len() >= Self::CASCADE_INDEX_MIN_EDGES
    }

    // Dependency lookups follow the current end of a rename chain.
    pub fn is_referenced_by_view(&self, id: &ObjectId) -> Vec<&ObjectId> {
        let target = self.resolve_rename(id);
        self.edges
            .iter()
            .filter(|e| {
                matches!(e.kind, DependencyKind::ViewDependency { .. })
                    && (self.resolve_rename(&e.referenced) == target || &e.referenced == id)
            })
            .map(|e| self.resolve_rename(&e.dependent))
            .collect()
    }

    pub fn is_referenced_by_fk(&self, id: &ObjectId) -> Vec<(&ObjectId, u64)> {
        let target = self.resolve_rename(id);
        self.edges
            .iter()
            .filter_map(|e| {
                if let DependencyKind::ForeignKey {
                    from_generation, ..
                } = &e.kind
                    && (self.resolve_rename(&e.referenced) == target || &e.referenced == id)
                {
                    Some((self.resolve_rename(&e.dependent), *from_generation))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn is_referenced_by_index(&self, id: &ObjectId) -> Vec<&ObjectId> {
        let target = self.resolve_rename(id);
        self.edges
            .iter()
            .filter(|e| {
                matches!(e.kind, DependencyKind::IndexOnRelation { .. })
                    && (self.resolve_rename(&e.referenced) == target || &e.referenced == id)
            })
            .map(|e| self.resolve_rename(&e.dependent))
            .collect()
    }

    pub fn partitions_of(&self, id: &ObjectId) -> Vec<&ObjectId> {
        let target = self.resolve_rename(id);
        self.edges
            .iter()
            .filter(|e| {
                matches!(e.kind, DependencyKind::PartitionOf)
                    && (self.resolve_rename(&e.referenced) == target || &e.referenced == id)
            })
            .map(|e| self.resolve_rename(&e.dependent))
            .collect()
    }

    pub fn resolve_rename<'a>(&'a self, id: &'a ObjectId) -> &'a ObjectId {
        let mut current = id;
        let mut visited = HashSet::new();
        loop {
            // A rename back to an earlier name is valid PostgreSQL. The graph
            // retains historical aliases, so resolve only acyclic paths; a
            // cycle has no unique alias target and must leave the supplied
            // identity unchanged.
            if !visited.insert(current.clone()) {
                return id;
            }
            match self.edges.iter().find(|edge| {
                matches!(edge.kind, DependencyKind::RenameTo) && &edge.dependent == current
            }) {
                Some(edge) => current = &edge.referenced,
                None => return current,
            }
        }
    }

    // Partition ancestry must remain acyclic.
    pub fn check_partition_cycle(&self, parent: &ObjectId, child: &ObjectId) -> bool {
        let resolved_parent = self.resolve_rename(parent);
        let resolved_child = self.resolve_rename(child);
        if resolved_parent == resolved_child {
            return true;
        }

        let mut current_parent = resolved_parent;
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(current_parent.clone()) {
                // The existing ancestry is already malformed. Reject another
                // attachment instead of looping or extending the cycle.
                return true;
            }
            let maybe_edge = self.edges.iter().find(|edge| {
                matches!(edge.kind, DependencyKind::PartitionOf)
                    && self.resolve_rename(&edge.dependent) == current_parent
            });
            if let Some(edge) = maybe_edge {
                let p = self.resolve_rename(&edge.referenced);
                if p == resolved_child {
                    return true;
                }
                current_parent = p;
            } else {
                break;
            }
        }
        false
    }

    /// Propagate a relation rename through relation-to-relation edges.
    ///
    /// Dependency endpoints are intentionally updated by edge kind rather than
    /// by blindly comparing `ObjectId`s.  `ObjectId` carries no catalog kind,
    /// and publications are represented by a synthetic `public/<name>` ID, so
    /// a generic endpoint rewrite can otherwise corrupt an unrelated edge when
    /// two namespaces happen to share a name.
    pub fn propagate_relation_rename(&mut self, old_id: &ObjectId, new_id: &ObjectId) {
        for edge in &mut self.edges {
            match &mut edge.kind {
                DependencyKind::RenameTo => {}
                DependencyKind::ForeignKey { .. }
                | DependencyKind::ViewDependency { .. }
                | DependencyKind::InheritanceOf
                | DependencyKind::PartitionOf
                | DependencyKind::ConstraintDependency { .. }
                | DependencyKind::ColumnGeneratedFrom { .. }
                | DependencyKind::ColumnDefaultOnSequence { .. } => {
                    if edge.dependent == *old_id {
                        edge.dependent = new_id.clone();
                    }
                    if edge.referenced == *old_id {
                        edge.referenced = new_id.clone();
                    }
                }
                DependencyKind::IndexOnRelation { .. }
                | DependencyKind::SequenceOwnedBy { .. }
                | DependencyKind::TriggerOnTable { .. } => {
                    if edge.referenced == *old_id {
                        edge.referenced = new_id.clone();
                    }
                }
                DependencyKind::ConstraintOnRelation { .. } => {
                    if edge.dependent == *old_id {
                        edge.dependent = new_id.clone();
                    }
                    if edge.referenced == *old_id {
                        edge.referenced = new_id.clone();
                    }
                }
                DependencyKind::PublicationIncludes { .. } => {
                    if edge.dependent == *old_id {
                        edge.dependent = new_id.clone();
                    }
                }
            }
        }
        self.invalidate_indexes();
    }

    /// Propagate an index rename.  Indexes are dependent endpoints of their
    /// `IndexOnRelation` edges; they are not relation references.
    pub fn propagate_index_rename(&mut self, old_id: &ObjectId, new_id: &ObjectId) {
        for edge in &mut self.edges {
            if matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
                && edge.dependent == *old_id
            {
                edge.dependent = new_id.clone();
            }
        }
        self.invalidate_indexes();
    }

    /// Propagate a sequence rename only through sequence ownership edges.
    pub fn propagate_sequence_rename(&mut self, old_id: &ObjectId, new_id: &ObjectId) {
        for edge in &mut self.edges {
            if matches!(edge.kind, DependencyKind::SequenceOwnedBy { .. })
                && edge.dependent == *old_id
            {
                edge.dependent = new_id.clone();
            }
        }
        self.invalidate_indexes();
    }

    /// Propagate a trigger rename through its trigger edge and payload.
    pub fn propagate_trigger_rename(&mut self, old_id: &ObjectId, new_id: &ObjectId) {
        for edge in &mut self.edges {
            if let DependencyKind::TriggerOnTable { trigger_id, .. } = &mut edge.kind
                && *trigger_id == *old_id
            {
                *trigger_id = new_id.clone();
                if edge.dependent == *old_id {
                    edge.dependent = new_id.clone();
                }
            }
        }
        self.invalidate_indexes();
    }

    /// Propagate a function rename through trigger dependency payloads.
    pub fn propagate_function_rename(&mut self, old_id: &ObjectId, new_id: &ObjectId) {
        for edge in &mut self.edges {
            if let DependencyKind::TriggerOnTable { function_id, .. } = &mut edge.kind
                && *function_id == *old_id
            {
                *function_id = new_id.clone();
            }
        }
        self.invalidate_indexes();
    }

    /// Backwards-compatible relation rename entry point.
    ///
    /// New callers should use the typed helpers above.  Keeping this method
    /// relation-scoped prevents the old all-endpoints behavior from silently
    /// rewriting sequence, trigger, function, or publication identity data.
    pub fn propagate_rename(&mut self, old_id: &ObjectId, new_id: &ObjectId) {
        self.propagate_relation_rename(old_id, new_id);
    }

    pub fn triggers_on(&self, table_id: &ObjectId) -> Vec<&DependencyEdge> {
        self.edges
            .iter()
            .filter(|e| {
                matches!(e.kind, DependencyKind::TriggerOnTable { .. }) && &e.referenced == table_id
            })
            .collect()
    }

    pub fn triggers_for_function(&self, function_id: &ObjectId) -> Vec<&DependencyEdge> {
        self.edges
            .iter()
            .filter(|e| {
                if let DependencyKind::TriggerOnTable {
                    function_id: fid, ..
                } = &e.kind
                {
                    fid == function_id
                } else {
                    false
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(name: &str) -> ObjectId {
        ObjectId::new("public", name)
    }

    fn view_edge(dependent: &str, referenced: &str) -> DependencyEdge {
        DependencyEdge::new(
            id(dependent),
            id(referenced),
            DependencyKind::ViewDependency {
                view_generation: 1,
                referenced_column: None,
            },
        )
    }

    fn canonical_views<'a>(graph: &'a DependencyGraph, target: &ObjectId) -> Vec<&'a ObjectId> {
        let resolved_target = graph.resolve_rename(target);
        graph
            .edges()
            .iter()
            .filter(|edge| {
                matches!(edge.kind, DependencyKind::ViewDependency { .. })
                    && (graph.resolve_rename(&edge.referenced) == resolved_target
                        || &edge.referenced == target)
            })
            .map(|edge| graph.resolve_rename(&edge.dependent))
            .collect()
    }

    fn assert_indexed_views_match_scan(graph: &DependencyGraph, targets: &[ObjectId]) {
        assert!(graph.indexes_are_valid());
        for target in targets {
            let indexed = graph
                .cascade_edges(target)
                .into_iter()
                .filter(|edge| matches!(edge.kind, DependencyKind::ViewDependency { .. }))
                .map(|edge| graph.resolve_rename(&edge.dependent))
                .collect::<Vec<_>>();
            assert_eq!(indexed, canonical_views(graph, target));
        }
    }

    #[test]
    fn indexes_track_every_graph_mutation_and_alias_cycle() {
        let a = id("a");
        let b = id("b");
        let c = id("c");
        let d = id("d");
        let targets = [a.clone(), b.clone(), c.clone(), d.clone()];
        let mut graph = DependencyGraph::new();

        graph.add_edge(view_edge("view_a", "a"));
        graph.add_edge(view_edge("view_b", "b"));
        for index in 0..DependencyGraph::CASCADE_INDEX_MIN_EDGES {
            graph.add_edge(view_edge(
                &format!("unrelated_view_{index}"),
                &format!("unrelated_table_{index}"),
            ));
        }
        assert_indexed_views_match_scan(&graph, &targets);

        graph.add_edge(DependencyEdge::new(
            a.clone(),
            b.clone(),
            DependencyKind::RenameTo,
        ));
        assert_indexed_views_match_scan(&graph, &targets);

        graph.propagate_rename(&b, &c);
        graph.add_edge(DependencyEdge::new(
            b.clone(),
            c.clone(),
            DependencyKind::RenameTo,
        ));
        assert_indexed_views_match_scan(&graph, &targets);

        graph.mutate_edges(|edges| {
            for edge in edges {
                if edge.dependent == id("view_b") {
                    edge.dependent = id("view_c");
                }
            }
        });
        assert_indexed_views_match_scan(&graph, &targets);

        let snapshot = graph.edges().to_vec();
        graph.retain_edges(|edge| edge.dependent != id("view_a"));
        assert_indexed_views_match_scan(&graph, &targets);
        graph.replace_edges(snapshot);
        assert_indexed_views_match_scan(&graph, &targets);

        let checkpoint = graph.edge_count();
        graph.add_edge(view_edge("temporary", "c"));
        graph.truncate(checkpoint);
        assert_indexed_views_match_scan(&graph, &targets);

        graph.add_edge(DependencyEdge::new(
            c.clone(),
            a.clone(),
            DependencyKind::RenameTo,
        ));
        assert_eq!(graph.resolve_rename(&a), &a);
        assert_eq!(graph.resolve_rename(&b), &b);
        assert_eq!(graph.resolve_rename(&c), &c);
        assert_indexed_views_match_scan(&graph, &targets);
    }

    #[test]
    fn trigger_dependencies_preserve_overloaded_function_identity() {
        let mut graph = DependencyGraph::new();
        let trigger_function = id("notify()");
        let overload = id("notify(integer)");
        graph.add_edge(DependencyEdge::new(
            id("events_notify_trigger"),
            id("events"),
            DependencyKind::TriggerOnTable {
                trigger_id: id("events_notify_trigger"),
                function_id: trigger_function.clone(),
            },
        ));

        assert_eq!(graph.triggers_for_function(&trigger_function).len(), 1);
        assert!(graph.triggers_for_function(&overload).is_empty());
    }

    #[test]
    fn traditional_inheritance_cascades_without_becoming_a_partition() {
        let parent = id("parent");
        let child = id("child");
        let mut graph = DependencyGraph::new();
        graph.add_edge(DependencyEdge::new(
            child.clone(),
            parent.clone(),
            DependencyKind::InheritanceOf,
        ));

        assert!(graph.partitions_of(&parent).is_empty());
        assert!(graph.cascade_edges(&parent).iter().any(|edge| {
            edge.dependent == child && matches!(edge.kind, DependencyKind::InheritanceOf)
        }));
    }
}
