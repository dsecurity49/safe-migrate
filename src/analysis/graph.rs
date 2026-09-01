use crate::ast::identifiers::ObjectId;
use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
        trigger_generation: u64,
    },
    PublicationIncludes {
        publication_name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ForeignKeyOperatorEvidence {
    pub pk_fk: Vec<String>,
    pub pk_pk: Vec<String>,
    pub fk_fk: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    edge_set: HashSet<DependencyEdge>,
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
            edge_set: self.edges.iter().cloned().collect(),
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
        // The dependency graph is a set of typed relationships. Replaying a
        // hydration row or an idempotent mutation must not multiply cascade
        // work or make traversal results depend on insertion history.
        if !self.edge_set.insert(edge.clone()) {
            return;
        }
        self.edges.push(edge);
        self.invalidate_indexes();
    }

    pub(crate) fn retain_edges(&mut self, mut keep: impl FnMut(&DependencyEdge) -> bool) {
        let previous_len = self.edges.len();
        self.edges.retain(|edge| keep(edge));
        if self.edges.len() != previous_len {
            self.rebuild_edge_set();
            self.invalidate_indexes();
        }
    }

    pub(crate) fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        if len >= self.edges.len() {
            return;
        }
        self.edges.truncate(len);
        self.rebuild_edge_set();
        self.invalidate_indexes();
    }

    pub(crate) fn replace_edges(&mut self, edges: Vec<DependencyEdge>) {
        self.edges = edges;
        self.deduplicate_edges();
        self.invalidate_indexes();
    }

    fn mutate_edges(&mut self, mutate: impl FnOnce(&mut [DependencyEdge])) {
        mutate(&mut self.edges);
        self.deduplicate_edges();
        self.invalidate_indexes();
    }

    /// Restore set semantics after an operation that rewrites existing edge
    /// identities. A rename or namespace remap can collapse two formerly
    /// distinct edges into one exact typed relationship; keeping both would
    /// make traversal and cascade results depend on mutation history.
    fn deduplicate_edges(&mut self) {
        let mut seen = HashSet::with_capacity(self.edges.len());
        self.edges.retain(|edge| seen.insert(edge.clone()));
        self.edge_set = seen;
    }

    fn rebuild_edge_set(&mut self) {
        self.edge_set = self.edges.iter().cloned().collect();
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
        if self.edges.len() >= Self::CASCADE_INDEX_MIN_EDGES {
            return self
                .resolved_referenced_edges(id)
                .filter(|edge| matches!(edge.kind, DependencyKind::ViewDependency { .. }))
                .map(|edge| self.resolve_rename(&edge.dependent))
                .collect();
        }
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
        if self.edges.len() >= Self::CASCADE_INDEX_MIN_EDGES {
            return self
                .resolved_referenced_edges(id)
                .filter_map(|edge| {
                    if let DependencyKind::ForeignKey {
                        from_generation, ..
                    } = &edge.kind
                    {
                        Some((self.resolve_rename(&edge.dependent), *from_generation))
                    } else {
                        None
                    }
                })
                .collect();
        }
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
        if self.edges.len() >= Self::CASCADE_INDEX_MIN_EDGES {
            return self
                .resolved_referenced_edges(id)
                .filter(|edge| matches!(edge.kind, DependencyKind::IndexOnRelation { .. }))
                .map(|edge| self.resolve_rename(&edge.dependent))
                .collect();
        }
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
        if self.edges.len() >= Self::CASCADE_INDEX_MIN_EDGES {
            return self
                .resolved_referenced_edges(id)
                .filter(|edge| matches!(edge.kind, DependencyKind::PartitionOf))
                .map(|edge| self.resolve_rename(&edge.dependent))
                .collect();
        }
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
        // A rename back to an earlier name is valid PostgreSQL. The indexed
        // resolver retains the same cycle fallback while avoiding a full edge
        // scan for every dependency lookup on large baselines.
        Self::resolve_rename_with(&self.edges, self.indexes(), id)
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

    /// Remap every schema-qualified graph endpoint during `ALTER SCHEMA ...
    /// RENAME`. Synthetic publication nodes remain cluster-scoped, while
    /// trigger payload identities follow their table/function endpoints.
    pub(crate) fn remap_schema_namespace(&mut self, old_schema: &str, new_schema: &str) {
        let remap = |id: &mut ObjectId| {
            if id.schema == old_schema {
                id.schema = new_schema.to_string();
            }
        };
        for edge in &mut self.edges {
            match &mut edge.kind {
                DependencyKind::PublicationIncludes { .. } => remap(&mut edge.dependent),
                DependencyKind::TriggerOnTable {
                    trigger_id,
                    function_id,
                    ..
                } => {
                    remap(&mut edge.dependent);
                    remap(&mut edge.referenced);
                    remap(trigger_id);
                    remap(function_id);
                }
                _ => {
                    remap(&mut edge.dependent);
                    remap(&mut edge.referenced);
                }
            }
        }
        self.deduplicate_edges();
        self.invalidate_indexes();
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
        self.deduplicate_edges();
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
        self.deduplicate_edges();
        self.invalidate_indexes();
    }

    /// Propagate a sequence rename through every typed sequence endpoint.
    /// Ownership uses the sequence as a dependent; a column default uses it
    /// as a referenced object. Both must follow the canonical identity.
    pub fn propagate_sequence_rename(&mut self, old_id: &ObjectId, new_id: &ObjectId) {
        for edge in &mut self.edges {
            match &edge.kind {
                DependencyKind::SequenceOwnedBy { .. } if edge.dependent == *old_id => {
                    edge.dependent = new_id.clone();
                }
                DependencyKind::ColumnDefaultOnSequence { .. } if edge.referenced == *old_id => {
                    edge.referenced = new_id.clone();
                }
                _ => {}
            }
        }
        self.deduplicate_edges();
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
        self.deduplicate_edges();
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
        self.deduplicate_edges();
        self.invalidate_indexes();
    }

    /// Rename a foreign-key constraint payload owned by a relation.
    pub fn rename_foreign_key_constraint(
        &mut self,
        table_id: &ObjectId,
        old_name: &str,
        new_name: &str,
    ) {
        self.mutate_edges(|edges| {
            for edge in edges {
                if edge.dependent == *table_id
                    && let DependencyKind::ForeignKey {
                        constraint_name: Some(name),
                        ..
                    } = &mut edge.kind
                    && name == old_name
                {
                    *name = new_name.to_string();
                }
            }
        });
    }

    /// Rename a table column in all typed dependency payloads that can carry
    /// column identity. The endpoint direction determines whether the column
    /// is source-side or referenced-side for foreign keys.
    pub fn rename_column_dependencies(
        &mut self,
        table_id: &ObjectId,
        old_name: &str,
        new_name: &str,
    ) {
        self.mutate_edges(|edges| {
            for edge in edges {
                match &mut edge.kind {
                    DependencyKind::ForeignKey {
                        from_columns,
                        to_columns,
                        ..
                    } => {
                        if edge.dependent == *table_id {
                            for column in from_columns {
                                if column == old_name {
                                    *column = new_name.to_string();
                                }
                            }
                        }
                        if edge.referenced == *table_id {
                            for column in to_columns {
                                if column == old_name {
                                    *column = new_name.to_string();
                                }
                            }
                        }
                    }
                    DependencyKind::ConstraintOnRelation { columns, .. }
                        if edge.dependent == *table_id =>
                    {
                        for column in columns {
                            if column == old_name {
                                *column = new_name.to_string();
                            }
                        }
                    }
                    DependencyKind::ConstraintDependency { columns, .. }
                        if edge.dependent == *table_id =>
                    {
                        for column in columns {
                            if column == old_name {
                                *column = new_name.to_string();
                            }
                        }
                    }
                    DependencyKind::ColumnGeneratedFrom {
                        column,
                        depends_on_column,
                    } => {
                        if edge.dependent == *table_id && column == old_name {
                            *column = new_name.to_string();
                        }
                        if edge.referenced == *table_id && depends_on_column == old_name {
                            *depends_on_column = new_name.to_string();
                        }
                    }
                    DependencyKind::ColumnDefaultOnSequence { column }
                        if edge.dependent == *table_id && column == old_name =>
                    {
                        *column = new_name.to_string();
                    }
                    _ => {}
                }
            }
        });
    }

    /// Rename a column in an index definition attached to a relation.
    pub fn rename_index_column(&mut self, table_id: &ObjectId, old_name: &str, new_name: &str) {
        self.mutate_edges(|edges| {
            for edge in edges {
                if edge.referenced != *table_id {
                    continue;
                }
                let DependencyKind::IndexOnRelation {
                    key_columns,
                    included_columns,
                    dependency_columns,
                    ..
                } = &mut edge.kind
                else {
                    continue;
                };
                for column in key_columns
                    .iter_mut()
                    .chain(included_columns)
                    .chain(dependency_columns)
                {
                    if column == old_name {
                        *column = new_name.to_string();
                    }
                }
            }
        });
    }

    /// Rename the owned column recorded on a sequence edge.
    pub fn rename_owned_sequence_column(
        &mut self,
        sequence_id: &ObjectId,
        old_name: &str,
        new_name: &str,
    ) {
        self.mutate_edges(|edges| {
            for edge in edges {
                if edge.dependent == *sequence_id
                    && let DependencyKind::SequenceOwnedBy { column } = &mut edge.kind
                    && column == old_name
                {
                    *column = new_name.to_string();
                }
            }
        });
    }

    /// Rename a publication node and its membership payloads.
    pub fn rename_publication(&mut self, old_name: &str, new_name: &str) {
        self.mutate_edges(|edges| {
            for edge in edges {
                if let DependencyKind::PublicationIncludes { publication_name } = &mut edge.kind
                    && publication_name == old_name
                {
                    *publication_name = new_name.to_string();
                    edge.referenced = ObjectId::new("public", new_name);
                }
            }
        });
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

    #[test]
    fn identical_dependency_edges_are_deduplicated() {
        let mut graph = DependencyGraph::new();
        let edge = view_edge("view", "table");
        graph.add_edge(edge.clone());
        graph.add_edge(edge);

        assert_eq!(graph.edge_count(), 1);
        assert_eq!(graph.cascade_edges(&id("table")).len(), 1);
    }

    #[test]
    fn no_op_edge_mutations_preserve_derived_indexes() {
        let mut graph = DependencyGraph::new();
        graph.add_edge(view_edge("view", "table"));
        let _ = graph.cascade_edges(&id("table"));

        graph.retain_edges(|_| true);
        graph.truncate(graph.edge_count() + 1);

        assert!(graph.indexes_are_valid());
        assert_eq!(graph.cascade_edges(&id("table")).len(), 1);
    }

    #[test]
    fn identity_remaps_collapse_duplicate_edges() {
        let mut graph = DependencyGraph::new();
        graph.add_edge(view_edge("view_a", "table"));
        graph.add_edge(view_edge("view_b", "table"));

        graph.propagate_relation_rename(&id("view_b"), &id("view_a"));

        assert_eq!(graph.edge_count(), 1);
        assert!(graph.indexes_are_valid());
    }

    #[test]
    fn column_rename_updates_both_sides_of_self_referencing_fk() {
        let table = id("self_ref");
        let mut graph = DependencyGraph::new();
        graph.add_edge(DependencyEdge::new(
            table.clone(),
            table.clone(),
            DependencyKind::ForeignKey {
                constraint_name: Some("self_fk".into()),
                from_columns: vec!["old_id".into()],
                to_columns: vec!["old_id".into()],
                operator_evidence: None,
                from_generation: 0,
            },
        ));
        graph.add_edge(DependencyEdge::new(
            table.clone(),
            table.clone(),
            DependencyKind::ConstraintDependency {
                constraint_name: "check_self".into(),
                columns: vec!["old_id".into()],
            },
        ));

        graph.rename_column_dependencies(&table, "old_id", "new_id");

        let DependencyKind::ForeignKey {
            from_columns,
            to_columns,
            ..
        } = &graph.edges()[0].kind
        else {
            panic!("expected foreign-key edge");
        };
        assert_eq!(from_columns, &["new_id"]);
        assert_eq!(to_columns, &["new_id"]);
        let DependencyKind::ConstraintDependency { columns, .. } = &graph.edges()[1].kind else {
            panic!("expected constraint dependency edge");
        };
        assert_eq!(columns, &["new_id"]);
    }

    fn relation_edge(dependent: &str, referenced: &str, kind: DependencyKind) -> DependencyEdge {
        DependencyEdge::new(id(dependent), id(referenced), kind)
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
                trigger_generation: 0,
            },
        ));

        assert_eq!(graph.triggers_for_function(&trigger_function).len(), 1);
        assert!(graph.triggers_for_function(&overload).is_empty());
    }

    #[test]
    fn indexed_reverse_dependency_lookups_match_alias_resolution() {
        let target = id("target");
        let renamed = id("renamed_target");
        let mut graph = DependencyGraph::new();
        for index in 0..DependencyGraph::CASCADE_INDEX_MIN_EDGES {
            graph.add_edge(view_edge(
                &format!("unrelated_view_{index}"),
                &format!("unrelated_table_{index}"),
            ));
        }
        graph.add_edge(relation_edge(
            "view",
            "target",
            DependencyKind::ViewDependency {
                view_generation: 1,
                referenced_column: None,
            },
        ));
        graph.add_edge(relation_edge(
            "index",
            "target",
            DependencyKind::IndexOnRelation {
                using_method: Some("btree".into()),
                key_columns: vec!["id".into()],
                included_columns: Vec::new(),
                dependency_columns: Vec::new(),
                dependency_columns_known: true,
                has_expression_keys: false,
                has_predicate: false,
                is_concurrent: false,
                is_unique: false,
                is_valid: true,
                is_ready: true,
                is_live: true,
                has_default_sort_order: true,
                has_default_opclasses: true,
                has_default_collations: true,
                eligibility_known: true,
            },
        ));
        graph.add_edge(relation_edge(
            "child",
            "target",
            DependencyKind::ForeignKey {
                constraint_name: Some("child_target_fkey".into()),
                from_columns: vec!["target_id".into()],
                to_columns: vec!["id".into()],
                operator_evidence: None,
                from_generation: 7,
            },
        ));
        graph.add_edge(relation_edge(
            "partition",
            "target",
            DependencyKind::PartitionOf,
        ));
        graph.add_edge(DependencyEdge::new(
            target.clone(),
            renamed.clone(),
            DependencyKind::RenameTo,
        ));

        assert_eq!(
            graph
                .is_referenced_by_view(&renamed)
                .into_iter()
                .map(|id| id.name.clone())
                .collect::<Vec<_>>(),
            vec!["view"]
        );
        assert_eq!(
            graph
                .is_referenced_by_index(&renamed)
                .into_iter()
                .map(|id| id.name.clone())
                .collect::<Vec<_>>(),
            vec!["index"]
        );
        assert_eq!(
            graph
                .is_referenced_by_fk(&renamed)
                .into_iter()
                .map(|(id, generation)| (id.name.clone(), generation))
                .collect::<Vec<_>>(),
            vec![("child".into(), 7)]
        );
        assert_eq!(
            graph
                .partitions_of(&renamed)
                .into_iter()
                .map(|id| id.name.clone())
                .collect::<Vec<_>>(),
            vec!["partition"]
        );
        assert!(graph.indexes_are_valid());
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
