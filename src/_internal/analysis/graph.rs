use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::index::{IndexDefinition, KeyCollation, ResolvedName};
use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};

fn remap_endpoint(endpoint: &mut ObjectId, mappings: &HashMap<ObjectId, ObjectId>) -> bool {
    let Some(replacement) = mappings.get(endpoint) else {
        return false;
    };
    if replacement == endpoint {
        return false;
    }
    *endpoint = replacement.clone();
    true
}

/// Why one object depends on another. The kind decides which operations must
/// respect the dependency.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum DependencyKind {
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
    /// A routine a view calls, which a drop of that routine must clear.
    ///
    /// `unresolved_name` is `Some` when the call could not be pinned to a
    /// signature. The edge endpoint is then the written name, and every
    /// overload of that name is a dependent. A move of only some overloads
    /// cannot be expressed that way and taints the chain instead. `None` means
    /// the endpoint is the resolved routine identity itself.
    ViewUsesRoutine {
        unresolved_name: Option<ObjectId>,
    },
    /// A type a view body casts to, which a drop of that type must clear.
    ///
    /// PostgreSQL records this from the cast alone: a view that selects a
    /// column of a type creates no such dependency. The endpoint is the type.
    ViewUsesType,
    /// A routine or aggregate that depends on another routine.
    RoutineUsesRoutine {
        unresolved_name: Option<ObjectId>,
    },
    /// A routine whose parsed body depends on a relation (and optionally a column).
    RoutineUsesRelation {
        referenced_column: Option<String>,
    },
    /// A routine or aggregate that depends on a user-defined type.
    RoutineUsesType,
    IndexOnRelation {
        definition: IndexDefinition,
        dependency_columns: Vec<String>,
        dependency_columns_known: bool,
        is_concurrent: bool,
        is_immediate: bool,
        eligibility_known: bool,
    },
    /// A primary-key/unique constraint whose ordered key columns are known.
    /// V7 hydration and local mutations share this edge; legacy or incomplete
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
    /// An index attached to a partitioned index with `ALTER INDEX ... ATTACH
    /// PARTITION`. PostgreSQL drops the child with its parent.
    IndexPartitionOf,
    /// A `DETACH PARTITION CONCURRENTLY` interrupted after its first internal
    /// transaction remains attached until `FINALIZE` completes it.
    PartitionDetachPending,
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
pub(crate) struct ForeignKeyOperatorEvidence {
    pub pk_fk: Vec<String>,
    pub pk_pk: Vec<String>,
    pub fk_fk: Vec<String>,
}

/// A directed dependency: the `dependent` object needs the `referenced` one to
/// stay valid.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct DependencyEdge {
    pub dependent: ObjectId,
    pub referenced: ObjectId,
    pub kind: DependencyKind,
}

impl DependencyEdge {
    pub(crate) fn new(dependent: ObjectId, referenced: ObjectId, kind: DependencyKind) -> Self {
        Self {
            dependent,
            referenced,
            kind,
        }
    }
}

/// Dependency edges between modeled objects, with lookup indexes built on first use.
#[derive(Debug, Default)]
pub(crate) struct DependencyGraph {
    edges: Vec<DependencyEdge>,
    edge_set: HashSet<DependencyEdge>,
    // Each lookup has its own lazy cell: rename resolution and dependent-edge
    // lookups must not force the expensive resolved-adjacency build.
    rename_index: OnceCell<HashMap<ObjectId, usize>>,
    dependent_index: OnceCell<HashMap<ObjectId, Vec<usize>>>,
    index_partition_index: OnceCell<HashMap<ObjectId, Vec<usize>>>,
    resolved_indexes: OnceCell<ResolvedIndexes>,
}

/// All identity moves belonging to one logical rename statement.
///
/// Applying them together keeps the graph at one pass and one deduplication
/// instead of one full rewrite per moved object.
#[derive(Debug, Default)]
pub(crate) struct GraphRenamePlan {
    pub relations: HashMap<ObjectId, ObjectId>,
    pub indexes: HashMap<ObjectId, ObjectId>,
    pub sequences: HashMap<ObjectId, ObjectId>,
    pub triggers: HashMap<ObjectId, ObjectId>,
    pub routines: HashMap<ObjectId, ObjectId>,
    pub types: HashMap<ObjectId, ObjectId>,
}

/// Undo record for a batched rename remap.
///
/// Only changed edges and edges removed by deduplication are retained; the
/// untouched remainder is reconstructed from the live edge vector on rollback.
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct GraphEdgeDelta {
    original_len: usize,
    changed: Vec<(usize, DependencyEdge)>,
    removed: Vec<(usize, DependencyEdge)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ResolvedIndexes {
    by_resolved_referenced: HashMap<ObjectId, Vec<usize>>,
    by_resolved_dependent: HashMap<ObjectId, Vec<usize>>,
}

impl Clone for DependencyGraph {
    fn clone(&self) -> Self {
        Self {
            edges: self.edges.clone(),
            edge_set: self.edges.iter().cloned().collect(),
            // Indexes are derived state. Avoid duplicating them in statement
            // checkpoints; the clone builds them only if a lookup needs them.
            rename_index: OnceCell::new(),
            dependent_index: OnceCell::new(),
            index_partition_index: OnceCell::new(),
            resolved_indexes: OnceCell::new(),
        }
    }
}

#[cfg(test)]
impl PartialEq for DependencyGraph {
    fn eq(&self, other: &Self) -> bool {
        self.edges == other.edges && self.edge_set_is_valid() && other.edge_set_is_valid()
    }
}

impl DependencyGraph {
    const CASCADE_INDEX_MIN_EDGES: usize = 1_024;

    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn edges(&self) -> &[DependencyEdge] {
        &self.edges
    }

    pub(crate) fn add_edge(&mut self, edge: DependencyEdge) {
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
    pub(crate) fn indexes_are_valid(&self) -> bool {
        let rename = Self::build_rename_index(&self.edges);
        self.rename_index() == &rename
            && self.dependent_index() == &Self::build_dependent_index(&self.edges)
            && self.index_partition_index()
                == &Self::build_index_partition_index(&self.edges, &rename)
            && self.resolved_indexes() == &Self::build_resolved_indexes(&self.edges, &rename)
    }

    #[cfg(test)]
    pub(crate) fn edge_set_is_valid(&self) -> bool {
        self.edge_set.len() == self.edges.len()
            && self.edge_set == self.edges.iter().cloned().collect()
    }

    /// Forces lazy index construction so benchmarks can measure it without
    /// mixing in a cascade lookup or result materialization.
    #[cfg(test)]
    pub(crate) fn build_indexes_for_tests(&self) {
        let _ = self.rename_index();
        let _ = self.dependent_index();
        let _ = self.index_partition_index();
        let _ = self.resolved_indexes();
    }

    fn invalidate_indexes(&mut self) {
        self.rename_index.take();
        self.dependent_index.take();
        self.index_partition_index.take();
        self.resolved_indexes.take();
    }

    fn rename_index(&self) -> &HashMap<ObjectId, usize> {
        self.rename_index
            .get_or_init(|| Self::build_rename_index(&self.edges))
    }

    fn dependent_index(&self) -> &HashMap<ObjectId, Vec<usize>> {
        self.dependent_index
            .get_or_init(|| Self::build_dependent_index(&self.edges))
    }

    fn index_partition_index(&self) -> &HashMap<ObjectId, Vec<usize>> {
        self.index_partition_index
            .get_or_init(|| Self::build_index_partition_index(&self.edges, self.rename_index()))
    }

    fn build_index_partition_index(
        edges: &[DependencyEdge],
        rename_by_source: &HashMap<ObjectId, usize>,
    ) -> HashMap<ObjectId, Vec<usize>> {
        let mut by_referenced: HashMap<ObjectId, Vec<usize>> = HashMap::new();
        let mut resolved: HashMap<ObjectId, ObjectId> = HashMap::new();
        for (index, edge) in edges.iter().enumerate() {
            if matches!(edge.kind, DependencyKind::IndexPartitionOf) {
                let referenced = Self::resolve_rename_memo(
                    edges,
                    rename_by_source,
                    &mut resolved,
                    &edge.referenced,
                );
                by_referenced.entry(referenced).or_default().push(index);
            }
        }
        by_referenced
    }

    fn resolved_indexes(&self) -> &ResolvedIndexes {
        self.resolved_indexes
            .get_or_init(|| Self::build_resolved_indexes(&self.edges, self.rename_index()))
    }

    fn build_rename_index(edges: &[DependencyEdge]) -> HashMap<ObjectId, usize> {
        let mut rename_by_source = HashMap::new();
        for (index, edge) in edges.iter().enumerate() {
            if matches!(edge.kind, DependencyKind::RenameTo) {
                rename_by_source
                    .entry(edge.dependent.clone())
                    .or_insert(index);
            }
        }
        rename_by_source
    }

    fn build_dependent_index(edges: &[DependencyEdge]) -> HashMap<ObjectId, Vec<usize>> {
        let mut by_dependent: HashMap<ObjectId, Vec<usize>> = HashMap::new();
        for (index, edge) in edges.iter().enumerate() {
            by_dependent
                .entry(edge.dependent.clone())
                .or_default()
                .push(index);
        }
        by_dependent
    }

    fn build_resolved_indexes(
        edges: &[DependencyEdge],
        rename_by_source: &HashMap<ObjectId, usize>,
    ) -> ResolvedIndexes {
        let mut indexes = ResolvedIndexes::default();
        let mut resolved: HashMap<ObjectId, ObjectId> = HashMap::new();
        for (index, edge) in edges.iter().enumerate() {
            if Self::cascade_kind(&edge.kind) {
                let referenced = Self::resolve_rename_memo(
                    edges,
                    rename_by_source,
                    &mut resolved,
                    &edge.referenced,
                );
                indexes
                    .by_resolved_referenced
                    .entry(referenced)
                    .or_default()
                    .push(index);
            }
            if Self::cycle_kind(&edge.kind) {
                let dependent = Self::resolve_rename_memo(
                    edges,
                    rename_by_source,
                    &mut resolved,
                    &edge.dependent,
                );
                indexes
                    .by_resolved_dependent
                    .entry(dependent)
                    .or_default()
                    .push(index);
            }
        }
        indexes
    }

    fn cascade_kind(kind: &DependencyKind) -> bool {
        matches!(
            kind,
            DependencyKind::ViewDependency { .. }
                | DependencyKind::ViewUsesType
                | DependencyKind::IndexOnRelation { .. }
                | DependencyKind::ForeignKey { .. }
                | DependencyKind::InheritanceOf
                | DependencyKind::PartitionOf
                | DependencyKind::PartitionDetachPending
        )
    }

    fn cycle_kind(kind: &DependencyKind) -> bool {
        matches!(
            kind,
            DependencyKind::InheritanceOf
                | DependencyKind::PartitionOf
                | DependencyKind::PartitionDetachPending
        )
    }

    /// Resolve one endpoint for index construction, caching acyclic results.
    ///
    /// A rename cycle returns the original input, exactly as
    /// [`Self::resolve_rename_with`] does; cycle nodes are not cached because
    /// their answer depends on where traversal started.
    fn resolve_rename_memo(
        edges: &[DependencyEdge],
        rename_by_source: &HashMap<ObjectId, usize>,
        resolved: &mut HashMap<ObjectId, ObjectId>,
        id: &ObjectId,
    ) -> ObjectId {
        if let Some(cached) = resolved.get(id) {
            return cached.clone();
        }
        let Some(first) = rename_by_source.get(id) else {
            return id.clone();
        };

        let mut path = vec![id.clone()];
        let mut visited = HashSet::new();
        visited.insert(id.clone());
        let mut current = edges[*first].referenced.clone();
        loop {
            if let Some(cached) = resolved.get(&current).cloned() {
                for node in path {
                    resolved.insert(node, cached.clone());
                }
                return cached;
            }
            if !visited.insert(current.clone()) {
                return id.clone();
            }
            path.push(current.clone());
            match rename_by_source.get(&current) {
                Some(index) => current = edges[*index].referenced.clone(),
                None => {
                    for node in path {
                        resolved.insert(node, current.clone());
                    }
                    return current;
                }
            }
        }
    }

    pub(crate) fn edges_for_dependents<'a>(
        &'a self,
        dependents: &HashSet<ObjectId>,
    ) -> impl Iterator<Item = &'a DependencyEdge> {
        let indexes = self.dependent_index();
        let mut positions = dependents
            .iter()
            .flat_map(|id| indexes.get(id).into_iter().flatten().copied())
            .collect::<Vec<_>>();
        positions.sort_unstable();
        positions.dedup();
        positions.into_iter().map(|index| &self.edges[index])
    }

    fn resolve_rename_with<'a>(
        edges: &'a [DependencyEdge],
        rename_by_source: &HashMap<ObjectId, usize>,
        id: &'a ObjectId,
    ) -> &'a ObjectId {
        // Most catalog IDs have never been renamed; avoid the visited-set
        // allocation and walk entirely for them.
        if !rename_by_source.contains_key(id) {
            return id;
        }
        let mut current = id;
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(current.clone()) {
                return id;
            }
            match rename_by_source.get(current) {
                Some(index) => current = &edges[*index].referenced,
                None => return current,
            }
        }
    }

    fn resolved_referenced_edges(&self, id: &ObjectId) -> impl Iterator<Item = &DependencyEdge> {
        let target = self.resolve_rename(id);
        self.resolved_indexes()
            .by_resolved_referenced
            .get(target)
            .into_iter()
            .flatten()
            .map(|index| &self.edges[*index])
    }

    fn resolved_dependent_edges(&self, id: &ObjectId) -> impl Iterator<Item = &DependencyEdge> {
        let target = self.resolve_rename(id);
        self.resolved_indexes()
            .by_resolved_dependent
            .get(target)
            .into_iter()
            .flatten()
            .map(|index| &self.edges[*index])
    }

    pub(crate) fn cascade_edges(&self, id: &ObjectId) -> Vec<&DependencyEdge> {
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
                            | DependencyKind::PartitionDetachPending
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
                        | DependencyKind::PartitionDetachPending
                )
            })
            .collect()
    }

    pub(crate) fn cascade_index_is_worthwhile(&self) -> bool {
        self.edges.len() >= Self::CASCADE_INDEX_MIN_EDGES
    }

    // Dependency lookups follow the current end of a rename chain.
    #[cfg(test)]
    pub(crate) fn is_referenced_by_view(&self, id: &ObjectId) -> Vec<&ObjectId> {
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

    #[cfg(test)]
    pub(crate) fn is_referenced_by_fk(&self, id: &ObjectId) -> Vec<(&ObjectId, u64)> {
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

    #[cfg(test)]
    pub(crate) fn is_referenced_by_index(&self, id: &ObjectId) -> Vec<&ObjectId> {
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

    /// The table an index is defined on, if the graph records one.
    pub(crate) fn index_table_of(&self, index: &ObjectId) -> Option<&ObjectId> {
        let position = self
            .dependent_index()
            .get(index)?
            .iter()
            .copied()
            .find(|position| {
                matches!(
                    self.edges[*position].kind,
                    DependencyKind::IndexOnRelation { .. }
                )
            })?;
        Some(&self.edges[position].referenced)
    }

    /// The definition recorded for an index dependent, if any.
    pub(crate) fn index_definition_of(&self, id: &ObjectId) -> Option<&IndexDefinition> {
        let position = self
            .dependent_index()
            .get(id)?
            .iter()
            .copied()
            .find(|position| {
                matches!(
                    self.edges[*position].kind,
                    DependencyKind::IndexOnRelation { .. }
                )
            })?;
        match &self.edges[position].kind {
            DependencyKind::IndexOnRelation { definition, .. } => Some(definition),
            _ => None,
        }
    }

    /// The parent index a child index is attached to, if any.
    pub(crate) fn index_parent_of(&self, child: &ObjectId) -> Option<&ObjectId> {
        let position = self
            .dependent_index()
            .get(child)?
            .iter()
            .copied()
            .find(|position| {
                matches!(self.edges[*position].kind, DependencyKind::IndexPartitionOf)
            })?;
        Some(&self.edges[position].referenced)
    }

    /// The child indexes attached to `parent`, if any.
    pub(crate) fn index_partitions_of(&self, parent: &ObjectId) -> Vec<ObjectId> {
        let target = self.resolve_rename(parent);
        if let Some(positions) = self.index_partition_index().get(target) {
            return positions
                .iter()
                .map(|&idx| self.edges[idx].dependent.clone())
                .collect();
        }
        Vec::new()
    }

    /// Rewrite a recorded index definition in place.
    ///
    /// Only one edge payload changes, so the edge set and derived indexes are
    /// maintained incrementally instead of rebuilding both for the whole graph.
    pub(crate) fn update_index_definition(
        &mut self,
        index: &ObjectId,
        apply: impl FnOnce(&mut crate::_internal::model::index::IndexDefinition),
    ) {
        let position = self.dependent_index().get(index).and_then(|positions| {
            positions.iter().copied().find(|position| {
                matches!(
                    self.edges[*position].kind,
                    DependencyKind::IndexOnRelation { .. }
                )
            })
        });
        let Some(position) = position else {
            return;
        };
        let previous = self.edges[position].clone();
        let mut updated = previous.clone();
        let DependencyKind::IndexOnRelation { definition, .. } = &mut updated.kind else {
            unreachable!("position matched an IndexOnRelation edge");
        };
        apply(definition);
        self.edge_set.remove(&previous);
        if self.edge_set.insert(updated.clone()) {
            self.edges[position] = updated;
        } else {
            // The update collapsed two distinct edges into one. Keep the
            // earliest occurrence so the canonical order matches
            // deduplicate_edges().
            self.edges[position] = updated.clone();
            if let Some(duplicate) = self.edges.iter().enumerate().find_map(|(candidate, edge)| {
                (candidate != position && *edge == updated).then_some(candidate)
            }) {
                self.edges.remove(duplicate);
            }
            self.invalidate_indexes();
        }
    }

    // Index definitions cache resolved collation names, so collation moves and
    // schema renames must rewrite those keys alongside the catalogue.
    pub(crate) fn remap_index_collation(
        &mut self,
        old_schema: &str,
        old_name: &str,
        new_schema: &str,
        new_name: &str,
    ) {
        self.mutate_edges(|edges| {
            for edge in edges {
                let DependencyKind::IndexOnRelation { definition, .. } = &mut edge.kind else {
                    continue;
                };
                for key in definition.keys.iter_mut().chain(&mut definition.included) {
                    let KeyCollation::Resolved(resolved) = &mut key.collation else {
                        continue;
                    };
                    if resolved.schema == old_schema && resolved.name == old_name {
                        *resolved = ResolvedName {
                            schema: new_schema.to_string(),
                            name: new_name.to_string(),
                        };
                    }
                }
            }
        });
    }

    pub(crate) fn remap_index_collation_schema(&mut self, old_schema: &str, new_schema: &str) {
        self.mutate_edges(|edges| {
            for edge in edges {
                let DependencyKind::IndexOnRelation { definition, .. } = &mut edge.kind else {
                    continue;
                };
                for key in definition.keys.iter_mut().chain(&mut definition.included) {
                    let KeyCollation::Resolved(resolved) = &mut key.collation else {
                        continue;
                    };
                    if resolved.schema == old_schema {
                        resolved.schema = new_schema.to_string();
                    }
                }
            }
        });
    }

    pub(crate) fn partitions_of(&self, id: &ObjectId) -> Vec<&ObjectId> {
        if self.edges.len() >= Self::CASCADE_INDEX_MIN_EDGES {
            return self
                .resolved_referenced_edges(id)
                .filter(|edge| {
                    matches!(
                        edge.kind,
                        DependencyKind::PartitionOf | DependencyKind::PartitionDetachPending
                    )
                })
                .map(|edge| self.resolve_rename(&edge.dependent))
                .collect();
        }
        let target = self.resolve_rename(id);
        self.edges
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    DependencyKind::PartitionOf | DependencyKind::PartitionDetachPending
                ) && (self.resolve_rename(&e.referenced) == target || &e.referenced == id)
            })
            .map(|e| self.resolve_rename(&e.dependent))
            .collect()
    }

    /// Transitive partitions below `id`, including nested sub-partitions.
    pub(crate) fn partition_descendants(&self, id: &ObjectId) -> Vec<ObjectId> {
        let mut descendants = Vec::new();
        let mut queue = self
            .partitions_of(id)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        while let Some(child) = queue.pop() {
            if descendants.contains(&child) {
                continue;
            }
            queue.extend(self.partitions_of(&child).into_iter().cloned());
            descendants.push(child);
        }
        descendants
    }

    pub(crate) fn inheritance_children_of(&self, id: &ObjectId) -> Vec<&ObjectId> {
        if self.edges.len() >= Self::CASCADE_INDEX_MIN_EDGES {
            return self
                .resolved_referenced_edges(id)
                .filter(|edge| {
                    matches!(
                        edge.kind,
                        DependencyKind::InheritanceOf | DependencyKind::PartitionOf
                    )
                })
                .map(|edge| self.resolve_rename(&edge.dependent))
                .collect();
        }
        let target = self.resolve_rename(id);
        self.edges
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    DependencyKind::InheritanceOf | DependencyKind::PartitionOf
                ) && (self.resolve_rename(&e.referenced) == target || &e.referenced == id)
            })
            .map(|e| self.resolve_rename(&e.dependent))
            .collect()
    }

    pub(crate) fn inheritance_parents_of(&self, child: &ObjectId) -> Vec<&ObjectId> {
        if self.edges.len() >= Self::CASCADE_INDEX_MIN_EDGES {
            return self
                .resolved_dependent_edges(child)
                .filter(|edge| {
                    matches!(
                        edge.kind,
                        DependencyKind::InheritanceOf | DependencyKind::PartitionOf
                    )
                })
                .map(|edge| self.resolve_rename(&edge.referenced))
                .collect();
        }
        let target = self.resolve_rename(child);
        self.edges
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    DependencyKind::InheritanceOf | DependencyKind::PartitionOf
                ) && (self.resolve_rename(&e.dependent) == target || &e.dependent == child)
            })
            .map(|e| self.resolve_rename(&e.referenced))
            .collect()
    }

    pub(crate) fn resolve_rename<'a>(&'a self, id: &'a ObjectId) -> &'a ObjectId {
        // A rename back to an earlier name is valid PostgreSQL. The indexed
        // resolver retains the same cycle fallback while avoiding a full edge
        // scan for every dependency lookup on large baselines.
        Self::resolve_rename_with(&self.edges, self.rename_index(), id)
    }

    // Partition ancestry must remain acyclic.
    pub(crate) fn check_partition_cycle(&self, parent: &ObjectId, child: &ObjectId) -> bool {
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
            let maybe_edge = if self.edges.len() >= Self::CASCADE_INDEX_MIN_EDGES {
                self.resolved_dependent_edges(current_parent).find(|edge| {
                    matches!(
                        edge.kind,
                        DependencyKind::PartitionOf | DependencyKind::PartitionDetachPending
                    )
                })
            } else {
                self.edges.iter().find(|edge| {
                    matches!(
                        edge.kind,
                        DependencyKind::PartitionOf | DependencyKind::PartitionDetachPending
                    ) && self.resolve_rename(&edge.dependent) == current_parent
                })
            };
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

    /// Traditional inheritance has the same acyclicity requirement as a
    /// partition tree, but must not treat a partition-only edge as ordinary
    /// inheritance when callers validate `ALTER TABLE .. INHERIT`.
    pub(crate) fn check_inheritance_cycle(&self, parent: &ObjectId, child: &ObjectId) -> bool {
        let resolved_parent = self.resolve_rename(parent);
        let resolved_child = self.resolve_rename(child);
        if resolved_parent == resolved_child {
            return true;
        }

        let mut pending = vec![resolved_parent];
        let mut visited = HashSet::new();
        while let Some(current) = pending.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            if self.edges.len() >= Self::CASCADE_INDEX_MIN_EDGES {
                for edge in self
                    .resolved_dependent_edges(current)
                    .filter(|edge| matches!(edge.kind, DependencyKind::InheritanceOf))
                {
                    let ancestor = self.resolve_rename(&edge.referenced);
                    if ancestor == resolved_child {
                        return true;
                    }
                    pending.push(ancestor);
                }
            } else {
                for edge in self.edges.iter().filter(|edge| {
                    matches!(edge.kind, DependencyKind::InheritanceOf)
                        && self.resolve_rename(&edge.dependent) == current
                }) {
                    let ancestor = self.resolve_rename(&edge.referenced);
                    if ancestor == resolved_child {
                        return true;
                    }
                    pending.push(ancestor);
                }
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
                // The written name is schema-qualified too, so a rename that
                // leaves it stale makes a later drop miss this view.
                DependencyKind::ViewUsesRoutine {
                    unresolved_name: Some(name),
                }
                | DependencyKind::RoutineUsesRoutine {
                    unresolved_name: Some(name),
                } => {
                    remap(&mut edge.dependent);
                    remap(&mut edge.referenced);
                    remap(name);
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

    /// Apply every identity move in one pass.
    ///
    /// The typed match preserves the per-kind endpoint rules that a blind
    /// `ObjectId` replacement would break; the single deduplication keeps
    /// canonical edge order while avoiding one full rewrite per moved object.
    pub(crate) fn apply_rename_plan(&mut self, plan: &GraphRenamePlan) {
        let _ = self.apply_rename_plan_recorded(plan);
    }

    /// Apply a rename plan and return the minimal undo delta, or `None` when
    /// no edge changed.
    pub(crate) fn apply_rename_plan_recorded(
        &mut self,
        plan: &GraphRenamePlan,
    ) -> Option<GraphEdgeDelta> {
        let original_len = self.edges.len();
        let mut changed = Vec::new();
        for (index, edge) in self.edges.iter_mut().enumerate() {
            if !Self::may_change(edge, plan) {
                continue;
            }
            let original = edge.clone();
            if Self::apply_plan_to_edge(edge, plan) {
                changed.push((index, original));
            }
        }
        if changed.is_empty() {
            return None;
        }
        let removed = self.deduplicate_edges_recording(&changed);
        self.invalidate_indexes();
        Some(GraphEdgeDelta {
            original_len,
            changed,
            removed,
        })
    }

    /// Broad containment test used only to avoid cloning unaffected edges.
    fn may_change(edge: &DependencyEdge, plan: &GraphRenamePlan) -> bool {
        let hit = |map: &HashMap<ObjectId, ObjectId>, id: &ObjectId| map.contains_key(id);
        match &edge.kind {
            DependencyKind::RenameTo => false,
            DependencyKind::TriggerOnTable {
                trigger_id,
                function_id,
                ..
            } => {
                hit(&plan.relations, &edge.dependent)
                    || hit(&plan.relations, &edge.referenced)
                    || hit(&plan.triggers, &edge.dependent)
                    || hit(&plan.triggers, trigger_id)
                    || hit(&plan.routines, function_id)
            }
            _ => {
                hit(&plan.relations, &edge.dependent)
                    || hit(&plan.relations, &edge.referenced)
                    || hit(&plan.indexes, &edge.dependent)
                    || hit(&plan.indexes, &edge.referenced)
                    || hit(&plan.sequences, &edge.dependent)
                    || hit(&plan.sequences, &edge.referenced)
                    || hit(&plan.triggers, &edge.dependent)
                    || hit(&plan.triggers, &edge.referenced)
                    || hit(&plan.routines, &edge.dependent)
                    || hit(&plan.routines, &edge.referenced)
                    || hit(&plan.types, &edge.dependent)
                    || hit(&plan.types, &edge.referenced)
            }
        }
    }

    fn apply_plan_to_edge(edge: &mut DependencyEdge, plan: &GraphRenamePlan) -> bool {
        let mut changed = false;
        match &mut edge.kind {
            DependencyKind::RenameTo => {}
            // Index-to-index: a relation rename never moves an index, but an
            // index rename or schema move changes both endpoints.
            DependencyKind::IndexPartitionOf => {
                changed |= remap_endpoint(&mut edge.dependent, &plan.indexes);
                changed |= remap_endpoint(&mut edge.referenced, &plan.indexes);
            }
            DependencyKind::ForeignKey { .. }
            | DependencyKind::ViewDependency { .. }
            | DependencyKind::InheritanceOf
            | DependencyKind::PartitionOf
            | DependencyKind::PartitionDetachPending
            | DependencyKind::ConstraintDependency { .. }
            | DependencyKind::ColumnGeneratedFrom { .. } => {
                changed |= remap_endpoint(&mut edge.dependent, &plan.relations);
                changed |= remap_endpoint(&mut edge.referenced, &plan.relations);
            }
            // A view reference follows only on the dependent side: the
            // referenced routine or type may share the relation's name.
            DependencyKind::ViewUsesRoutine { unresolved_name } => {
                changed |= remap_endpoint(&mut edge.dependent, &plan.relations);
                if unresolved_name.is_none() {
                    changed |= remap_endpoint(&mut edge.referenced, &plan.routines);
                }
            }
            DependencyKind::ViewUsesType => {
                changed |= remap_endpoint(&mut edge.dependent, &plan.relations);
                changed |= remap_endpoint(&mut edge.referenced, &plan.types);
            }
            DependencyKind::RoutineUsesRoutine { unresolved_name } => {
                changed |= remap_endpoint(&mut edge.dependent, &plan.routines);
                if unresolved_name.is_none() {
                    changed |= remap_endpoint(&mut edge.referenced, &plan.routines);
                }
            }
            DependencyKind::RoutineUsesRelation { .. } => {
                changed |= remap_endpoint(&mut edge.dependent, &plan.routines);
                changed |= remap_endpoint(&mut edge.referenced, &plan.relations);
            }
            DependencyKind::RoutineUsesType => {
                changed |= remap_endpoint(&mut edge.dependent, &plan.routines);
                changed |= remap_endpoint(&mut edge.referenced, &plan.types);
            }
            DependencyKind::ColumnDefaultOnSequence { .. } => {
                changed |= remap_endpoint(&mut edge.dependent, &plan.relations);
                changed |= remap_endpoint(&mut edge.referenced, &plan.sequences);
            }
            DependencyKind::IndexOnRelation { .. } => {
                changed |= remap_endpoint(&mut edge.referenced, &plan.relations);
                changed |= remap_endpoint(&mut edge.dependent, &plan.indexes);
            }
            DependencyKind::SequenceOwnedBy { .. } => {
                changed |= remap_endpoint(&mut edge.referenced, &plan.relations);
                changed |= remap_endpoint(&mut edge.dependent, &plan.sequences);
            }
            DependencyKind::TriggerOnTable {
                trigger_id,
                function_id,
                ..
            } => {
                changed |= remap_endpoint(&mut edge.referenced, &plan.relations);
                changed |= remap_endpoint(&mut edge.dependent, &plan.triggers);
                changed |= remap_endpoint(trigger_id, &plan.triggers);
                changed |= remap_endpoint(function_id, &plan.routines);
            }
            DependencyKind::ConstraintOnRelation { .. } => {
                changed |= remap_endpoint(&mut edge.dependent, &plan.relations);
                changed |= remap_endpoint(&mut edge.referenced, &plan.relations);
            }
            DependencyKind::PublicationIncludes { .. } => {
                changed |= remap_endpoint(&mut edge.dependent, &plan.relations);
            }
        }
        changed
    }

    fn deduplicate_edges_recording(
        &mut self,
        changed: &[(usize, DependencyEdge)],
    ) -> Vec<(usize, DependencyEdge)> {
        // Fast path: if reinserting only the changed edges produces no duplicates,
        // we can avoid re-hashing and re-allocating the entire graph set.
        let mut had_collision = false;
        for (_, original) in changed {
            self.edge_set.remove(original);
        }
        for (index, _) in changed {
            if !self.edge_set.insert(self.edges[*index].clone()) {
                had_collision = true;
                break;
            }
        }

        if !had_collision {
            return Vec::new();
        }

        // Collision path: rebuild keeping the canonical first occurrences.
        let changed_map: HashMap<usize, DependencyEdge> = changed.iter().cloned().collect();
        let mut seen = HashSet::with_capacity(self.edges.len());
        let mut removed = Vec::new();
        let mut kept = Vec::with_capacity(self.edges.len());
        for (index, edge) in std::mem::take(&mut self.edges).into_iter().enumerate() {
            if seen.insert(edge.clone()) {
                kept.push(edge);
            } else {
                let original = changed_map
                    .get(&index)
                    .cloned()
                    .unwrap_or_else(|| edge.clone());
                removed.push((index, original));
            }
        }
        self.edges = kept;
        self.edge_set = seen;
        removed
    }

    /// Restore the edge vector captured by a rename delta.
    ///
    /// Untouched edges are consumed from the live vector in order; additions
    /// appended after the delta was recorded are dropped, so the accompanying
    /// length marker sees the pre-rename length.
    pub(crate) fn restore_edge_delta(&mut self, delta: GraphEdgeDelta) {
        let mut current = std::mem::take(&mut self.edges).into_iter();
        let mut changed = delta.changed.into_iter().collect::<HashMap<_, _>>();
        let mut removed = delta.removed.into_iter().collect::<HashMap<_, _>>();
        let mut restored = Vec::with_capacity(delta.original_len);
        for index in 0..delta.original_len {
            if let Some(edge) = removed.remove(&index) {
                restored.push(edge);
            } else {
                let edge = current
                    .next()
                    .expect("graph edge delta must match the live edge count");
                restored.push(changed.remove(&index).unwrap_or(edge));
            }
        }
        self.edges = restored;
        self.rebuild_edge_set();
        self.invalidate_indexes();
    }

    #[cfg(test)]
    pub(crate) fn propagate_relation_rename(&mut self, old_id: &ObjectId, new_id: &ObjectId) {
        let mut plan = GraphRenamePlan::default();
        plan.relations.insert(old_id.clone(), new_id.clone());
        self.apply_rename_plan(&plan);
    }

    /// Propagate a sequence rename through every typed sequence endpoint.
    /// Ownership uses the sequence as a dependent; a column default uses it
    /// as a referenced object. Both must follow the canonical identity.
    pub(crate) fn propagate_sequence_rename(&mut self, old_id: &ObjectId, new_id: &ObjectId) {
        let mut plan = GraphRenamePlan::default();
        plan.sequences.insert(old_id.clone(), new_id.clone());
        self.apply_rename_plan(&plan);
    }

    /// Propagate a trigger rename through its trigger edge and payload.
    pub(crate) fn propagate_trigger_rename(&mut self, old_id: &ObjectId, new_id: &ObjectId) {
        let mut plan = GraphRenamePlan::default();
        plan.triggers.insert(old_id.clone(), new_id.clone());
        self.apply_rename_plan(&plan);
    }

    /// Propagate a routine rename through its typed endpoints: trigger
    /// dependencies and resolved view references. A name-only view reference
    /// is the caller's decision, because only it can see the remaining
    /// overloads of the written name.
    pub(crate) fn propagate_function_rename(&mut self, old_id: &ObjectId, new_id: &ObjectId) {
        let mut plan = GraphRenamePlan::default();
        plan.routines.insert(old_id.clone(), new_id.clone());
        self.apply_rename_plan(&plan);
    }

    /// Whether any view references `name` without a resolved signature.
    pub(crate) fn has_view_reference_to_name(&self, name: &ObjectId) -> bool {
        self.edges.iter().any(|edge| {
            matches!(
                &edge.kind,
                DependencyKind::ViewUsesRoutine {
                    unresolved_name: Some(reference),
                }
                | DependencyKind::RoutineUsesRoutine {
                    unresolved_name: Some(reference),
                } if reference == name
            )
        })
    }

    /// Follow a name-only view reference to a moved name; the caller has
    /// established that every overload of the old name moved with it.
    pub(crate) fn propagate_view_reference_rename(
        &mut self,
        old_name: &ObjectId,
        new_name: &ObjectId,
    ) {
        for edge in &mut self.edges {
            match &mut edge.kind {
                DependencyKind::ViewUsesRoutine {
                    unresolved_name: Some(reference),
                }
                | DependencyKind::RoutineUsesRoutine {
                    unresolved_name: Some(reference),
                } if reference == old_name => {
                    *reference = new_name.clone();
                    edge.referenced = new_name.clone();
                }
                _ => {}
            }
        }
        self.deduplicate_edges();
        self.invalidate_indexes();
    }

    /// Rename a foreign-key constraint payload owned by a relation.
    pub(crate) fn rename_constraint(
        &mut self,
        table_id: &ObjectId,
        old_name: &str,
        new_name: &str,
    ) {
        let _ = self.rename_constraint_recorded(table_id, old_name, new_name);
    }

    pub(crate) fn rename_constraint_recorded(
        &mut self,
        table_id: &ObjectId,
        old_name: &str,
        new_name: &str,
    ) -> Option<GraphEdgeDelta> {
        let original_len = self.edges.len();
        let mut changed = Vec::new();
        for (index, edge) in self.edges.iter_mut().enumerate() {
            if edge.dependent != *table_id {
                continue;
            }
            let matches = match &edge.kind {
                DependencyKind::ForeignKey {
                    constraint_name: Some(name),
                    ..
                }
                | DependencyKind::ConstraintOnRelation {
                    constraint_name: name,
                    ..
                }
                | DependencyKind::ConstraintDependency {
                    constraint_name: name,
                    ..
                } => name == old_name,
                _ => false,
            };
            if !matches {
                continue;
            }
            let original = edge.clone();
            let name = match &mut edge.kind {
                DependencyKind::ForeignKey {
                    constraint_name: Some(name),
                    ..
                }
                | DependencyKind::ConstraintOnRelation {
                    constraint_name: name,
                    ..
                }
                | DependencyKind::ConstraintDependency {
                    constraint_name: name,
                    ..
                } => name,
                _ => unreachable!("constraint edge kind changed during rename"),
            };
            *name = new_name.to_string();
            changed.push((index, original));
        }
        if changed.is_empty() {
            return None;
        }
        let removed = self.deduplicate_edges_recording(&changed);
        self.invalidate_indexes();
        Some(GraphEdgeDelta {
            original_len,
            changed,
            removed,
        })
    }

    /// Rename table columns across multiple relations in a single recorded pass.
    pub(crate) fn rename_columns_for_relations_recorded(
        &mut self,
        table_ids: &HashSet<ObjectId>,
        old_name: &str,
        new_name: &str,
    ) -> Option<GraphEdgeDelta> {
        let original_len = self.edges.len();
        let mut changed = Vec::new();

        for index in 0..self.edges.len() {
            let edge = &self.edges[index];
            let needs_mutation = match &edge.kind {
                DependencyKind::ForeignKey {
                    from_columns,
                    to_columns,
                    ..
                } => {
                    (table_ids.contains(&edge.dependent)
                        && from_columns.iter().any(|c| c == old_name))
                        || (table_ids.contains(&edge.referenced)
                            && to_columns.iter().any(|c| c == old_name))
                }
                DependencyKind::ConstraintOnRelation { columns, .. }
                | DependencyKind::ConstraintDependency { columns, .. } => {
                    table_ids.contains(&edge.dependent) && columns.iter().any(|c| c == old_name)
                }
                DependencyKind::ColumnGeneratedFrom {
                    column,
                    depends_on_column,
                } => {
                    (table_ids.contains(&edge.dependent) && column == old_name)
                        || (table_ids.contains(&edge.referenced) && depends_on_column == old_name)
                }
                DependencyKind::ColumnDefaultOnSequence { column } => {
                    table_ids.contains(&edge.dependent) && column == old_name
                }
                DependencyKind::IndexOnRelation {
                    definition,
                    dependency_columns,
                    ..
                } => {
                    if !table_ids.contains(&edge.referenced) {
                        false
                    } else {
                        let in_keys = definition
                            .keys
                            .iter()
                            .chain(definition.included.iter())
                            .any(|key| match &key.kind {
                                crate::_internal::model::index::IndexKeyKind::Column(name) => {
                                    name == old_name
                                }
                                crate::_internal::model::index::IndexKeyKind::CatalogExpression(
                                    expr,
                                ) => expr
                                    .referenced_columns()
                                    .is_some_and(|cols| cols.contains(old_name)),
                                crate::_internal::model::index::IndexKeyKind::Expression(_) => {
                                    false
                                }
                            });
                        in_keys || dependency_columns.iter().any(|c| c == old_name)
                    }
                }
                DependencyKind::SequenceOwnedBy { column } => {
                    table_ids.contains(&edge.referenced) && column == old_name
                }
                DependencyKind::ViewDependency {
                    referenced_column: Some(column),
                    ..
                }
                | DependencyKind::RoutineUsesRelation {
                    referenced_column: Some(column),
                } => table_ids.contains(&edge.referenced) && column == old_name,
                _ => false,
            };

            if !needs_mutation {
                continue;
            }

            let original = self.edges[index].clone();
            let edge = &mut self.edges[index];

            match &mut edge.kind {
                DependencyKind::ForeignKey {
                    from_columns,
                    to_columns,
                    ..
                } => {
                    if table_ids.contains(&edge.dependent) {
                        for column in from_columns {
                            if column == old_name {
                                *column = new_name.to_string();
                            }
                        }
                    }
                    if table_ids.contains(&edge.referenced) {
                        for column in to_columns {
                            if column == old_name {
                                *column = new_name.to_string();
                            }
                        }
                    }
                }
                DependencyKind::ConstraintOnRelation { columns, .. }
                | DependencyKind::ConstraintDependency { columns, .. } => {
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
                    if table_ids.contains(&edge.dependent) && column == old_name {
                        *column = new_name.to_string();
                    }
                    if table_ids.contains(&edge.referenced) && depends_on_column == old_name {
                        *depends_on_column = new_name.to_string();
                    }
                }
                DependencyKind::ColumnDefaultOnSequence { column } => {
                    *column = new_name.to_string();
                }
                DependencyKind::IndexOnRelation {
                    definition,
                    dependency_columns,
                    ..
                } => {
                    for key in definition.keys.iter_mut().chain(&mut definition.included) {
                        match &mut key.kind {
                            crate::_internal::model::index::IndexKeyKind::Column(name) => {
                                if name == old_name {
                                    *name = new_name.to_string();
                                }
                            }
                            crate::_internal::model::index::IndexKeyKind::CatalogExpression(
                                expr,
                            ) => {
                                expr.rename_column(old_name, new_name);
                            }
                            crate::_internal::model::index::IndexKeyKind::Expression(_) => {}
                        }
                    }
                    for column in dependency_columns.iter_mut() {
                        if column == old_name {
                            *column = new_name.to_string();
                        }
                    }
                }
                DependencyKind::SequenceOwnedBy { column } => {
                    *column = new_name.to_string();
                }
                DependencyKind::ViewDependency {
                    referenced_column: Some(column),
                    ..
                }
                | DependencyKind::RoutineUsesRelation {
                    referenced_column: Some(column),
                } => {
                    *column = new_name.to_string();
                }
                _ => {}
            }

            changed.push((index, original));
        }

        if changed.is_empty() {
            return None;
        }

        let removed = self.deduplicate_edges_recording(&changed);
        self.invalidate_indexes();
        Some(GraphEdgeDelta {
            original_len,
            changed,
            removed,
        })
    }

    /// Rename a table column in all typed dependency payloads that can carry
    /// column identity. The endpoint direction determines whether the column
    /// is source-side or referenced-side for foreign keys.
    #[cfg(test)]
    pub(crate) fn rename_column_dependencies(
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
    pub(crate) fn rename_index_column(
        &mut self,
        table_id: &ObjectId,
        old_name: &str,
        new_name: &str,
    ) {
        self.mutate_edges(|edges| {
            for edge in edges {
                if edge.referenced != *table_id {
                    continue;
                }
                let DependencyKind::IndexOnRelation {
                    definition,
                    dependency_columns,
                    ..
                } = &mut edge.kind
                else {
                    continue;
                };
                let mut index_keys = Vec::new();
                for key in definition.keys.iter_mut().chain(&mut definition.included) {
                    match &mut key.kind {
                        crate::_internal::model::index::IndexKeyKind::Column(name) => {
                            index_keys.push(name);
                        }
                        crate::_internal::model::index::IndexKeyKind::CatalogExpression(expr) => {
                            expr.rename_column(old_name, new_name);
                        }
                        crate::_internal::model::index::IndexKeyKind::Expression(_) => {}
                    }
                }
                for column in index_keys.into_iter().chain(dependency_columns.iter_mut()) {
                    if column == old_name {
                        *column = new_name.to_string();
                    }
                }
            }
        });
    }

    /// Rename the owned column recorded on a sequence edge.
    pub(crate) fn rename_owned_sequence_column(
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
    pub(crate) fn rename_publication(&mut self, old_name: &str, new_name: &str) {
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

    /// Views that depend on a routine.
    ///
    /// A reference that resolved to an exact signature matches only that
    /// routine. One that could not be resolved matches every routine of that
    /// name, because the call may be any of its overloads.
    pub(crate) fn views_for_function(&self, function_id: &ObjectId) -> Vec<&DependencyEdge> {
        let (schema, signature) = Self::split_routine_signature(function_id);
        self.edges
            .iter()
            .filter(|edge| match &edge.kind {
                DependencyKind::ViewUsesRoutine { unresolved_name } => match unresolved_name {
                    None => &edge.referenced == function_id,
                    Some(name) => name.schema == schema && name.name == signature,
                },
                _ => false,
            })
            .collect()
    }

    /// The schema and bare name of a routine whose identity is `name(arguments)`.
    pub(crate) fn split_routine_signature(routine: &ObjectId) -> (&str, &str) {
        match routine.name.split_once('(') {
            Some((name, _)) => (routine.schema.as_str(), name),
            None => (routine.schema.as_str(), routine.name.as_str()),
        }
    }

    /// Views whose body casts to a type.
    pub(crate) fn views_for_type(&self, ty: &ObjectId) -> Vec<&DependencyEdge> {
        let target = self.resolve_rename(ty);
        if self.edges.len() >= Self::CASCADE_INDEX_MIN_EDGES {
            return self
                .resolved_referenced_edges(ty)
                .filter(|edge| matches!(edge.kind, DependencyKind::ViewUsesType))
                .collect();
        }
        self.edges
            .iter()
            .filter(|edge| {
                matches!(edge.kind, DependencyKind::ViewUsesType)
                    && (self.resolve_rename(&edge.referenced) == target || &edge.referenced == ty)
            })
            .collect()
    }

    pub(crate) fn routines_for_function(&self, function_id: &ObjectId) -> Vec<&DependencyEdge> {
        let (schema, signature) = Self::split_routine_signature(function_id);
        self.edges
            .iter()
            .filter(|edge| match &edge.kind {
                DependencyKind::RoutineUsesRoutine { unresolved_name } => match unresolved_name {
                    None => &edge.referenced == function_id,
                    Some(name) => name.schema == schema && name.name == signature,
                },
                _ => false,
            })
            .collect()
    }

    pub(crate) fn routines_for_type(&self, ty: &ObjectId) -> Vec<&DependencyEdge> {
        let target = self.resolve_rename(ty);
        self.edges
            .iter()
            .filter(|edge| {
                matches!(edge.kind, DependencyKind::RoutineUsesType)
                    && (self.resolve_rename(&edge.referenced) == target || &edge.referenced == ty)
            })
            .collect()
    }

    pub(crate) fn triggers_for_function(&self, function_id: &ObjectId) -> Vec<&DependencyEdge> {
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
#[path = "graph_tests.rs"]
mod tests;
