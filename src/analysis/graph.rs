use crate::model::relation::ObjectId;

// ─────────────────────────────────────────────
// Edge types — one struct per dependency kind.
// Each edge is immutable once inserted; the graph
// grows monotonically during forward simulation.
// Rollback removes edges via the undo log in
// TransactionFrame, not by mutating the graph
// directly.
// ─────────────────────────────────────────────

/// A foreign key relationship between two tables.
#[derive(Debug, Clone, PartialEq)]
pub struct FkEdge {
    pub from_table: ObjectId,
    pub from_columns: Vec<String>,
    pub to_table: ObjectId,
    pub to_columns: Vec<String>,
    /// Generation of from_table when this edge was created.
    /// Used to filter ABA phantom edges.
    pub from_generation: u64,
}

/// A view's dependency on one or more base tables or other views.
#[derive(Debug, Clone, PartialEq)]
pub struct ViewEdge {
    pub view_id: ObjectId,
    pub depends_on: Vec<ObjectId>,
    /// Generation of the view when this edge was created.
    pub view_generation: u64,
}

/// An index's dependency on its parent table.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexEdge {
    pub index_id: ObjectId,
    pub relation_id: ObjectId,
}

/// A rename operation — tracks old → new identity so downstream
/// references can be resolved after a RENAME TO.
#[derive(Debug, Clone, PartialEq)]
pub struct RenameEdge {
    pub from: ObjectId,
    pub to: ObjectId,
}

/// A partition's parent → child relationship.
#[derive(Debug, Clone, PartialEq)]
pub struct PartitionEdge {
    pub parent: ObjectId,
    pub child: ObjectId,
}

// ─────────────────────────────────────────────
// DependencyGraph — the full live dependency
// surface of the schema at the current simulation
// point. Populated by state.apply() and queried
// read-only by the rule engine.
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct DependencyGraph {
    pub foreign_keys: Vec<FkEdge>,
    pub views: Vec<ViewEdge>,
    pub indexes: Vec<IndexEdge>,
    pub renames: Vec<RenameEdge>,
    pub partitions: Vec<PartitionEdge>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Query helpers (read-only, used by rules) ──────────────────────

    /// Returns the IDs of all views that depend on `id`, filtered by generation.
    /// Only edges whose view_generation matches the current view's generation
    /// are returned — prevents ABA phantom view dependencies.
    pub fn is_referenced_by_view(&self, id: &ObjectId) -> Vec<&ObjectId> {
        self.views
            .iter()
            .filter(|v| v.depends_on.contains(id))
            .map(|v| &v.view_id)
            .collect()
    }

    /// Returns the IDs of all tables that reference `id` via a foreign key,
    /// filtered by from_generation to prevent ABA phantom FK dependencies.
    pub fn is_referenced_by_fk(&self, id: &ObjectId) -> Vec<(&ObjectId, u64)> {
        self.foreign_keys
            .iter()
            .filter(|fk| &fk.to_table == id)
            .map(|fk| (&fk.from_table, fk.from_generation))
            .collect()
    }

    /// Returns the IDs of all indexes that depend on `id`.
    pub fn is_referenced_by_index(&self, id: &ObjectId) -> Vec<&ObjectId> {
        self.indexes
            .iter()
            .filter(|ix| &ix.relation_id == id)
            .map(|ix| &ix.index_id)
            .collect()
    }

    /// Returns the IDs of all child partitions of `id`.
    pub fn partitions_of(&self, id: &ObjectId) -> Vec<&ObjectId> {
        self.partitions
            .iter()
            .filter(|p| &p.parent == id)
            .map(|p| &p.child)
            .collect()
    }

    /// Resolves the current canonical identity of `id` after any renames.
    /// Walks the rename chain until no further rename is found.
    pub fn resolve_rename<'a>(&'a self, id: &'a ObjectId) -> &'a ObjectId {
        let mut current = id;
        loop {
            match self.renames.iter().find(|r| &r.from == current) {
                Some(edge) => current = &edge.to,
                None => return current,
            }
        }
    }
}
