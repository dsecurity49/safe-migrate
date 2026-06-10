use crate::analysis::graph::IndexEdge;
use crate::model::relation::{ObjectId, RelationOverlay};

/// A single transaction or savepoint block.
#[derive(Debug, Clone)]
pub struct TransactionFrame {
    pub name: String,
    pub undo_log: Vec<StateChange>,
}

impl TransactionFrame {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), undo_log: Vec::new() }
    }
}

/// The exact primitive needed to revert a state mutation.
#[derive(Debug, Clone)]
pub enum StateChange {
    /// Snapshot of a relation's state before mutation.
    RelationSnapshot {
        id: ObjectId,
        previous: Option<RelationOverlay>,
    },

    /// Snapshot of the search path before mutation.
    SearchPathSnapshot {
        previous: Vec<String>,
    },

    /// Length marker for the FK edge list before a mutation.
    ///
    /// On rollback we truncate foreign_keys to this length — O(1) snapshot,
    /// O(k) rollback where k = edges added since snapshot. This avoids the
    /// O(N) clone-entire-vec pattern.
    ///
    /// Invariant: edges are always appended, never reordered. Truncation is
    /// correct because rollback only needs to remove the most-recently-added
    /// edges, which are always at the tail.
    FkGraphLengthMarker {
        len: usize,
    },

    /// Length marker for the view edge list before a mutation.
    /// Same O(1) pattern as FkGraphLengthMarker.
    ViewGraphLengthMarker {
        len: usize,
    },

    /// Length marker for the index edge list before a CreateIndex mutation.
    /// CreateIndex appends, so the append-only invariant holds and truncation
    /// is safe here.
    ///
    /// NOT used for DropIndex — see IndexGraphSnapshot below.
    IndexGraphLengthMarker {
        len: usize,
    },

    /// Bug 5 fix: length marker for the rename edge list.
    ///
    /// Mutation::Rename appends to graph.renames; on rollback we truncate back
    /// to the pre-rename length. Same O(1)/O(k) pattern as FkGraphLengthMarker.
    ///
    /// Previously missing: Mutation::Rename pushed a RenameEdge inside a
    /// transaction but never recorded an undo entry, so ROLLBACK left phantom
    /// rename edges in graph.renames.
    RenameGraphLengthMarker {
        len: usize,
    },

    /// Bug 6 fix: full snapshot of the index list, taken before DropIndex.
    ///
    /// DropIndex uses retain() which removes an element from an arbitrary
    /// position in the list. This breaks the append-only invariant required
    /// by the length-marker pattern — truncate() can only remove tail elements.
    ///
    /// A full clone is the correct approach here:
    ///   - DROP INDEX is rare in migrations.
    ///   - Index lists are small (tens of entries at most).
    ///   - Correctness of rollback outweighs the O(N) clone cost.
    IndexGraphSnapshot {
        previous: Vec<IndexEdge>,
    },
}
