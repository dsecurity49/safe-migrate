use crate::analysis::graph::FkEdge;
use crate::model::relation::{ObjectId, RelationOverlay};

/// A single transaction or savepoint block.
#[derive(Debug, Clone)]
pub struct TransactionFrame {
    pub name: String,
    pub undo_log: Vec<StateChange>,
}

impl TransactionFrame {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            undo_log: Vec::new(),
        }
    }
}

/// The exact primitive needed to revert a state mutation.
#[derive(Debug, Clone)]
pub enum StateChange {
    /// Holds the exact state of a relation before it was mutated.
    /// If it didn't exist in the local overlay before, `previous` is None.
    RelationSnapshot {
        id: ObjectId,
        previous: Option<RelationOverlay>,
    },

    /// Holds the previous search path.
    SearchPathSnapshot {
        previous: Vec<String>,
    },

    /// Snapshot of the FK edge list before a graph mutation.
    /// On rollback, the entire foreign_keys vec is restored to this state.
    /// This is the correct fix for Bug 1 (graph leak on rollback):
    /// AddForeignKey pushes to the graph but rollback had no way to undo it.
    FkGraphSnapshot {
        previous: Vec<FkEdge>,
    },
}
