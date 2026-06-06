// src/analysis/transaction.rs
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
/// (Expanding slightly on the Blueprint to hold the actual prior state).
#[derive(Debug, Clone)]
pub enum StateChange {
    /// Holds the exact state of a relation *before* it was mutated.
    /// If it didn't exist in the local overlay before, `previous` is None.
    RelationSnapshot {
        id: ObjectId,
        previous: Option<RelationOverlay>,
    },
    
    /// Holds the previous search path
    SearchPathSnapshot {
        previous: Vec<String>,
    },
    
    // Future: GraphSnapshot, ConfidenceSnapshot
}
