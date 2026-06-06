use std::collections::HashMap;
use crate::db::cache::DbCache;
use crate::model::relation::{ObjectId, RelationOverlay};
use crate::analysis::graph::DependencyGraph;
use crate::analysis::transaction::TransactionFrame;
use crate::analysis::mutations::Mutation;

/// Indicates the engine's certainty about the current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confidence {
    Exact,
    Tainted,
}

#[derive(Debug, Clone)]
pub struct LocalState {
    pub relations: HashMap<ObjectId, RelationOverlay>,
    pub graph: DependencyGraph,
    pub search_path: Vec<String>,
    pub confidence: Confidence,
    pub transactions: Vec<TransactionFrame>,
}

impl LocalState {
    pub fn new() -> Self {
        Self {
            relations: HashMap::new(),
            graph: DependencyGraph::new(),
            search_path: vec!["public".to_string()],
            confidence: Confidence::Exact,
            transactions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnalysisState {
    pub cache: DbCache,
    pub local: LocalState,
}

impl AnalysisState {
    pub fn new(cache: DbCache) -> Self {
        Self {
            cache,
            local: LocalState::new(),
        }
    }
    pub fn apply(&mut self, mutation: &Mutation) {
        match mutation {
            Mutation::DropTable { id } => {
                // THE TOMBSTONE RULE: Never delete, only shadow.
                self.local.relations.insert(id.clone(), RelationOverlay::Dropped);
            }
            // Future mutations (CreateTable, AlterTable) will be handled here
            _ => {}
        }
    }
}
