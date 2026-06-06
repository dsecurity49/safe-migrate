use std::collections::HashMap;
use crate::db::cache::DbCache;
use crate::model::relation::{ObjectId, RelationOverlay};
use crate::analysis::graph::DependencyGraph;
use crate::analysis::transaction::TransactionFrame;
use crate::analysis::mutations::Mutation;
use crate::model::relation::RelationState;
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
            Mutation::CreateTable { id } => {
                self.local.relations.insert(
                    id.clone(),
                    RelationOverlay::Present(RelationState {
                        id: id.clone(),
                        columns: vec![],
                    }),
                );
            }
            Mutation::DropTable { id } => {
                self.local.relations.insert(id.clone(), RelationOverlay::Dropped);
            }
            _ => {}
        }
    }
    pub fn get_relation(&self, id: &ObjectId) -> Option<&RelationState> {
        match self.local.relations.get(id) {
            Some(RelationOverlay::Present(state)) => Some(state),
            Some(RelationOverlay::Dropped) => None,
            None => self.cache.get_relation(id),
        }
    }
}

