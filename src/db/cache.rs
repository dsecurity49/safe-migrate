// src/db/cache.rs
use crate::model::relation::{ObjectId, RelationState};
use std::collections::HashMap;

/// A read-only representation of the target database's state *before*
/// the migration begins.
///
/// INVARIANT: This cache is NEVER mutated by the rules or the apply phase.
/// It is populated once at startup (from a live database or test fixtures)
/// and then only read.
#[derive(Debug, Clone)]
pub struct DbCache {
    relations: HashMap<ObjectId, RelationState>,
}

impl DbCache {
    pub fn new() -> Self {
        Self {
            relations: HashMap::new(),
        }
    }

    pub fn get_relation(&self, id: &ObjectId) -> Option<&RelationState> {
        self.relations.get(id)
    }

    /// Insert a baseline relation into the cache.
    ///
    /// Used by tests and by the database introspection layer (future) to
    /// populate the pre-migration schema snapshot.
    pub fn insert(&mut self, state: RelationState) {
        self.relations.insert(state.id.clone(), state);
    }

    /// Iterate all baseline relations.
    ///
    /// Bug 2 fix: used by AnalysisState::new() to seed LocalState so rules
    /// see pre-existing tables without requiring a separate DbCache lookup
    /// path inside every rule. The previous design left DbCache permanently
    /// invisible to get_relation() — any object that existed only in the
    /// cache was never found by rules or state lookups.
    pub fn baseline_relations(&self) -> impl Iterator<Item = (&ObjectId, &RelationState)> {
        self.relations.iter()
    }
}
