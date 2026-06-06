// src/db/cache.rs
use crate::model::relation::{ObjectId, RelationState};
use std::collections::HashMap;

/// A read-only representation of the target database's state *before* /// the migration begins.
/// 
/// INVARIANT: This cache is NEVER mutated by the rules or the apply phase.
#[derive(Debug, Clone)]
pub struct DbCache {
    /// Baseline tables, views, etc.
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

    // Future: Add methods to populate this cache via a live PostgreSQL connection.
}
