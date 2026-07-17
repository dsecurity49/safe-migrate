// FILE: src/db/cache.rs
use crate::ast::identifiers::ObjectId;
use crate::model::function::FunctionState;
use crate::model::relation::RelationState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignKeyCache {
    pub constraint_name: String,
    pub from_table: ObjectId,
    pub to_table: ObjectId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexCache {
    pub index_id: ObjectId,
    pub table_id: ObjectId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerCache {
    pub trigger_id: ObjectId,
    pub table_id: ObjectId,
    pub function_id: ObjectId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbCache {
    pub pg_version_num: Option<u32>,

    pub relations: HashMap<ObjectId, RelationState>,

    #[serde(default)]
    pub foreign_keys: Vec<ForeignKeyCache>,

    #[serde(default)]
    pub indexes: Vec<IndexCache>,

    #[serde(default)]
    pub triggers: Vec<TriggerCache>,

    #[serde(default)]
    pub functions: HashMap<ObjectId, FunctionState>,
}

pub const CACHE_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DbCacheVersioned {
    V1(DbCache),
}

impl Default for DbCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DbCache {
    pub fn new() -> Self {
        Self {
            pg_version_num: None,
            relations: HashMap::new(),
            foreign_keys: Vec::new(),
            indexes: Vec::new(),
            triggers: Vec::new(),
            functions: HashMap::new(),
        }
    }

    pub fn insert_baseline(&mut self, id: ObjectId, state: RelationState) {
        self.relations.insert(id, state);
    }

    pub fn baseline_relations(&self) -> impl Iterator<Item = (&ObjectId, &RelationState)> {
        self.relations.iter()
    }
}
