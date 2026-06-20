// FILE: src/db/cache.rs
use std::collections::HashMap;
use crate::ast::identifiers::ObjectId;
use crate::model::relation::RelationState;
use serde::{Serialize, Deserialize};

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
pub struct DbCache {
    pub pg_version_num: Option<u32>,
    
    // Tell Serde to convert the complex HashMap into a flat JSON array
    #[serde(with = "vectorize")]
    pub relations: HashMap<ObjectId, RelationState>,
    
    #[serde(default)]
    pub foreign_keys: Vec<ForeignKeyCache>,
    
    #[serde(default)]
    pub indexes: Vec<IndexCache>,
}

impl DbCache {
    pub fn new() -> Self {
        Self {
            pg_version_num: None,
            relations: HashMap::new(),
            foreign_keys: Vec::new(),
            indexes: Vec::new(),
        }
    }

    pub fn insert_baseline(&mut self, id: ObjectId, state: RelationState) {
        self.relations.insert(id, state);
    }

    pub fn baseline_relations(&self) -> impl Iterator<Item = (&ObjectId, &RelationState)> {
        self.relations.iter()
    }
}

// Helper module to let Serde handle Structs as HashMap Keys
mod vectorize {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;
    use std::hash::Hash;

    pub fn serialize<K, V, S>(map: &HashMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        K: Serialize,
        V: Serialize,
        S: Serializer,
    {
        let vec: Vec<(&K, &V)> = map.iter().collect();
        vec.serialize(serializer)
    }

    pub fn deserialize<'de, K, V, D>(deserializer: D) -> Result<HashMap<K, V>, D::Error>
    where
        K: Deserialize<'de> + Eq + Hash,
        V: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        let vec: Vec<(K, V)> = Vec::deserialize(deserializer)?;
        Ok(vec.into_iter().collect())
    }
}

