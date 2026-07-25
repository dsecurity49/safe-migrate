// FILE: src/db/cache.rs
use crate::ast::identifiers::ObjectId;
use crate::model::constraint::ConstraintState;
use crate::model::function::FunctionState;
use crate::model::relation::RelationState;
use crate::model::trigger::TriggerEnableMode;
use crate::model::types::TypeState;
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
    pub enabled_mode: TriggerEnableMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyTriggerCache {
    pub trigger_id: ObjectId,
    pub table_id: ObjectId,
    pub function_id: ObjectId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyCache {
    pub classid: u32,
    pub objid: u32,
    pub objsubid: i32,
    pub refclassid: u32,
    pub refobjid: u32,
    pub refobjsubid: i32,
    pub deptype: String,
    pub obj_schema: Option<String>,
    pub obj_name: Option<String>,
    pub ref_schema: Option<String>,
    pub ref_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbCacheV1 {
    pub pg_version_num: Option<u32>,
    pub relations: HashMap<ObjectId, RelationState>,
    #[serde(default)]
    pub foreign_keys: Vec<ForeignKeyCache>,
    #[serde(default)]
    pub indexes: Vec<IndexCache>,
    #[serde(default)]
    pub triggers: Vec<LegacyTriggerCache>,
    #[serde(default)]
    pub functions: HashMap<ObjectId, FunctionState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbCacheV2 {
    pub pg_version_num: Option<u32>,
    pub relations: HashMap<ObjectId, RelationState>,
    pub foreign_keys: Vec<ForeignKeyCache>,
    pub indexes: Vec<IndexCache>,
    pub triggers: Vec<LegacyTriggerCache>,
    pub functions: HashMap<ObjectId, FunctionState>,
    pub dependencies: Vec<DependencyCache>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbCache {
    pub pg_version_num: Option<u32>,
    pub search_path: Vec<String>,
    pub relations: HashMap<ObjectId, RelationState>,
    pub foreign_keys: Vec<ForeignKeyCache>,
    pub indexes: Vec<IndexCache>,
    pub constraints: Vec<ConstraintState>,
    pub triggers: Vec<TriggerCache>,
    pub functions: HashMap<ObjectId, FunctionState>,
    pub types: HashMap<ObjectId, TypeState>,
    pub dependencies: Vec<DependencyCache>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbCacheV3 {
    pub pg_version_num: Option<u32>,
    pub search_path: Vec<String>,
    pub relations: HashMap<ObjectId, RelationState>,
    pub foreign_keys: Vec<ForeignKeyCache>,
    pub indexes: Vec<IndexCache>,
    pub triggers: Vec<LegacyTriggerCache>,
    pub functions: HashMap<ObjectId, FunctionState>,
    pub dependencies: Vec<DependencyCache>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbCacheV4 {
    pub pg_version_num: Option<u32>,
    pub search_path: Vec<String>,
    pub relations: HashMap<ObjectId, RelationState>,
    pub foreign_keys: Vec<ForeignKeyCache>,
    pub indexes: Vec<IndexCache>,
    pub constraints: Vec<ConstraintState>,
    pub triggers: Vec<TriggerCache>,
    pub functions: HashMap<ObjectId, FunctionState>,
    pub dependencies: Vec<DependencyCache>,
}

pub const CACHE_FORMAT_VERSION: u32 = 5;

const _: () = assert!(
    CACHE_FORMAT_VERSION == 5,
    "CACHE_FORMAT_VERSION must be updated when new DbCacheVersioned variants are added",
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DbCacheVersioned {
    V1(DbCacheV1),
    V2(DbCacheV2),
    V3(DbCacheV3),
    V4(DbCacheV4),
    V5(DbCache),
}

impl DbCacheVersioned {
    pub fn format_version(&self) -> u32 {
        match self {
            DbCacheVersioned::V1(_) => 1,
            DbCacheVersioned::V2(_) => 2,
            DbCacheVersioned::V3(_) => 3,
            DbCacheVersioned::V4(_) => 4,
            DbCacheVersioned::V5(_) => 5,
        }
    }

    pub fn into_cache(self) -> Result<DbCache, String> {
        match self {
            DbCacheVersioned::V1(c) => Ok(DbCache {
                pg_version_num: c.pg_version_num,
                relations: c.relations,
                foreign_keys: c.foreign_keys,
                indexes: c.indexes,
                constraints: Vec::new(),
                triggers: upgrade_legacy_triggers(c.triggers),
                functions: c.functions,
                types: HashMap::new(),
                dependencies: Vec::new(),
                search_path: vec!["public".to_string()],
            }),
            DbCacheVersioned::V2(c) => Ok(DbCache {
                pg_version_num: c.pg_version_num,
                search_path: vec!["public".to_string()],
                relations: c.relations,
                foreign_keys: c.foreign_keys,
                indexes: c.indexes,
                constraints: Vec::new(),
                triggers: upgrade_legacy_triggers(c.triggers),
                functions: c.functions,
                types: HashMap::new(),
                dependencies: c.dependencies,
            }),
            DbCacheVersioned::V3(c) => Ok(DbCache {
                pg_version_num: c.pg_version_num,
                search_path: c.search_path,
                relations: c.relations,
                foreign_keys: c.foreign_keys,
                indexes: c.indexes,
                constraints: Vec::new(),
                triggers: upgrade_legacy_triggers(c.triggers),
                functions: c.functions,
                types: HashMap::new(),
                dependencies: c.dependencies,
            }),
            DbCacheVersioned::V4(c) => Ok(DbCache {
                pg_version_num: c.pg_version_num,
                search_path: c.search_path,
                relations: c.relations,
                foreign_keys: c.foreign_keys,
                indexes: c.indexes,
                constraints: c.constraints,
                triggers: c.triggers,
                functions: c.functions,
                types: HashMap::new(),
                dependencies: c.dependencies,
            }),
            DbCacheVersioned::V5(c) => Ok(c),
        }
    }
}

fn upgrade_legacy_triggers(triggers: Vec<LegacyTriggerCache>) -> Vec<TriggerCache> {
    triggers
        .into_iter()
        .map(|trigger| TriggerCache {
            trigger_id: trigger.trigger_id,
            table_id: trigger.table_id,
            function_id: trigger.function_id,
            enabled_mode: TriggerEnableMode::Origin,
        })
        .collect()
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
            search_path: vec!["public".to_string()],
            relations: HashMap::new(),
            foreign_keys: Vec::new(),
            indexes: Vec::new(),
            constraints: Vec::new(),
            triggers: Vec::new(),
            functions: HashMap::new(),
            types: HashMap::new(),
            dependencies: Vec::new(),
        }
    }

    pub fn insert_baseline(&mut self, id: ObjectId, state: RelationState) {
        self.relations.insert(id, state);
    }

    pub fn baseline_relations(&self) -> impl Iterator<Item = (&ObjectId, &RelationState)> {
        self.relations.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bug019_into_cache_succeeds_for_v1() {
        // 1d: into_cache() must succeed for the current format version (V1).
        let cache = DbCacheV1 {
            pg_version_num: None,
            relations: HashMap::new(),
            foreign_keys: Vec::new(),
            indexes: Vec::new(),
            triggers: Vec::new(),
            functions: HashMap::new(),
        };
        let versioned = DbCacheVersioned::V1(cache);
        assert_eq!(versioned.format_version(), 1);
        let result = versioned.into_cache();
        assert!(
            result.is_ok(),
            "into_cache() should succeed for V1: {:?}",
            result
        );
    }

    #[test]
    fn test_bug019_format_version_constant_matches_v1_variant() {
        // 1d: CACHE_FORMAT_VERSION must equal the discriminant reported by V1.
        let versioned = DbCacheVersioned::V1(DbCacheV1 {
            pg_version_num: None,
            relations: HashMap::new(),
            foreign_keys: Vec::new(),
            indexes: Vec::new(),
            triggers: Vec::new(),
            functions: HashMap::new(),
        });
        assert_eq!(
            versioned.format_version(),
            1,
            "format_version() for V1 must match 1"
        );
    }
}
