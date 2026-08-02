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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CacheMetadata {
    /// Seconds since the Unix epoch when `safe-migrate sync` assembled this
    /// baseline. `None` represents a cache written before provenance support.
    pub created_at_unix_secs: Option<u64>,
    /// PostgreSQL database name only; connection credentials and host details
    /// are deliberately never stored in a cache.
    pub source_database: Option<String>,
    /// Session role used when the cache was synchronized. This is needed to
    /// resolve PostgreSQL's special `$user` search-path entry.
    pub source_role: Option<String>,
    /// Explicit schema scope passed to sync. `None` means all non-system
    /// schemas were requested.
    pub schemas: Option<Vec<String>>,
}

/// Metadata layout written by cache V3. Keep this byte-for-byte stable so V3
/// remains readable after the current cache schema evolves.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CacheMetadataV3 {
    pub created_at_unix_secs: Option<u64>,
    pub source_database: Option<String>,
    pub schemas: Option<Vec<String>>,
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

/// Cache layout written by safe-migrate v0.4.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbCacheV3 {
    pub pg_version_num: Option<u32>,
    pub metadata: CacheMetadataV3,
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
pub struct DbCache {
    pub pg_version_num: Option<u32>,
    pub metadata: CacheMetadata,
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

pub const CACHE_FORMAT_VERSION: u32 = 4;

/// Prefixes every V3 payload after zstd decompression. Older caches did not
/// have a payload header, so this prevents their bincode V3 discriminator from
/// being mistaken for the redesigned V3 schema.
pub const CACHE_V3_MAGIC: &[u8] = b"SMCACHE03";
pub const CACHE_V4_MAGIC: &[u8] = b"SMCACHE04";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DbCacheVersioned {
    V1(DbCacheV1),
    V2(DbCacheV2),
    V3(DbCacheV3),
    V4(DbCache),
}

impl DbCacheVersioned {
    pub fn format_version(&self) -> u32 {
        match self {
            DbCacheVersioned::V1(_) => 1,
            DbCacheVersioned::V2(_) => 2,
            DbCacheVersioned::V3(_) => 3,
            DbCacheVersioned::V4(_) => 4,
        }
    }

    pub fn into_cache(self) -> Result<DbCache, String> {
        match self {
            DbCacheVersioned::V1(_) | DbCacheVersioned::V2(_) => Err(
                "This cache format is unsupported. Run `safe-migrate sync` to rebuild it."
                    .to_string(),
            ),
            DbCacheVersioned::V3(c) => Ok(c.into()),
            DbCacheVersioned::V4(c) => Ok(c),
        }
    }
}

impl From<DbCacheV3> for DbCache {
    fn from(cache: DbCacheV3) -> Self {
        Self {
            pg_version_num: cache.pg_version_num,
            metadata: CacheMetadata {
                created_at_unix_secs: cache.metadata.created_at_unix_secs,
                source_database: cache.metadata.source_database,
                source_role: None,
                schemas: cache.metadata.schemas,
            },
            search_path: cache.search_path,
            relations: cache.relations,
            foreign_keys: cache.foreign_keys,
            indexes: cache.indexes,
            constraints: cache.constraints,
            triggers: cache.triggers,
            functions: cache.functions,
            types: cache.types,
            dependencies: cache.dependencies,
        }
    }
}

impl From<DbCache> for DbCacheV3 {
    fn from(cache: DbCache) -> Self {
        Self {
            pg_version_num: cache.pg_version_num,
            metadata: CacheMetadataV3 {
                created_at_unix_secs: cache.metadata.created_at_unix_secs,
                source_database: cache.metadata.source_database,
                schemas: cache.metadata.schemas,
            },
            search_path: cache.search_path,
            relations: cache.relations,
            foreign_keys: cache.foreign_keys,
            indexes: cache.indexes,
            constraints: cache.constraints,
            triggers: cache.triggers,
            functions: cache.functions,
            types: cache.types,
            dependencies: cache.dependencies,
        }
    }
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
            metadata: CacheMetadata::default(),
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
    fn legacy_v1_cache_is_rejected() {
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
        assert_eq!(
            result.unwrap_err(),
            "This cache format is unsupported. Run `safe-migrate sync` to rebuild it."
        );
    }

    #[test]
    fn current_cache_format_is_v4() {
        assert_eq!(CACHE_FORMAT_VERSION, 4);
        assert_eq!(DbCacheVersioned::V4(DbCache::new()).format_version(), 4);
        assert_eq!(CACHE_V3_MAGIC, b"SMCACHE03");
        assert_eq!(CACHE_V4_MAGIC, b"SMCACHE04");
    }

    #[test]
    fn v3_cache_remains_readable_without_inventing_a_source_role() {
        let v3 = DbCacheV3::from(DbCache::new());
        let cache = DbCacheVersioned::V3(v3).into_cache().unwrap();
        assert_eq!(cache.metadata.source_role, None);
    }
}
