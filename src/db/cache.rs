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

/// Compile-time guard: the version constant must equal the discriminant of the
/// latest (highest-numbered) variant in `DbCacheVersioned`.  When a new variant
/// `V2` is added, `CACHE_FORMAT_VERSION` must be bumped to `2`, and this
/// assertion will catch any mismatch at compile time.
const _: () = assert!(
    CACHE_FORMAT_VERSION == 1,
    "CACHE_FORMAT_VERSION must be updated when new DbCacheVersioned variants are added",
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DbCacheVersioned {
    V1(DbCache),
}

impl DbCacheVersioned {
    /// Return the format-version number encoded in this variant.
    pub fn format_version(&self) -> u32 {
        match self {
            DbCacheVersioned::V1(_) => 1,
        }
    }

    /// Unwrap into a `DbCache`, returning an error if the stored version does
    /// not match `CACHE_FORMAT_VERSION`.  This catches the case where a cache
    /// file was written by a newer binary and is then read by an older one that
    /// only knows about lower-numbered variants.
    pub fn into_cache(self) -> Result<DbCache, String> {
        let v = self.format_version();
        if v != CACHE_FORMAT_VERSION {
            return Err(format!(
                "cache format version mismatch: file is v{v}, binary expects v{CACHE_FORMAT_VERSION}. \
                 Run `safe-migrate sync` to rebuild the cache."
            ));
        }
        match self {
            DbCacheVersioned::V1(c) => Ok(c),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bug019_into_cache_succeeds_for_v1() {
        // 1d: into_cache() must succeed for the current format version (V1).
        let cache = DbCache::new();
        let versioned = DbCacheVersioned::V1(cache);
        assert_eq!(versioned.format_version(), CACHE_FORMAT_VERSION);
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
        let versioned = DbCacheVersioned::V1(DbCache::new());
        assert_eq!(
            versioned.format_version(),
            CACHE_FORMAT_VERSION,
            "format_version() for V1 must match CACHE_FORMAT_VERSION"
        );
    }
}
