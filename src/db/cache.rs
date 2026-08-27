use crate::ast::identifiers::ObjectId;
use crate::model::constraint::ConstraintState;
use crate::model::function::FunctionState;
use crate::model::relation::RelationState;
use crate::model::replication::{PublicationState, SubscriptionState};
use crate::model::role::RoleState;
use crate::model::schema::SchemaState;
use crate::model::sequence::SequenceState;
use crate::model::trigger::TriggerEnableMode;
use crate::model::types::TypeState;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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
    /// `SESSION_USER` at synchronization time. This remains distinct from
    /// `source_role` when the connection has selected another effective role.
    pub source_session_role: Option<String>,
    /// Parsed `search_path` setting before PostgreSQL expands `$user`.
    pub source_search_path: Option<Vec<String>>,
    /// Effective `lock_timeout` observed on the fresh synchronization
    /// connection, normalized to milliseconds. PostgreSQL uses zero to mean
    /// that the timeout is disabled.
    pub source_lock_timeout_ms: u64,
    /// Effective `statement_timeout` observed on the fresh synchronization
    /// connection, normalized to milliseconds. PostgreSQL uses zero to mean
    /// that the timeout is disabled.
    pub source_statement_timeout_ms: u64,
    /// Explicit schema scope passed to sync. `None` means all non-system
    /// schemas were requested.
    pub schemas: Option<Vec<String>>,
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
    pub roles: HashMap<ObjectId, RoleState>,
    pub schemas: HashMap<String, SchemaState>,
    pub sequences: HashMap<ObjectId, SequenceState>,
    pub dependencies: Vec<DependencyCache>,
    pub publications: HashMap<String, PublicationState>,
    pub subscriptions: HashMap<String, SubscriptionState>,
}

pub const CACHE_FORMAT_VERSION: u32 = 6;

pub const CACHE_V6_MAGIC: &[u8] = b"SMCACHE06";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DbCacheVersioned {
    // Unit variants reserve the historic bincode discriminants. The reader
    // rejects non-V6 headers before decoding, so legacy layouts are not part
    // of the production model and cannot be converted accidentally.
    V1,
    V2,
    V3,
    V4,
    V5(Box<DbCache>),
    V6(Box<DbCache>),
}

impl DbCacheVersioned {
    pub fn format_version(&self) -> u32 {
        match self {
            DbCacheVersioned::V1 => 1,
            DbCacheVersioned::V2 => 2,
            DbCacheVersioned::V3 => 3,
            DbCacheVersioned::V4 => 4,
            DbCacheVersioned::V5(_) => 5,
            DbCacheVersioned::V6(_) => 6,
        }
    }

    pub fn into_cache(self) -> Result<DbCache, String> {
        match self {
            DbCacheVersioned::V1
            | DbCacheVersioned::V2
            | DbCacheVersioned::V3
            | DbCacheVersioned::V4
            | DbCacheVersioned::V5(_) => Err(
                "This cache format is unsupported. Run `safe-migrate sync` to rebuild it."
                    .to_string(),
            ),
            DbCacheVersioned::V6(c) => {
                c.validate_semantics()?;
                Ok(*c)
            }
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
            roles: HashMap::new(),
            schemas: HashMap::new(),
            sequences: HashMap::new(),
            dependencies: Vec::new(),
            publications: HashMap::new(),
            subscriptions: HashMap::new(),
        }
    }

    pub fn insert_baseline(&mut self, id: ObjectId, state: RelationState) {
        self.relations.insert(id, state);
    }

    pub fn baseline_relations(&self) -> impl Iterator<Item = (&ObjectId, &RelationState)> {
        self.relations.iter()
    }

    pub(crate) fn validate_semantics(&self) -> Result<(), String> {
        for (id, relation) in &self.relations {
            if id != &relation.id {
                return Err(format!(
                    "relation cache key '{}' disagrees with embedded identity '{}'",
                    id, relation.id
                ));
            }
        }
        for (id, function) in &self.functions {
            if id != &function.id {
                return Err(format!(
                    "routine cache key '{}' disagrees with embedded identity '{}'",
                    id, function.id
                ));
            }
        }
        for (id, ty) in &self.types {
            if id != &ty.id {
                return Err(format!(
                    "type cache key '{}' disagrees with embedded identity '{}'",
                    id, ty.id
                ));
            }
        }
        for (id, role) in &self.roles {
            if id != &role.id {
                return Err(format!(
                    "role cache key '{}' disagrees with embedded identity '{}'",
                    id, role.id
                ));
            }
        }
        for (name, schema) in &self.schemas {
            if name != &schema.name {
                return Err(format!(
                    "schema cache key '{}' disagrees with embedded identity '{}'",
                    name, schema.name
                ));
            }
        }
        for (id, sequence) in &self.sequences {
            if id != &sequence.id {
                return Err(format!(
                    "sequence cache key '{}' disagrees with embedded identity '{}'",
                    id, sequence.id
                ));
            }
        }
        for (name, publication) in &self.publications {
            if name != &publication.name {
                return Err(format!(
                    "publication cache key '{}' disagrees with embedded identity '{}'",
                    name, publication.name
                ));
            }
        }
        for (name, subscription) in &self.subscriptions {
            if name != &subscription.name {
                return Err(format!(
                    "subscription cache key '{}' disagrees with embedded identity '{}'",
                    name, subscription.name
                ));
            }
        }

        let mut constraint_keys = HashSet::new();
        for constraint in &self.constraints {
            if !self.relations.contains_key(&constraint.table_id) {
                return Err(format!(
                    "constraint '{}.{}' references a missing relation",
                    constraint.table_id, constraint.name
                ));
            }
            if !constraint_keys.insert((constraint.table_id.clone(), constraint.name.clone())) {
                return Err(format!(
                    "constraint '{}.{}' appears more than once",
                    constraint.table_id, constraint.name
                ));
            }
        }

        let mut index_ids = HashSet::new();
        for index in &self.indexes {
            if !self.relations.contains_key(&index.table_id) {
                return Err(format!(
                    "index '{}' references missing relation '{}'",
                    index.index_id, index.table_id
                ));
            }
            if !index_ids.insert(index.index_id.clone()) {
                return Err(format!("index '{}' appears more than once", index.index_id));
            }
        }

        let mut trigger_ids = HashSet::new();
        for trigger in &self.triggers {
            if !self.relations.contains_key(&trigger.table_id) {
                return Err(format!(
                    "trigger '{}' references missing relation '{}'",
                    trigger.trigger_id, trigger.table_id
                ));
            }
            if !trigger_ids.insert(trigger.trigger_id.clone()) {
                return Err(format!(
                    "trigger '{}' appears more than once",
                    trigger.trigger_id
                ));
            }
        }

        let mut foreign_key_ids = HashSet::new();
        for foreign_key in &self.foreign_keys {
            if !self.relations.contains_key(&foreign_key.from_table)
                || !self.relations.contains_key(&foreign_key.to_table)
            {
                return Err(format!(
                    "foreign key '{}.{}' references a missing relation",
                    foreign_key.from_table, foreign_key.constraint_name
                ));
            }
            if !foreign_key_ids.insert((
                foreign_key.from_table.clone(),
                foreign_key.constraint_name.clone(),
            )) {
                return Err(format!(
                    "foreign key '{}.{}' appears more than once",
                    foreign_key.from_table, foreign_key.constraint_name
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_legacy_cache_variant_is_rejected_generically() {
        for (versioned, expected_version) in [
            (DbCacheVersioned::V1, 1),
            (DbCacheVersioned::V2, 2),
            (DbCacheVersioned::V3, 3),
            (DbCacheVersioned::V4, 4),
        ] {
            assert_eq!(versioned.format_version(), expected_version);
            assert_eq!(
                versioned.into_cache().unwrap_err(),
                "This cache format is unsupported. Run `safe-migrate sync` to rebuild it."
            );
        }
        let v5 = DbCacheVersioned::V5(Box::default());
        assert_eq!(v5.format_version(), 5);
        assert_eq!(
            v5.into_cache().unwrap_err(),
            "This cache format is unsupported. Run `safe-migrate sync` to rebuild it."
        );
    }

    #[test]
    fn current_cache_format_is_v6() {
        assert_eq!(CACHE_FORMAT_VERSION, 6);
        assert_eq!(DbCacheVersioned::V6(Box::default()).format_version(), 6);
        assert_eq!(CACHE_V6_MAGIC, b"SMCACHE06");
    }

    #[test]
    fn current_cache_rejects_mismatched_embedded_identity() {
        let mut cache = DbCache::new();
        cache.schemas.insert(
            "app".to_string(),
            SchemaState {
                name: "other".to_string(),
                owner: ObjectId::new("", "postgres"),
                generation: 0,
            },
        );

        let error = DbCacheVersioned::V6(Box::new(cache))
            .into_cache()
            .unwrap_err();
        assert!(error.contains("schema cache key 'app'"));
    }

    #[test]
    fn current_cache_rejects_dangling_index_relationship() {
        let mut cache = DbCache::new();
        cache.indexes.push(IndexCache {
            index_id: ObjectId::new("public", "items_idx"),
            table_id: ObjectId::new("public", "items"),
        });

        let error = DbCacheVersioned::V6(Box::new(cache))
            .into_cache()
            .unwrap_err();
        assert!(error.contains("references missing relation 'public.items'"));
    }
}
