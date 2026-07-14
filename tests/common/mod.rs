#![allow(dead_code)]

use safe_migrate::ast::identifiers::ObjectId;
use safe_migrate::db::cache::DbCache;
use safe_migrate::engine::config::Config;
use safe_migrate::engine::engine::SafeMigrateEngine;
use safe_migrate::model::relation::{Persistence, RelationKind, RelationState};

pub fn setup_engine() -> SafeMigrateEngine {
    SafeMigrateEngine::new(Config::default())
}

pub fn setup_state() -> safe_migrate::AnalysisState {
    safe_migrate::AnalysisState::new(DbCache::new())
}

pub fn object_id(schema: &str, name: &str) -> ObjectId {
    ObjectId::new(schema, name)
}

pub fn cache_with_table(schema: &str, name: &str, rows: Option<u64>) -> DbCache {
    let mut cache = DbCache::new();
    let tid = object_id(schema, name);
    cache.insert_baseline(
        tid.clone(),
        RelationState::new(
            tid.clone(),
            object_id(schema, "postgres"),
            0,
            rows,
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );
    cache
}
