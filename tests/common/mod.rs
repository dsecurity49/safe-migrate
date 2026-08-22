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
    safe_migrate::AnalysisState::new(cache_with_safe_timeouts())
}

fn cache_with_safe_timeouts() -> DbCache {
    let mut cache = DbCache::new();
    cache.metadata.source_lock_timeout_ms = 1_000;
    cache.metadata.source_statement_timeout_ms = 10_000;
    cache
}

pub fn object_id(schema: &str, name: &str) -> ObjectId {
    ObjectId::new(schema, name)
}

pub fn database_hosts_are_local(config: &postgres::Config) -> bool {
    config.get_hosts().iter().all(|host| match host {
        postgres::config::Host::Unix(_) => true,
        postgres::config::Host::Tcp(host) if host.eq_ignore_ascii_case("localhost") => true,
        postgres::config::Host::Tcp(host) => host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
    })
}

pub fn cache_with_table(schema: &str, name: &str, rows: Option<u64>) -> DbCache {
    let mut cache = cache_with_safe_timeouts();
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
