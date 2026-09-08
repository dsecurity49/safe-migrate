#![allow(dead_code)]

pub(crate) mod invariants;

use safe_migrate::_internal::ast::identifiers::ObjectId;
use safe_migrate::_internal::db::cache::DbCache;
use safe_migrate::_internal::engine::engine::SafeMigrateEngine;
use safe_migrate::_internal::model::relation::{Persistence, RelationKind, RelationState};
use safe_migrate::api::Config;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

static SAFE_MIGRATE_BINARY: OnceLock<PathBuf> = OnceLock::new();

/// Unit tests do not receive Cargo's integration-test binary environment
/// variable, so build the CLI once and invoke its deterministic target path.
pub(crate) fn safe_migrate_command() -> assert_cmd::Command {
    let binary = SAFE_MIGRATE_BINARY.get_or_init(|| {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let status = Command::new(env!("CARGO"))
            .args(["build", "--locked", "--bin", "safe-migrate"])
            .current_dir(&manifest_dir)
            .status()
            .expect("run cargo build for CLI integration tests");
        assert!(
            status.success(),
            "cargo build must produce the safe-migrate CLI"
        );
        manifest_dir
            .join("target")
            .join("debug")
            .join(format!("safe-migrate{}", std::env::consts::EXE_SUFFIX))
    });
    assert_cmd::Command::new(binary)
}

pub(crate) fn setup_engine() -> SafeMigrateEngine {
    SafeMigrateEngine::new(Config::default())
}

pub(crate) fn setup_state() -> crate::_internal::analysis::state::AnalysisState {
    crate::_internal::analysis::state::AnalysisState::new(cache_with_safe_timeouts())
}

fn cache_with_safe_timeouts() -> DbCache {
    let mut cache = DbCache::new();
    cache.metadata.source_lock_timeout_ms = 1_000;
    cache.metadata.source_statement_timeout_ms = 10_000;
    cache
}

pub(crate) fn object_id(schema: &str, name: &str) -> ObjectId {
    ObjectId::new(schema, name)
}

pub(crate) fn database_hosts_are_local(config: &postgres::Config) -> bool {
    config
        .get_hostaddrs()
        .iter()
        .all(|address| address.is_loopback())
        && config.get_hosts().iter().all(|host| match host {
            #[cfg(unix)]
            postgres::config::Host::Unix(_) => true,
            postgres::config::Host::Tcp(host) if host.eq_ignore_ascii_case("localhost") => true,
            postgres::config::Host::Tcp(host) => host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback()),
        })
}

pub(crate) fn cache_with_table(schema: &str, name: &str, rows: Option<u64>) -> DbCache {
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
