#![allow(dead_code)]

pub(crate) mod invariants;

use safe_migrate::_internal::ast::identifiers::ObjectId;
use safe_migrate::_internal::db::cache::{CatalogCoverage, CatalogFamily, DbCache, SchemaCoverage};
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
    let mut cache = synced_cache();
    cache.metadata.source_lock_timeout_ms = 1_000;
    cache.metadata.source_statement_timeout_ms = 10_000;
    cache
}

/// A hand-built baseline that retrieved the whole catalog. Coverage is a claim
/// about what was read, so a test asserting exact behavior must state it.
pub(crate) fn synced_cache() -> DbCache {
    let mut cache = DbCache::new();
    cache.coverage =
        CatalogCoverage::for_families(SchemaCoverage::from_sync_scope(None), CatalogFamily::ALL);
    cache.opclasses = Some(default_opclasses());
    cache.collations = Some(default_collations());
    cache
}

/// The `pg_catalog` collations `sync` would load, reduced to the entries a test
/// can rely on: the database default plus the `C` and `POSIX` locales.
fn default_collations() -> crate::_internal::model::collation::CollationCatalogue {
    use crate::_internal::model::collation::CollationCatalogue;
    use crate::_internal::model::index::ResolvedName;
    CollationCatalogue::from_entries(
        ["default", "C", "POSIX"]
            .iter()
            .map(|name| ResolvedName {
                schema: "pg_catalog".to_string(),
                name: (*name).to_string(),
            })
            .collect(),
    )
}

/// The SQL spelling a column carries, for the catalog `typname` above.
fn aliases_for(intype: &str) -> Vec<String> {
    match intype {
        "int4" => vec!["integer".to_string()],
        "bool" => vec!["boolean".to_string()],
        _ => Vec::new(),
    }
}

/// The operator classes `sync` would load, reduced to the entries a test can
/// rely on. The families mirror a live PostgreSQL catalog: `int4_ops` belongs
/// to `integer_ops`, `date_ops`/`timestamptz_ops` to `datetime_ops`, and the
/// `*_pattern_ops` classes to `text_pattern_ops`. `varchar` has no default
/// class of its own on modern servers, so it is deliberately absent and
/// resolves through `text`.
fn default_opclasses() -> crate::_internal::model::opclass::OpclassCatalogue {
    use crate::_internal::model::index::ResolvedName;
    use crate::_internal::model::opclass::{OpclassCatalogue, OpclassEntry};
    let mut catalogue = Vec::new();
    for (intype, name, family, is_default) in [
        ("int4", "int4_ops", "integer_ops", true),
        ("text", "text_ops", "text_ops", true),
        ("text", "text_pattern_ops", "text_pattern_ops", false),
        ("text", "varchar_ops", "text_ops", false),
        ("text", "varchar_pattern_ops", "text_pattern_ops", false),
        ("bool", "bool_ops", "bool_ops", true),
        ("date", "date_ops", "datetime_ops", true),
        ("timestamptz", "timestamptz_ops", "datetime_ops", true),
    ] {
        catalogue.push(OpclassEntry {
            name: name.to_string(),
            namespace: "pg_catalog".to_string(),
            family: ResolvedName {
                schema: "pg_catalog".to_string(),
                name: family.to_string(),
            },
            intype: intype.to_string(),
            aliases: aliases_for(intype),
            method: "btree".to_string(),
            is_default,
        });
    }
    OpclassCatalogue::from_entries(catalogue)
}

/// The synthetic empty cache `Baseline::unavailable()` produces, whose coverage
/// is empty because nothing was ever read.
pub(crate) fn unavailable_cache() -> DbCache {
    DbCache::new()
}

pub(crate) fn object_id(schema: &str, name: &str) -> ObjectId {
    ObjectId::new(schema, name)
}

/// The reason of the single `chain-conflict` a statement produces, or `""` when
/// it produces none. Tests that assert a rejection read PostgreSQL's own words
/// back rather than a restatement of them.
pub(crate) fn conflict_reason(
    engine: &SafeMigrateEngine,
    state: &mut crate::_internal::analysis::state::AnalysisState,
    sql: &str,
) -> String {
    engine
        .analyze(sql, state)
        .expect("the statement should analyze")
        .into_iter()
        .find(|violation| violation.rule_id == "chain-conflict")
        .map(|violation| violation.reason)
        .unwrap_or_default()
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
