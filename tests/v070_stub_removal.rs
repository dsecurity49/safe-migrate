use safe_migrate::_internal::analysis::state::AnalysisState;
use safe_migrate::_internal::db::cache::{CatalogCoverage, DbCache, SchemaCoverage};
use safe_migrate::_internal::engine::engine::SafeMigrateEngine;
use safe_migrate::_internal::model::schema::SchemaState;
use safe_migrate::_internal::report::violations::ObjectKind;
use safe_migrate::api::Config;

/// A cache that claims a complete, synced baseline containing schema `public`
/// but no relations, so a reference to anything else is provably absent.
fn synced_empty_baseline() -> DbCache {
    let mut cache = DbCache::new();
    cache.metadata.schemas = Some(vec!["public".to_string()]);
    cache.coverage = CatalogCoverage {
        schema_scope: SchemaCoverage::from_sync_scope(Some(&["public".to_string()])),
        families: cache.coverage.families.clone(),
    };
    cache.schemas.insert(
        "public".to_string(),
        SchemaState {
            name: "public".to_string(),
            owner: safe_migrate::_internal::ast::identifiers::ObjectId::new(
                "pg_catalog",
                "postgres",
            ),
            generation: 0,
        },
    );
    cache
}

#[test]
fn timeout_findings_name_the_object_the_statement_acts_on() {
    let engine = SafeMigrateEngine::new(Config::default());
    let mut state = AnalysisState::new(DbCache::new());
    let violations = engine
        .analyze(
            "CREATE TABLE victims (id int);
             CREATE INDEX slow_idx ON victims (id);",
            &mut state,
        )
        .unwrap();

    let timeout = violations
        .iter()
        .find(|violation| violation.rule_id == "require-lock-timeout")
        .unwrap_or_else(|| {
            panic!(
                "a CREATE INDEX without a lock_timeout must be reported, got: {:?}",
                violations
                    .iter()
                    .map(|violation| (&violation.rule_id, &violation.object_name))
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(timeout.object_kind, ObjectKind::Index);
    assert_eq!(timeout.object_name, "public.slow_idx");
}

#[test]
fn timeout_finding_reports_an_unknown_subject_when_there_is_none() {
    // LOCK has no single object, so the finding must say so rather than
    // invent a name.
    let engine = SafeMigrateEngine::new(Config::default());
    let mut state = AnalysisState::with_baseline(DbCache::new(), true);
    let violations = engine.analyze("LOCK TABLE a, b;", &mut state).unwrap();

    let timeout = violations
        .iter()
        .find(|violation| violation.rule_id == "require-lock-timeout")
        .expect("LOCK without a lock_timeout must be reported");
    assert_eq!(timeout.object_kind, ObjectKind::Unknown);
    assert_eq!(timeout.object_name, "unknown statement");
}

#[test]
fn missing_baseline_object_is_reported_as_schema_drift() {
    let engine = SafeMigrateEngine::new(Config::default());
    let mut state = AnalysisState::with_baseline(synced_empty_baseline(), true);
    let violations = engine
        .analyze("ALTER TABLE absent_table ADD COLUMN x int;", &mut state)
        .unwrap();

    let drift = violations
        .iter()
        .find(|violation| violation.rule_id == "schema-drift")
        .expect("a table absent from a synced baseline is schema drift");
    assert!(
        drift.reason.contains("absent_table"),
        "drift must name the missing object: {}",
        drift.reason
    );
}

#[test]
fn unknown_object_is_not_drift_without_a_synced_baseline() {
    // Without a baseline the object may simply be unknown, so only a taint
    // is justified; claiming drift would be a false alarm.
    let engine = SafeMigrateEngine::new(Config::default());
    let mut state = AnalysisState::with_baseline(DbCache::new(), false);
    let violations = engine
        .analyze("ALTER TABLE absent_table ADD COLUMN x int;", &mut state)
        .unwrap();

    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "schema-drift"),
        "absence is unknown, so drift must not be claimed"
    );
}

#[test]
fn object_created_earlier_in_the_migration_is_never_drift() {
    let engine = SafeMigrateEngine::new(Config::default());
    let mut state = AnalysisState::with_baseline(synced_empty_baseline(), true);
    let violations = engine
        .analyze(
            "CREATE TABLE fresh_table (id int);
             ALTER TABLE fresh_table ADD COLUMN x int;",
            &mut state,
        )
        .unwrap();

    let drift: Vec<_> = violations
        .iter()
        .filter(|violation| violation.rule_id == "schema-drift")
        .collect();
    assert!(
        drift.is_empty(),
        "a table created in the same migration is present in local state, got: {:?}",
        drift
            .iter()
            .map(|violation| violation.reason.clone())
            .collect::<Vec<_>>()
    );
}
