use safe_migrate::_internal::analysis::state::AnalysisState;
use safe_migrate::_internal::db::cache::{CatalogCoverage, DbCache, SchemaCoverage};
use safe_migrate::_internal::engine::engine::SafeMigrateEngine;
use safe_migrate::_internal::model::schema::SchemaState;
use safe_migrate::_internal::report::violations::ObjectKind;
use safe_migrate::api::Config;

/// A synced baseline holding schema `public` and no relations.
fn synced_empty_baseline() -> DbCache {
    let mut cache = crate::common::synced_cache();
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
    let mut state = AnalysisState::new(crate::common::synced_cache());
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
    // LOCK names two relations, so there is no single subject.
    let engine = SafeMigrateEngine::new(Config::default());
    let mut state = AnalysisState::with_baseline(crate::common::synced_cache(), true);
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
    // Without a baseline the object is unknown, so drift would be a false alarm.
    let engine = SafeMigrateEngine::new(Config::default());
    let mut state = AnalysisState::with_baseline(crate::common::synced_cache(), false);
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
