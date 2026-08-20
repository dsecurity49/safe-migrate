use std::collections::HashMap;

use safe_migrate::analysis::state::{AnalysisState, Confidence};
use safe_migrate::db::cache::DbCache;
use safe_migrate::engine::config::{Config, RuleConfig};
use safe_migrate::engine::engine::SafeMigrateEngine;
use safe_migrate::report::violations::Violation;

fn cache_with_timeouts(lock_timeout_ms: u64, statement_timeout_ms: u64) -> DbCache {
    let mut cache = DbCache::new();
    cache.metadata.source_lock_timeout_ms = lock_timeout_ms;
    cache.metadata.source_statement_timeout_ms = statement_timeout_ms;
    cache
}

fn timeout_findings(violations: &[Violation]) -> Vec<&Violation> {
    violations
        .iter()
        .filter(|violation| {
            matches!(
                violation.rule_id,
                "require-lock-timeout" | "require-statement-timeout"
            )
        })
        .collect()
}

fn analyze_slow_statement(state: &mut AnalysisState) -> Vec<Violation> {
    SafeMigrateEngine::new(Config::default())
        .analyze(
            "COMMENT ON TABLE future_table IS 'timeout rule probe';",
            state,
        )
        .expect("Squawk should parse COMMENT ON")
}

#[test]
fn synchronized_timeout_values_control_timeout_findings() {
    let mut safe_state = AnalysisState::new(cache_with_timeouts(1_000, 10_000));
    assert!(timeout_findings(&analyze_slow_statement(&mut safe_state)).is_empty());

    let mut disabled_state = AnalysisState::new(cache_with_timeouts(0, 0));
    let disabled = analyze_slow_statement(&mut disabled_state);
    let disabled_ids: Vec<_> = timeout_findings(&disabled)
        .iter()
        .map(|violation| violation.rule_id)
        .collect();
    assert_eq!(
        disabled_ids,
        ["require-lock-timeout", "require-statement-timeout"]
    );

    let mut ineffective_lock_state = AnalysisState::new(cache_with_timeouts(5_000, 5_000));
    let ineffective = analyze_slow_statement(&mut ineffective_lock_state);
    let timeout_findings = timeout_findings(&ineffective);
    assert_eq!(timeout_findings.len(), 1);
    assert_eq!(timeout_findings[0].rule_id, "require-lock-timeout");
    assert!(
        timeout_findings[0]
            .reason
            .contains("PostgreSQL reaches statement_timeout first")
    );
}

#[test]
fn unavailable_baseline_reports_unknown_timeout_evidence() {
    let mut state = AnalysisState::with_baseline(DbCache::new(), false);
    let violations = analyze_slow_statement(&mut state);
    let timeout_findings = timeout_findings(&violations);

    assert_eq!(state.local.lock_timeout.effective, None);
    assert_eq!(state.local.statement_timeout.effective, None);
    assert_eq!(timeout_findings.len(), 2);
    assert!(timeout_findings.iter().any(|violation| {
        violation.rule_id == "require-lock-timeout"
            && violation.reason.contains("No lock_timeout is known")
    }));
    assert!(timeout_findings.iter().any(|violation| {
        violation.rule_id == "require-statement-timeout"
            && violation.reason.contains("No statement_timeout is known")
    }));
}

#[test]
fn sql_set_and_reset_update_effective_timeout_rules_in_order() {
    let engine = SafeMigrateEngine::new(Config::default());
    let mut state = AnalysisState::new(cache_with_timeouts(0, 0));

    let safe = engine
        .analyze(
            "SET lock_timeout = '1s';
             SET statement_timeout = '5s';
             COMMENT ON TABLE future_table IS 'safe timeout pair';",
            &mut state,
        )
        .unwrap();
    assert!(timeout_findings(&safe).is_empty());
    assert_eq!(state.local.lock_timeout.effective, Some(1_000));
    assert_eq!(state.local.statement_timeout.effective, Some(5_000));

    let statement_reset = engine
        .analyze(
            "RESET statement_timeout;
             COMMENT ON TABLE future_table IS 'statement timeout reset';",
            &mut state,
        )
        .unwrap();
    let timeout_findings = timeout_findings(&statement_reset);
    assert_eq!(timeout_findings.len(), 1);
    assert_eq!(timeout_findings[0].rule_id, "require-statement-timeout");

    engine.analyze("RESET ALL;", &mut state).unwrap();
    assert_eq!(state.local.lock_timeout.effective, Some(0));
    assert_eq!(state.local.statement_timeout.effective, Some(0));
    assert_eq!(state.local.search_path_template, ["public"]);
}

#[test]
fn transaction_local_timeout_and_search_path_restore_session_values() {
    let engine = SafeMigrateEngine::new(Config::default());
    let mut state = AnalysisState::new(cache_with_timeouts(500, 5_000));

    engine
        .analyze(
            "BEGIN;
             SET lock_timeout = '2s';
             SET LOCAL lock_timeout = '1s';
             SET search_path TO session_schema;
             SET LOCAL search_path TO local_schema;
             COMMIT;",
            &mut state,
        )
        .unwrap();

    assert!(state.local.transactions.is_empty());
    assert_eq!(state.local.lock_timeout.session, Some(2_000));
    assert_eq!(state.local.lock_timeout.effective, Some(2_000));
    assert_eq!(state.local.search_path_template, ["session_schema"]);
    assert_eq!(state.local.session_search_path_template, ["session_schema"]);

    engine
        .analyze(
            "BEGIN;
             SET LOCAL lock_timeout = '3s';
             SET LOCAL search_path TO rolled_back_schema;
             ROLLBACK;",
            &mut state,
        )
        .unwrap();
    assert_eq!(state.local.lock_timeout.effective, Some(2_000));
    assert_eq!(state.local.search_path_template, ["session_schema"]);

    engine
        .analyze(
            "SET LOCAL lock_timeout = '4s';
             SET LOCAL search_path TO ignored_schema;",
            &mut state,
        )
        .unwrap();
    assert_eq!(state.local.lock_timeout.effective, Some(2_000));
    assert_eq!(state.local.search_path_template, ["session_schema"]);
}

#[test]
fn savepoint_rollback_restores_settings_and_reset_all_is_transactional() {
    let engine = SafeMigrateEngine::new(Config::default());
    let mut state = AnalysisState::new(cache_with_timeouts(500, 5_000));

    engine
        .analyze(
            "SET lock_timeout = '2s';
             SET statement_timeout = '20s';
             SET search_path TO session_schema;
             BEGIN;
             SAVEPOINT before_reset;
             RESET ALL;
             ROLLBACK TO before_reset;
             COMMIT;",
            &mut state,
        )
        .unwrap();

    assert_eq!(state.local.lock_timeout.effective, Some(2_000));
    assert_eq!(state.local.statement_timeout.effective, Some(20_000));
    assert_eq!(state.local.search_path_template, ["session_schema"]);

    engine.analyze("RESET ALL;", &mut state).unwrap();
    assert_eq!(state.local.lock_timeout.effective, Some(500));
    assert_eq!(state.local.statement_timeout.effective, Some(5_000));
    assert_eq!(state.local.search_path_template, ["public"]);
}

#[test]
fn rollback_restores_confidence_tainted_by_reset_search_path() {
    let engine = SafeMigrateEngine::new(Config::default());
    let mut cache = cache_with_timeouts(500, 5_000);
    cache.metadata.schemas = Some(vec!["public".to_string()]);
    cache.search_path = vec!["public".to_string()];
    let mut state = AnalysisState::new(cache);
    state.local.default_search_path_template = vec!["outside_sync_scope".to_string()];

    engine
        .analyze("BEGIN; RESET search_path;", &mut state)
        .unwrap();
    assert_eq!(state.local.confidence, Confidence::Tainted);

    engine.analyze("ROLLBACK;", &mut state).unwrap();
    assert_eq!(state.local.confidence, Confidence::Exact);
    assert_eq!(state.local.search_path_template, ["public"]);
}

#[test]
fn timeout_findings_deduplicate_once_per_file_and_can_be_disabled() {
    let engine = SafeMigrateEngine::new(Config::default());
    let mut state = AnalysisState::new(cache_with_timeouts(0, 0));
    let violations = engine
        .analyze(
            "COMMENT ON TABLE first_table IS 'first';
             COMMENT ON TABLE second_table IS 'second';",
            &mut state,
        )
        .unwrap();
    assert_eq!(timeout_findings(&violations).len(), 2);

    let config = Config {
        rules: HashMap::from([
            (
                "require-lock-timeout".to_string(),
                RuleConfig {
                    disabled: Some(true),
                    ..RuleConfig::default()
                },
            ),
            (
                "require-statement-timeout".to_string(),
                RuleConfig {
                    disabled: Some(true),
                    ..RuleConfig::default()
                },
            ),
        ]),
        ..Config::default()
    };
    let mut state = AnalysisState::new(cache_with_timeouts(0, 0));
    let disabled = SafeMigrateEngine::new(config)
        .analyze(
            "COMMENT ON TABLE future_table IS 'disabled timeout rules';",
            &mut state,
        )
        .unwrap();
    assert!(timeout_findings(&disabled).is_empty());
}

#[test]
fn invalid_timeout_value_is_an_exact_chain_conflict() {
    let engine = SafeMigrateEngine::new(Config::default());
    let mut state = AnalysisState::new(cache_with_timeouts(500, 5_000));
    let violations = engine
        .analyze("SET lock_timeout = 'forever';", &mut state)
        .unwrap();

    assert!(violations.iter().any(|violation| {
        violation.rule_id == "chain-conflict"
            && violation.reason.contains("invalid timeout value 'forever'")
    }));
    assert_eq!(state.local.lock_timeout.effective, Some(500));
    assert_eq!(state.local.confidence, Confidence::Exact);
}
