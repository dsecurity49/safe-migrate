use crate::_internal::analysis::namespace::{SESSION_TEMP_SCHEMA, SearchPathEntry};
use crate::_internal::analysis::state::AnalysisState;
use crate::_internal::engine::engine::SafeMigrateEngine;

fn analyze(engine: &SafeMigrateEngine, state: &mut AnalysisState, sql: &str) {
    let findings = engine.analyze(sql, state).expect("scenario should analyze");
    assert!(
        findings
            .iter()
            .all(|finding| finding.rule_id != "chain-conflict"),
        "unexpected state conflict: {findings:?}"
    );
}

fn assert_temp_schema_is_searched_first(state: &AnalysisState) {
    let path = state.relation_search_path();
    assert_eq!(
        path.first().and_then(SearchPathEntry::name),
        Some(SESSION_TEMP_SCHEMA)
    );
}

fn assert_temp_schema_is_absent(state: &AnalysisState) {
    assert!(!state.temp_namespace_exists());
    assert!(
        state
            .relation_search_path()
            .iter()
            .all(|entry| entry.name() != Some(SESSION_TEMP_SCHEMA)),
        "a rolled-back temp namespace must not stay in the search path"
    );
}

#[test]
fn rollback_removes_a_temp_namespace_created_in_the_transaction() {
    let engine = crate::common::setup_engine();
    let mut state = crate::common::setup_state();

    analyze(
        &engine,
        &mut state,
        "BEGIN;\nCREATE TEMP TABLE pg_temp.rollback_probe (id bigint NOT NULL);\nROLLBACK;",
    );

    assert_temp_schema_is_absent(&state);
}

#[test]
fn rollback_to_savepoint_removes_only_the_namespace_it_created() {
    let engine = crate::common::setup_engine();
    let mut state = crate::common::setup_state();

    analyze(
        &engine,
        &mut state,
        "BEGIN;\nSAVEPOINT before_temp;\nCREATE TEMP TABLE pg_temp.savepoint_probe (id bigint NOT NULL);\nROLLBACK TO SAVEPOINT before_temp;",
    );
    assert_temp_schema_is_absent(&state);
    analyze(&engine, &mut state, "ROLLBACK;");
    assert_temp_schema_is_absent(&state);

    analyze(
        &engine,
        &mut state,
        "CREATE TEMP TABLE pg_temp.kept_probe (id bigint NOT NULL);",
    );
    assert!(state.temp_namespace_exists());

    analyze(
        &engine,
        &mut state,
        "BEGIN;\nSAVEPOINT after_temp;\nCREATE TEMP TABLE pg_temp.discarded_probe (id bigint NOT NULL);\nROLLBACK TO SAVEPOINT after_temp;\nROLLBACK;",
    );
    assert_temp_schema_is_searched_first(&state);
    assert!(state.relation_is_present(&crate::common::object_id("pg_temp", "kept_probe")));
}

#[test]
fn dropped_temp_object_keeps_the_session_namespace() {
    let engine = crate::common::setup_engine();
    let mut state = crate::common::setup_state();

    analyze(
        &engine,
        &mut state,
        "CREATE TEMP TABLE pg_temp.drop_probe (id bigint NOT NULL);\nDROP TABLE pg_temp.drop_probe;",
    );

    assert_temp_schema_is_searched_first(&state);
}

#[test]
fn on_commit_drop_keeps_the_session_namespace() {
    let engine = crate::common::setup_engine();
    let mut state = crate::common::setup_state();

    analyze(
        &engine,
        &mut state,
        "BEGIN;\nCREATE TEMP TABLE pg_temp.on_commit_probe (id bigint NOT NULL) ON COMMIT DROP;\nCOMMIT;",
    );

    assert_temp_schema_is_searched_first(&state);
    assert!(!state.relation_is_present(&crate::common::object_id("pg_temp", "on_commit_probe")));
}

#[test]
fn rollback_drops_an_explicit_temp_path_entry_added_by_creation() {
    let engine = crate::common::setup_engine();
    let mut state = crate::common::setup_state();

    analyze(&engine, &mut state, "SET search_path = pg_temp, public;");
    analyze(
        &engine,
        &mut state,
        "BEGIN;\nCREATE TEMP TABLE pg_temp.path_probe (id bigint NOT NULL);\nROLLBACK;",
    );

    assert_temp_schema_is_absent(&state);
}
