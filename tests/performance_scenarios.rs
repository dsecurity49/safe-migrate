mod common;

mod performance_scenarios {
    use crate::common::{object_id, setup_engine, setup_state};
    use safe_migrate::db::cache::{DbCache, DbCacheVersioned};
    use safe_migrate::db::cache_file::{CACHE_KEY_ENV, protect_cache_bytes, unprotect_cache_bytes};
    use safe_migrate::model::relation::{Persistence, RelationKind, RelationState};
    use std::io::Cursor;
    use std::time::Instant;

    const LARGE_BASELINE_RELATIONS: usize = 1_000;
    const LONG_CHAIN_STATEMENTS: usize = 1_000;
    const ROLLBACK_STATEMENTS: usize = 500;
    const SAVEPOINT_ITERATIONS: usize = 250;
    const GRAPH_OBJECTS: usize = 100;
    const REPORT_FINDINGS: usize = 250;

    fn report_elapsed(scenario: &str, statements: usize, elapsed: std::time::Duration) {
        eprintln!(
            "scenario={scenario} statements={statements} elapsed_ms={}",
            elapsed.as_millis()
        );
    }

    fn large_baseline() -> DbCache {
        let mut cache = DbCache::new();
        cache.search_path = vec!["public".to_string()];
        for index in 0..LARGE_BASELINE_RELATIONS {
            let id = object_id("public", &format!("perf_baseline_{index}"));
            cache.insert_baseline(
                id.clone(),
                RelationState::new(
                    id,
                    object_id("public", "postgres"),
                    0,
                    Some(1_000),
                    RelationKind::Table,
                    Persistence::Permanent,
                    0,
                ),
            );
        }
        cache
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn ordered_thousand_statement_chain() {
        let engine = setup_engine();
        let mut state = setup_state();
        let files = (0..LONG_CHAIN_STATEMENTS)
            .map(|index| {
                (
                    format!("V{index:04}__create.sql"),
                    format!("CREATE TABLE IF NOT EXISTS perf_chain_{index} (id bigint NOT NULL);"),
                )
            })
            .collect::<Vec<_>>();

        let started = Instant::now();
        let findings = engine
            .analyze_chain(&files, &mut state)
            .expect("long ordered chain should analyze");
        let elapsed = started.elapsed();

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
        assert!(state.relation_is_present(&object_id("public", "perf_chain_999")));
        report_elapsed(
            "ordered_thousand_statement_chain",
            LONG_CHAIN_STATEMENTS,
            elapsed,
        );
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn large_synchronized_baseline_hydration() {
        let started = Instant::now();
        let state = safe_migrate::AnalysisState::with_baseline(large_baseline(), true);
        let elapsed = started.elapsed();

        assert!(state.baseline_available);
        assert_eq!(state.baseline_relations.len(), LARGE_BASELINE_RELATIONS);
        assert!(state.relation_is_present(&object_id("public", "perf_baseline_999")));
        report_elapsed(
            "large_synchronized_baseline_hydration",
            LARGE_BASELINE_RELATIONS,
            elapsed,
        );
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn cache_encode_compress_encrypt_round_trip() {
        let cache = large_baseline();
        let started = Instant::now();
        let config = bincode::config::standard().with_variable_int_encoding();
        let payload = bincode::serde::encode_to_vec(DbCacheVersioned::V6(Box::new(cache)), config)
            .expect("cache should encode");
        let compressed = zstd::stream::encode_all(Cursor::new(payload), 3)
            .expect("cache payload should compress");
        unsafe {
            std::env::set_var(
                CACHE_KEY_ENV,
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            );
        }
        let encrypted = protect_cache_bytes(compressed, true).expect("cache should encrypt");
        let compressed =
            unprotect_cache_bytes(encrypted.clone(), true).expect("cache should decrypt");
        unsafe {
            std::env::remove_var(CACHE_KEY_ENV);
        }
        let payload = zstd::stream::decode_all(Cursor::new(compressed))
            .expect("cache payload should decompress");
        let decoded: DbCacheVersioned = bincode::serde::decode_from_slice(&payload, config)
            .expect("cache payload should decode")
            .0;
        let cache = decoded
            .into_cache()
            .expect("cache version should be current");
        let elapsed = started.elapsed();

        assert_eq!(cache.relations.len(), LARGE_BASELINE_RELATIONS);
        eprintln!(
            "scenario=cache_encode_compress_encrypt_round_trip relations={LARGE_BASELINE_RELATIONS} encrypted_bytes={} elapsed_ms={}",
            encrypted.len(),
            elapsed.as_millis()
        );
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn rename_and_cascade_dependency_graph() {
        let engine = setup_engine();
        let mut state = setup_state();
        let mut sql = String::from(
            "CREATE TABLE IF NOT EXISTS perf_graph_parent (id bigint PRIMARY KEY);\nCREATE VIEW perf_graph_parent_view AS SELECT id FROM perf_graph_parent;\n",
        );
        for index in 0..GRAPH_OBJECTS {
            sql.push_str(&format!(
                "CREATE TABLE IF NOT EXISTS perf_graph_child_{index} (id bigint PRIMARY KEY, parent_id bigint REFERENCES perf_graph_parent(id));\nCREATE INDEX IF NOT EXISTS perf_graph_child_{index}_parent_idx ON perf_graph_child_{index}(parent_id);\nCREATE VIEW perf_graph_view_{index} AS SELECT parent_id FROM perf_graph_child_{index};\n"
            ));
        }
        sql.push_str(
            "ALTER TABLE perf_graph_parent RENAME TO perf_graph_renamed;\nDROP TABLE perf_graph_renamed CASCADE;",
        );

        let started = Instant::now();
        let findings = engine
            .analyze(&sql, &mut state)
            .expect("graph scenario should analyze");
        let elapsed = started.elapsed();

        assert!(
            findings
                .iter()
                .all(|finding| finding.rule_id != "chain-conflict"),
            "graph workload must complete without a state conflict: {findings:?}"
        );
        assert!(!state.relation_is_present(&object_id("public", "perf_graph_renamed")));
        assert!(!state.relation_is_present(&object_id("public", "perf_graph_parent_view")));
        assert!(state.relation_is_present(&object_id("public", "perf_graph_child_0")));
        assert!(state.relation_is_present(&object_id("public", "perf_graph_view_99")));
        report_elapsed(
            "rename_and_cascade_dependency_graph",
            GRAPH_OBJECTS * 3 + 4,
            elapsed,
        );
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn location_rich_reports_with_many_findings() {
        let engine = setup_engine();
        let mut state = setup_state();
        let sql = (0..REPORT_FINDINGS)
            .map(|index| format!("CREATE TABLE perf_report_{index} (id bigint NOT NULL);"))
            .collect::<Vec<_>>()
            .join("\n");

        let started = Instant::now();
        let findings = engine
            .analyze_with_locations("performance.sql".to_string(), sql, &mut state)
            .expect("report scenario should analyze");
        let json =
            safe_migrate::Reporter::json_report_with_locations(&findings, &state.local.confidence);
        let markdown = safe_migrate::Reporter::markdown_report(&findings, &state.local.confidence);
        let elapsed = started.elapsed();

        assert_eq!(findings.len(), REPORT_FINDINGS);
        assert_eq!(json["summary"]["total"], REPORT_FINDINGS);
        assert!(markdown.contains("perf_report_249"));
        report_elapsed(
            "location_rich_reports_with_many_findings",
            REPORT_FINDINGS,
            elapsed,
        );
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn long_transaction_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        let mut sql = String::from("BEGIN;\n");
        for index in 0..ROLLBACK_STATEMENTS {
            sql.push_str(&format!(
                "CREATE TABLE perf_undo_{index} (id bigint NOT NULL);\n"
            ));
        }
        sql.push_str("ALTER TABLE perf_undo_0 DROP COLUMN missing_column;\nCOMMIT;");

        let started = Instant::now();
        let findings = engine
            .analyze(&sql, &mut state)
            .expect("rollback scenario should analyze");
        let elapsed = started.elapsed();

        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "missing rollback conflict: {findings:?}"
        );
        for index in 0..ROLLBACK_STATEMENTS {
            assert!(
                !state.relation_is_present(&object_id("public", &format!("perf_undo_{index}"))),
                "rollback left perf_undo_{index} present"
            );
        }
        report_elapsed(
            "long_transaction_rollback",
            ROLLBACK_STATEMENTS + 3,
            elapsed,
        );
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn multi_action_failure_restores_the_statement_state() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE perf_multi_action (id bigint NOT NULL);",
                &mut state,
            )
            .expect("baseline table should analyze");

        let started = Instant::now();
        let findings = engine
            .analyze(
                "BEGIN;
                 ALTER TABLE perf_multi_action
                    ADD COLUMN first_value integer,
                    ADD COLUMN second_value integer,
                    DROP COLUMN missing_column;
                 COMMIT;",
                &mut state,
            )
            .expect("multi-action rollback scenario should analyze");
        let elapsed = started.elapsed();

        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
        let relation = state
            .local
            .relations
            .get(&object_id("public", "perf_multi_action"))
            .expect("baseline relation should remain modeled");
        let safe_migrate::model::relation::RelationOverlay::Present(relation) = relation else {
            panic!("failed transaction must not drop the baseline relation");
        };
        assert!(
            relation
                .columns
                .iter()
                .all(|column| { column.name != "first_value" && column.name != "second_value" })
        );
        report_elapsed(
            "multi_action_failure_restores_the_statement_state",
            3,
            elapsed,
        );
    }

    #[test]
    #[ignore = "manual performance scenario; run with --ignored --nocapture"]
    fn repeated_savepoint_rollbacks_leave_no_transient_relations() {
        let engine = setup_engine();
        let mut state = setup_state();
        let mut sql = String::from("BEGIN;\n");
        for index in 0..SAVEPOINT_ITERATIONS {
            sql.push_str(&format!(
                "SAVEPOINT checkpoint_{index};\nCREATE TABLE IF NOT EXISTS perf_savepoint_{index} (id bigint NOT NULL);\nROLLBACK TO SAVEPOINT checkpoint_{index};\n"
            ));
        }
        sql.push_str("COMMIT;");

        let started = Instant::now();
        let findings = engine
            .analyze(&sql, &mut state)
            .expect("savepoint scenario should analyze");
        let elapsed = started.elapsed();

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
        assert!(!state.relation_is_present(&object_id("public", "perf_savepoint_0")));
        assert!(!state.relation_is_present(&object_id("public", "perf_savepoint_249")));
        report_elapsed(
            "repeated_savepoint_rollbacks_leave_no_transient_relations",
            SAVEPOINT_ITERATIONS * 3 + 2,
            elapsed,
        );
    }
}
