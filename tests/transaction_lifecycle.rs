mod common;

mod transaction_lifecycle_tests {
    use crate::common::*;
    use safe_migrate::analysis::state::AnalysisState;

    #[test]
    fn test_txn_commit() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("BEGIN; CREATE TABLE t(id int); COMMIT;", &mut state)
            .unwrap();

        assert!(state.local.transactions.is_empty());
        assert!(state.relation_is_present(&object_id("public", "t")));
    }

    #[test]
    fn commit_and_chain_starts_a_new_transaction() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "CREATE TABLE users (id int); BEGIN; COMMIT AND CHAIN; CREATE INDEX CONCURRENTLY idx ON users (id); ROLLBACK;",
                &mut state,
            )
            .unwrap();

        assert!(
            violations
                .iter()
                .any(|v| v.rule_id == "concurrent-in-transaction")
        );
        assert!(state.local.transactions.is_empty());
    }

    #[test]
    fn rollback_and_chain_starts_a_new_transaction() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "CREATE TABLE users (id int); BEGIN; ROLLBACK AND CHAIN; CREATE INDEX CONCURRENTLY idx ON users (id); ROLLBACK;",
                &mut state,
            )
            .unwrap();

        assert!(
            violations
                .iter()
                .any(|v| v.rule_id == "concurrent-in-transaction")
        );
        assert!(state.local.transactions.is_empty());
    }

    #[test]
    fn test_txn_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("BEGIN; CREATE TABLE t(id int); ROLLBACK;", &mut state)
            .unwrap();

        assert!(state.local.transactions.is_empty());
        assert!(!state.relation_is_present(&object_id("public", "t")));
    }

    #[test]
    fn statement_journal_restores_replication_state_after_late_conflict() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE journal_table(id integer);
                 CREATE PUBLICATION journal_publication FOR TABLE journal_table;",
                &mut state,
            )
            .unwrap();

        engine.analyze("BEGIN;", &mut state).unwrap();
        let publication_before = state.local.publications.get("journal_publication").cloned();
        let graph_before = state.local.graph.edges().to_vec();
        let generation_before = state.local.generation_counter;
        let confidence_before = state.local.confidence.clone();

        let findings = engine
            .analyze(
                "ALTER PUBLICATION journal_publication ADD TABLE journal_table;",
                &mut state,
            )
            .unwrap();

        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict")
        );
        assert_eq!(
            state.local.publications.get("journal_publication").cloned(),
            publication_before
        );
        assert_eq!(state.local.graph.edges(), graph_before);
        assert_eq!(state.local.generation_counter, generation_before);
        assert_eq!(state.local.confidence, confidence_before);
        assert!(state.local.transaction_aborted);

        engine.analyze("ROLLBACK;", &mut state).unwrap();
        assert!(state.local.transactions.is_empty());
        assert!(!state.local.transaction_aborted);
    }

    #[test]
    fn missing_savepoint_aborts_the_transaction_and_skips_later_statements() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "BEGIN; CREATE TABLE t(id int); ROLLBACK TO SAVEPOINT missing; DROP DATABASE should_not_run; ROLLBACK;",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|v| v.rule_id == "chain-conflict"));
        assert!(!violations.iter().any(|v| v.rule_id == "drop-database"));
        assert!(!state.relation_is_present(&object_id("public", "t")));
        assert!(!state.local.transaction_aborted);
    }

    #[test]
    fn test_savepoint_flow() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "BEGIN; SAVEPOINT s1; CREATE TABLE t(id int); ROLLBACK TO s1; RELEASE SAVEPOINT s1; COMMIT;",
                &mut state,
            )
            .unwrap();

        assert!(state.local.transactions.is_empty());
    }

    #[test]
    fn unquoted_savepoint_names_are_case_insensitive() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "CREATE TABLE users (id int); BEGIN; SAVEPOINT MixedCase; ROLLBACK TO SAVEPOINT mixedcase; CREATE INDEX CONCURRENTLY idx ON users (id); ROLLBACK;",
                &mut state,
            )
            .unwrap();

        assert!(
            violations
                .iter()
                .any(|v| v.rule_id == "concurrent-in-transaction")
        );
        assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));
    }

    #[test]
    fn test_rollback_to_savepoint_keeps_outer_txn() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "BEGIN; SAVEPOINT s1; CREATE TABLE t(id int); ROLLBACK TO s1; COMMIT;",
                &mut state,
            )
            .unwrap();

        assert!(state.local.transactions.is_empty());
        assert!(!state.relation_is_present(&object_id("public", "t")));
    }

    #[test]
    fn rollback_to_savepoint_recovers_an_aborted_transaction() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "BEGIN;
                 SAVEPOINT recover;
                 CREATE TABLE rolled_back(id integer);
                 CREATE TABLE rolled_back(id integer);
                 ROLLBACK TO SAVEPOINT recover;
                 CREATE TABLE after_recovery(id integer);
                 COMMIT;",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict" && violation.reason.contains("rolled_back")
        }));
        assert!(!state.relation_is_present(&object_id("public", "rolled_back")));
        assert!(state.relation_is_present(&object_id("public", "after_recovery")));
        assert!(state.local.transactions.is_empty());
        assert!(!state.local.transaction_aborted);
    }

    #[test]
    fn root_transaction_frame_is_not_a_savepoint_named_transaction() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "BEGIN;
                 CREATE TABLE retained(id integer);
                 ROLLBACK TO SAVEPOINT \"transaction\";
                 ROLLBACK;",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict"
                && violation
                    .reason
                    .contains("savepoint 'transaction' does not exist")
        }));
        assert!(!state.relation_is_present(&object_id("public", "retained")));
    }

    #[test]
    fn rollback_to_outer_savepoint_undoes_nested_changes_in_reverse_order() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "CREATE TABLE t(id int); BEGIN; SAVEPOINT a; ALTER TABLE t ADD COLUMN a integer; SAVEPOINT b; ALTER TABLE t ADD COLUMN b integer; ROLLBACK TO SAVEPOINT a; ALTER TABLE t ADD COLUMN a text; COMMIT;",
                &mut state,
            )
            .unwrap();

        assert!(!violations.iter().any(|v| v.rule_id == "chain-conflict"));
        let relation = state
            .local
            .relations
            .get(&object_id("public", "t"))
            .and_then(|overlay| match overlay {
                safe_migrate::analysis::state::RelationOverlay::Present(relation) => Some(relation),
                safe_migrate::analysis::state::RelationOverlay::Dropped => None,
            })
            .expect("table should remain present");
        let column = relation
            .columns
            .iter()
            .find(|column| column.name == "a")
            .expect("replacement column should be present");
        assert_eq!(column.data_type.as_deref(), Some("text"));
        assert!(!relation.columns.iter().any(|column| column.name == "b"));
    }

    #[test]
    fn release_outer_savepoint_removes_nested_savepoints_and_preserves_undo() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "BEGIN;
                 SAVEPOINT outer_sp;
                 CREATE TABLE release_a(id integer);
                 SAVEPOINT inner_sp;
                 CREATE TABLE release_b(id integer);
                 RELEASE SAVEPOINT outer_sp;
                 ROLLBACK TO SAVEPOINT inner_sp;
                 DROP DATABASE production;
                 ROLLBACK;",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict"
                && violation
                    .reason
                    .contains("savepoint 'inner_sp' does not exist")
        }));
        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "drop-database")
        );
        assert!(!state.relation_is_present(&object_id("public", "release_a")));
        assert!(!state.relation_is_present(&object_id("public", "release_b")));
        assert!(state.local.transactions.is_empty());
        assert!(!state.local.transaction_aborted);
    }

    #[test]
    fn missing_release_savepoint_aborts_the_active_transaction() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "BEGIN; RELEASE SAVEPOINT missing; DROP DATABASE production; ROLLBACK;",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict"
                && violation
                    .reason
                    .contains("savepoint 'missing' does not exist")
        }));
        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "drop-database")
        );
        assert!(state.local.transactions.is_empty());
        assert!(!state.local.transaction_aborted);
    }

    #[test]
    fn mutation_conflict_aborts_the_transaction_and_skips_later_statements() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "BEGIN;
                 CREATE TABLE conflict_t(id integer);
                 CREATE TABLE conflict_t(id integer);
                 DROP DATABASE production;
                 ROLLBACK;",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict"
                && violation.reason.contains("relation 'public.conflict_t'")
        }));
        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "drop-database")
        );
        assert!(!state.relation_is_present(&object_id("public", "conflict_t")));
        assert!(state.local.transactions.is_empty());
        assert!(!state.local.transaction_aborted);
    }

    #[test]
    fn idempotent_skip_does_not_abort_the_transaction() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "BEGIN;
                 CREATE TABLE kept_t(id integer);
                 CREATE TABLE IF NOT EXISTS kept_t(id integer);
                 CREATE TABLE following_t(id integer);
                 COMMIT;",
                &mut state,
            )
            .unwrap();

        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );
        assert!(state.relation_is_present(&object_id("public", "kept_t")));
        assert!(state.relation_is_present(&object_id("public", "following_t")));
        assert!(state.local.transactions.is_empty());
        assert!(!state.local.transaction_aborted);
    }

    #[test]
    fn savepoint_outside_transaction_does_not_create_a_transaction_frame() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "SAVEPOINT outside_sp;
                 CREATE INDEX CONCURRENTLY outside_idx ON users(id);",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict"
                && violation
                    .reason
                    .contains("SAVEPOINT can only be used in transaction blocks")
        }));
        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "concurrent-in-transaction")
        );
        assert!(state.local.transactions.is_empty());
        assert!(!state.local.transaction_aborted);
    }

    #[test]
    fn rollback_to_savepoint_outside_transaction_does_not_abort_later_analysis() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "ROLLBACK TO SAVEPOINT outside_sp; DROP DATABASE production;",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict"
                && violation
                    .reason
                    .contains("savepoint 'outside_sp' does not exist")
        }));
        assert!(
            violations
                .iter()
                .any(|violation| violation.rule_id == "drop-database")
        );
        assert!(state.local.transactions.is_empty());
        assert!(!state.local.transaction_aborted);
    }

    #[test]
    fn chain_without_active_transaction_does_not_start_a_transaction() {
        let engine = setup_engine();

        for (statement, expected_reason, index_name) in [
            (
                "COMMIT AND CHAIN",
                "COMMIT AND CHAIN can only be used in transaction blocks",
                "commit_outside_idx",
            ),
            (
                "ROLLBACK AND CHAIN",
                "ROLLBACK AND CHAIN can only be used in transaction blocks",
                "rollback_outside_idx",
            ),
        ] {
            let mut state = setup_state();
            let sql = format!("{statement}; CREATE INDEX CONCURRENTLY {index_name} ON users(id);");
            let violations = engine.analyze(&sql, &mut state).unwrap();

            assert!(violations.iter().any(|violation| {
                violation.rule_id == "chain-conflict" && violation.reason.contains(expected_reason)
            }));
            assert!(
                !violations
                    .iter()
                    .any(|violation| violation.rule_id == "concurrent-in-transaction")
            );
            assert!(state.local.transactions.is_empty());
            assert!(!state.local.transaction_aborted);
        }
    }

    #[test]
    fn multi_action_alter_table_restores_state_after_a_failed_action() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "CREATE TABLE t(id int); ALTER TABLE t ADD COLUMN b integer, DROP COLUMN missing; ALTER TABLE t ADD COLUMN b text;",
                &mut state,
            )
            .unwrap();

        assert!(
            violations
                .iter()
                .any(|violation| { violation.reason.contains("column 'missing' does not exist") })
        );
        assert!(!violations.iter().any(|violation| {
            violation
                .reason
                .contains("column 'b' already added with type integer")
        }));
        let relation = state
            .local
            .relations
            .get(&object_id("public", "t"))
            .and_then(|overlay| match overlay {
                safe_migrate::analysis::state::RelationOverlay::Present(relation) => Some(relation),
                safe_migrate::analysis::state::RelationOverlay::Dropped => None,
            })
            .expect("table should remain present");
        let column = relation
            .columns
            .iter()
            .find(|column| column.name == "b")
            .expect("following statement should add column b");
        assert_eq!(column.data_type.as_deref(), Some("text"));
    }

    #[test]
    fn failed_compound_statement_discards_earlier_risk_findings() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "CREATE TABLE t(id integer);
                 ALTER TABLE t DROP COLUMN id, DROP COLUMN missing;",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict"
                && violation.reason.contains("column 'missing' does not exist")
        }));
        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "irreversible-migration")
        );
        let relation = state
            .local
            .relations
            .get(&object_id("public", "t"))
            .and_then(|overlay| match overlay {
                safe_migrate::analysis::state::RelationOverlay::Present(relation) => Some(relation),
                safe_migrate::analysis::state::RelationOverlay::Dropped => None,
            })
            .expect("failed compound statement must preserve the table");
        assert!(relation.has_column("id"));
    }

    #[test]
    fn test_rename_propagation_rollback() {
        let engine = setup_engine();
        let mut cache = safe_migrate::db::cache::DbCache::new();

        let t1_id = object_id("public", "t1");
        let v1_id = object_id("public", "v1");

        cache.insert_baseline(
            t1_id.clone(),
            safe_migrate::model::relation::RelationState::new(
                t1_id.clone(),
                object_id("public", "postgres"),
                0,
                Some(10),
                safe_migrate::model::relation::RelationKind::Table,
                safe_migrate::model::relation::Persistence::Permanent,
                0,
            ),
        );
        cache.insert_baseline(
            v1_id.clone(),
            safe_migrate::model::relation::RelationState::new(
                v1_id.clone(),
                object_id("public", "postgres"),
                0,
                Some(1),
                safe_migrate::model::relation::RelationKind::View,
                safe_migrate::model::relation::Persistence::Permanent,
                0,
            ),
        );

        let mut state = AnalysisState::new(cache);

        state
            .local
            .graph
            .add_edge(safe_migrate::analysis::graph::DependencyEdge {
                dependent: v1_id.clone(),
                referenced: t1_id.clone(),
                kind: safe_migrate::analysis::graph::DependencyKind::ViewDependency {
                    view_generation: 0,
                    referenced_column: None,
                },
            });

        assert_eq!(state.local.graph.edges()[0].referenced, t1_id);

        engine
            .analyze("BEGIN; ALTER TABLE t1 RENAME TO t2; ROLLBACK;", &mut state)
            .unwrap();

        assert!(state.relation_is_present(&t1_id));
        assert!(!state.relation_is_present(&object_id("public", "t2")));
        assert_eq!(state.local.graph.edges()[0].referenced, t1_id);
    }
}
