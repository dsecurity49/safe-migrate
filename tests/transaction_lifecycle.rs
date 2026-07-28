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
                "BEGIN; COMMIT AND CHAIN; CREATE INDEX CONCURRENTLY idx ON users (id); ROLLBACK;",
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
                "BEGIN; ROLLBACK AND CHAIN; CREATE INDEX CONCURRENTLY idx ON users (id); ROLLBACK;",
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
                "BEGIN; SAVEPOINT MixedCase; ROLLBACK TO SAVEPOINT mixedcase; CREATE INDEX CONCURRENTLY idx ON users (id); ROLLBACK;",
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
            .edges
            .push(safe_migrate::analysis::graph::DependencyEdge {
                dependent: v1_id.clone(),
                referenced: t1_id.clone(),
                kind: safe_migrate::analysis::graph::DependencyKind::ViewDependency {
                    view_generation: 0,
                },
            });

        // Assert initial view dependency points to t1
        assert_eq!(state.local.graph.edges[0].referenced, t1_id);

        // Run rename under transaction and rollback
        engine
            .analyze("BEGIN; ALTER TABLE t1 RENAME TO t2; ROLLBACK;", &mut state)
            .unwrap();

        // Check that table name is restored to t1, and the view dependency is restored to t1
        assert!(state.relation_is_present(&t1_id));
        assert!(!state.relation_is_present(&object_id("public", "t2")));
        assert_eq!(state.local.graph.edges[0].referenced, t1_id);
    }
}

// ─────────────────────────────────────────────
// 5. AST Expression Parsing Exhaustion
// ─────────────────────────────────────────────
