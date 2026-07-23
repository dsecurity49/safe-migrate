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
