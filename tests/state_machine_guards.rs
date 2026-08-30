mod common;

mod state_machine_guards_tests {
    use crate::common::*;
    use safe_migrate::analysis::state::AnalysisState;
    use safe_migrate::model::relation::{
        Persistence, RelationKind, RelationOverlay, RelationState,
    };

    #[test]
    fn test_skip_guard_create_table() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE TABLE t(id INT);", &mut state)
            .unwrap();
        engine
            .analyze("CREATE TABLE IF NOT EXISTS t(new_col INT);", &mut state)
            .unwrap();

        let rel = state.get_relation(&object_id("public", "t")).unwrap();
        if let RelationOverlay::Present(r) = rel {
            assert!(r.has_column("id"));
            assert!(!r.has_column("new_col"));
        } else {
            panic!("relation should be present");
        }
    }

    #[test]
    fn test_reversibility_type_widen() {
        let engine = setup_engine();
        let mut cache = safe_migrate::db::cache::DbCache::new();
        let tid = object_id("public", "t");
        let mut rel = RelationState::new(
            tid.clone(),
            object_id("public", "postgres"),
            0,
            Some(10),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        rel.apply_column_action(&safe_migrate::model::relation::ColumnAction::Add {
            name: "val".to_string(),
            data_type: Some("int".to_string()),
            not_null: false,
            default: None,
        });
        cache.insert_baseline(tid, rel);
        let mut state = AnalysisState::new(cache);

        // Run analysis
        let v = engine
            .analyze("ALTER TABLE t ALTER COLUMN val TYPE bigint;", &mut state)
            .unwrap();

        // Ensure that ReversibilityRule did not flag this as irreversible
        // We are checking for specific violations and widening SHOULD NOT trigger "irreversible-migration"
        // If TypeChangeRewriteRule flags it, that's fine.
        assert!(
            v.iter()
                .all(|viol| viol.rule_id != "irreversible-migration"),
            "ReversibilityRule flagged widening as irreversible: {:?}",
            v.iter()
                .filter(|viol| viol.rule_id == "irreversible-migration")
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_skip_guard_drop_column() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE TABLE t(id INT);", &mut state)
            .unwrap();
        assert!(
            engine
                .analyze("ALTER TABLE t DROP COLUMN IF EXISTS missing;", &mut state)
                .is_ok()
        );
    }

    #[test]
    fn test_skip_guard_drop_missing_objects() {
        let engine = setup_engine();
        let mut state = setup_state();

        assert!(
            engine
                .analyze("DROP TABLE IF EXISTS missing;", &mut state)
                .is_ok()
        );
        assert!(
            engine
                .analyze("DROP VIEW IF EXISTS missing;", &mut state)
                .is_ok()
        );
        assert!(
            engine
                .analyze("DROP MATERIALIZED VIEW IF EXISTS missing;", &mut state)
                .is_ok()
        );
        assert!(
            engine
                .analyze("DROP INDEX IF EXISTS missing;", &mut state)
                .is_ok()
        );
        assert!(
            engine
                .analyze("DROP SEQUENCE IF EXISTS missing;", &mut state)
                .is_ok()
        );
        assert!(
            engine
                .analyze("DROP DOMAIN IF EXISTS missing;", &mut state)
                .is_ok()
        );
    }

    #[test]
    fn schema_neutral_application_name_keeps_exact_confidence() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze("SET application_name = 'migration-check';", &mut state)
            .unwrap();

        assert!(violations.is_empty());
        assert_eq!(
            state.local.confidence,
            safe_migrate::analysis::state::Confidence::Exact
        );
    }

    #[test]
    fn unknown_scoped_target_in_multi_drop_preserves_known_targets() {
        let engine = setup_engine();
        let mut cache = safe_migrate::db::cache::DbCache::new();
        cache.metadata.schemas = Some(vec!["app".to_string()]);
        let table_id = object_id("app", "known_table");
        let view_id = object_id("app", "known_view");
        let materialized_view_id = object_id("app", "known_materialized_view");
        cache.insert_baseline(
            table_id.clone(),
            RelationState::new(
                table_id.clone(),
                object_id("", "postgres"),
                0,
                None,
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        cache.insert_baseline(
            view_id.clone(),
            RelationState::new(
                view_id.clone(),
                object_id("", "postgres"),
                0,
                None,
                RelationKind::View,
                Persistence::Permanent,
                0,
            ),
        );
        cache.insert_baseline(
            materialized_view_id.clone(),
            RelationState::new(
                materialized_view_id.clone(),
                object_id("", "postgres"),
                0,
                None,
                RelationKind::MaterializedView,
                Persistence::Permanent,
                0,
            ),
        );
        let mut state = AnalysisState::new(cache);

        engine
            .analyze(
                "DROP TABLE IF EXISTS app.known_table, tenant.unknown_table;",
                &mut state,
            )
            .unwrap();
        engine
            .analyze("DROP VIEW app.known_view, tenant.unknown_view;", &mut state)
            .unwrap();
        engine
            .analyze(
                "DROP MATERIALIZED VIEW app.known_materialized_view, tenant.unknown_materialized_view;",
                &mut state,
            )
            .unwrap();

        assert!(state.relation_is_present(&table_id));
        assert!(state.relation_is_present(&view_id));
        assert!(state.relation_is_present(&materialized_view_id));
        assert_eq!(
            state.local.confidence,
            safe_migrate::analysis::state::Confidence::Tainted
        );
    }

    #[test]
    fn missing_unguarded_drop_aborts_following_transaction_statements() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "BEGIN; DROP VIEW missing_view; CREATE TABLE should_not_exist(id int); COMMIT;",
                &mut state,
            )
            .unwrap();

        assert!(
            violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );
        assert!(!state.relation_is_present(&object_id("public", "should_not_exist")));
    }

    #[test]
    fn guarded_drop_still_rejects_the_wrong_relation_kind() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();

        let violations = engine
            .analyze("DROP VIEW IF EXISTS t;", &mut state)
            .unwrap();

        assert!(state.relation_is_present(&object_id("public", "t")));
        assert!(
            violations
                .iter()
                .any(|violation| violation.rule_id == "chain-conflict")
        );
    }

    #[test]
    fn test_skip_guard_create_index() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();
        engine
            .analyze("CREATE INDEX idx ON t(id);", &mut state)
            .unwrap();

        let edge_count = state
            .local
            .graph
            .edges()
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    safe_migrate::analysis::graph::DependencyKind::IndexOnRelation { .. }
                )
            })
            .count();
        engine
            .analyze("CREATE INDEX IF NOT EXISTS idx ON t(id);", &mut state)
            .unwrap();

        assert_eq!(
            state
                .local
                .graph
                .edges()
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::analysis::graph::DependencyKind::IndexOnRelation { .. }
                ))
                .count(),
            edge_count
        );
    }

    #[test]
    fn test_skip_guard_create_sequence() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine.analyze("CREATE SEQUENCE s;", &mut state).unwrap();
        let before = state
            .local
            .graph
            .edges()
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    safe_migrate::analysis::graph::DependencyKind::SequenceOwnedBy { .. }
                )
            })
            .count();
        engine
            .analyze(
                "CREATE SEQUENCE IF NOT EXISTS s OWNED BY foo.bar;",
                &mut state,
            )
            .unwrap();
        assert_eq!(
            state
                .local
                .graph
                .edges()
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::analysis::graph::DependencyKind::SequenceOwnedBy { .. }
                ))
                .count(),
            before
        );
    }
}
