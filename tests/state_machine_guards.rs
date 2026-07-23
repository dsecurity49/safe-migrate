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
            .edges
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
                .edges
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
            .edges
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
                .edges
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

// ─────────────────────────────────────────────
// 2. Rule Evaluation Exhaustion
// ─────────────────────────────────────────────
