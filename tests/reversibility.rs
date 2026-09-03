mod common;

mod reversibility_tests {
    use crate::common::*;
    use safe_migrate::_internal::analysis::state::AnalysisState;
    use safe_migrate::_internal::model::relation::{Persistence, RelationKind, RelationState};
    use safe_migrate::_internal::report::violations::ViolationTier;

    #[test]
    fn test_reversibility_drop_column_empty_table() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id INT);", &mut state)
            .unwrap();
        let v = engine
            .analyze("ALTER TABLE t DROP COLUMN id;", &mut state)
            .unwrap();
        assert!(
            v.iter()
                .any(|violation| violation.tier == ViolationTier::Tier3)
        );
    }

    #[test]
    fn test_reversibility_drop_column_nonempty_table() {
        let engine = setup_engine();
        let mut cache = safe_migrate::_internal::db::cache::DbCache::new();
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
        rel.apply_column_action(&safe_migrate::_internal::model::relation::ColumnAction::Add {
            name: "id".to_string(),
            data_type: Some("int".to_string()),
            not_null: false,
            default: None,
        });
        cache.insert_baseline(tid.clone(), rel);
        let mut state = AnalysisState::new(cache);
        let v = engine
            .analyze("ALTER TABLE t DROP COLUMN id;", &mut state)
            .unwrap();
        assert!(
            v.iter()
                .any(|violation| violation.tier == ViolationTier::Tier1)
        );
    }

    #[test]
    fn test_reversibility_drop_column_added_in_transaction() {
        let engine = setup_engine();
        let mut cache = safe_migrate::_internal::db::cache::DbCache::new();
        let tid = object_id("public", "t");
        cache.insert_baseline(
            tid.clone(),
            RelationState::new(
                tid,
                object_id("public", "postgres"),
                0,
                Some(10),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        let mut state = AnalysisState::new(cache);

        // Run BEGIN; ADD COLUMN; DROP COLUMN; COMMIT;
        let v = engine
            .analyze(
                "BEGIN; ALTER TABLE t ADD COLUMN val int; ALTER TABLE t DROP COLUMN val; COMMIT;",
                &mut state,
            )
            .unwrap();

        // DROP COLUMN should be Tier3, not Tier1
        assert!(
            v.iter()
                .all(|violation| violation.rule_id != "irreversible-migration"
                    || violation.tier != ViolationTier::Tier1)
        );
    }

    #[test]
    fn test_reversibility_drop_table() {
        let engine = setup_engine();
        let mut cache = safe_migrate::_internal::db::cache::DbCache::new();
        let tid = object_id("public", "t");
        cache.insert_baseline(
            tid.clone(),
            RelationState::new(
                tid,
                object_id("public", "postgres"),
                0,
                Some(10),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        let mut state = AnalysisState::new(cache);
        let v = engine.analyze("DROP TABLE t;", &mut state).unwrap();
        assert!(
            v.iter()
                .any(|violation| violation.tier == ViolationTier::Tier1)
        );
    }

    #[test]
    fn test_reversibility_rename_table() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id INT);", &mut state)
            .unwrap();
        let v = engine
            .analyze("ALTER TABLE t RENAME TO t2;", &mut state)
            .unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn test_reversibility_add_nullable_column_no_default() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id INT);", &mut state)
            .unwrap();
        let v = engine
            .analyze("ALTER TABLE t ADD COLUMN name TEXT;", &mut state)
            .unwrap();
        // This is safe, hence reversibility rule shouldn't emit violation.
        // It might be caught by TypeChangeRewriteRule? No, it's AddColumn.
        // The ReversibilityRule itself checks `classify`.
        // If classify returns Reversible, v will be empty.
        assert!(
            v.iter()
                .all(|violation| violation.rule_id != "irreversible-migration")
        );
    }

    #[test]
    fn test_reversibility_type_widen() {
        let engine = setup_engine();
        let mut cache = safe_migrate::_internal::db::cache::DbCache::new();
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
        rel.apply_column_action(&safe_migrate::_internal::model::relation::ColumnAction::Add {
            name: "val".to_string(),
            data_type: Some("int".to_string()),
            not_null: false,
            default: None,
        });
        cache.insert_baseline(tid, rel);
        let mut state = AnalysisState::new(cache);

        let v = engine
            .analyze("ALTER TABLE t ALTER COLUMN val TYPE bigint;", &mut state)
            .unwrap();

        assert!(
            v.iter()
                .all(|viol| viol.rule_id != "irreversible-migration")
        );
    }

    #[test]
    fn test_reversibility_type_narrow() {
        let engine = setup_engine();
        let mut cache = safe_migrate::_internal::db::cache::DbCache::new();
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
        rel.apply_column_action(&safe_migrate::_internal::model::relation::ColumnAction::Add {
            name: "val".to_string(),
            data_type: Some("bigint".to_string()),
            not_null: false,
            default: None,
        });
        cache.insert_baseline(tid, rel);
        let mut state = AnalysisState::new(cache);
        // Narrowing bigint -> int is unsafe
        let v = engine
            .analyze("ALTER TABLE t ALTER COLUMN val TYPE int;", &mut state)
            .unwrap();
        // This should be flagged as conditionally reversible by ReversibilityRule
        assert!(
            v.iter()
                .any(|violation| violation.rule_id == "irreversible-migration")
        );
    }

    /// text -> varchar(n) is a narrowing change and should be flagged as lossy
    #[test]
    fn test_reversibility_text_to_varchar_narrowing() {
        let engine = setup_engine();
        let mut cache = safe_migrate::_internal::db::cache::DbCache::new();
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
        rel.apply_column_action(&safe_migrate::_internal::model::relation::ColumnAction::Add {
            name: "data".to_string(),
            data_type: Some("text".to_string()),
            not_null: false,
            default: None,
        });
        cache.insert_baseline(tid, rel);
        let mut state = AnalysisState::new(cache);
        // text -> varchar(50) is lossy narrowing
        let v = engine
            .analyze(
                "ALTER TABLE t ALTER COLUMN data TYPE varchar(50);",
                &mut state,
            )
            .unwrap();
        // Should be flagged as irreversible by ReversibilityRule
        assert!(
            v.iter()
                .any(|violation| violation.rule_id == "irreversible-migration"),
            "text -> varchar(50) should be flagged as irreversible (lossy narrowing)"
        );
    }
}

// ─────────────────────────────────────────────
// 3. State Mutation Topology
// ─────────────────────────────────────────────
