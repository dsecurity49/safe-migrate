mod reversibility_tests {
    use crate::common::*;
    use safe_migrate::_internal::analysis::state::AnalysisState;
    use safe_migrate::_internal::model::relation::{Persistence, RelationKind, RelationState};
    use safe_migrate::_internal::report::violations::ViolationTier;

    fn baseline_with_columns(rows: u64, columns: &[(&str, &str)]) -> AnalysisState {
        let mut cache = crate::common::synced_cache();
        let tid = object_id("public", "t");
        let mut rel = RelationState::new(
            tid.clone(),
            object_id("public", "postgres"),
            0,
            Some(rows),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        for (name, data_type) in columns {
            rel.apply_column_action(
                &safe_migrate::_internal::model::relation::ColumnAction::Add {
                    name: (*name).to_string(),
                    data_type: Some((*data_type).to_string()),
                    not_null: false,
                    default: None,
                },
            );
        }
        cache.insert_baseline(tid, rel);
        AnalysisState::new(cache)
    }

    fn irreversible_tiers(
        violations: &[safe_migrate::_internal::report::violations::Violation],
    ) -> Vec<ViolationTier> {
        violations
            .iter()
            .filter(|violation| violation.rule_id == "irreversible-migration")
            .map(|violation| violation.tier.clone())
            .collect()
    }

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
        let mut cache = crate::common::synced_cache();
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
        rel.apply_column_action(
            &safe_migrate::_internal::model::relation::ColumnAction::Add {
                name: "id".to_string(),
                data_type: Some("int".to_string()),
                not_null: false,
                default: None,
            },
        );
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
        let mut cache = crate::common::synced_cache();
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
    fn test_reversibility_rename_then_drop_existing_column_keeps_data_loss_tier() {
        let engine = setup_engine();
        let mut state = baseline_with_columns(10, &[("customer_id", "int")]);

        let v = engine
            .analyze(
                "BEGIN; ALTER TABLE t RENAME COLUMN customer_id TO account_id; \
                 ALTER TABLE t DROP COLUMN account_id; COMMIT;",
                &mut state,
            )
            .unwrap();

        assert_eq!(
            irreversible_tiers(&v),
            vec![ViolationTier::Tier1],
            "dropping a renamed pre-existing column still destroys data: {v:?}"
        );
    }

    #[test]
    fn test_reversibility_add_rename_then_drop_column_stays_tier3() {
        let engine = setup_engine();
        let mut state = baseline_with_columns(10, &[("id", "int")]);

        let v = engine
            .analyze(
                "BEGIN; ALTER TABLE t ADD COLUMN val int; \
                 ALTER TABLE t RENAME COLUMN val TO val2; \
                 ALTER TABLE t DROP COLUMN val2; COMMIT;",
                &mut state,
            )
            .unwrap();

        assert_eq!(
            irreversible_tiers(&v),
            vec![ViolationTier::Tier3],
            "a column created, renamed, and dropped in one transaction holds no pre-existing data: {v:?}"
        );
    }

    #[test]
    fn test_reversibility_rename_then_drop_after_savepoint_rollback_keeps_data_loss_tier() {
        let engine = setup_engine();
        let mut state = baseline_with_columns(10, &[("customer_id", "int")]);

        let v = engine
            .analyze(
                "BEGIN; ALTER TABLE t RENAME COLUMN customer_id TO account_id; \
                 SAVEPOINT s; ALTER TABLE t DROP COLUMN account_id; \
                 ROLLBACK TO s; ALTER TABLE t DROP COLUMN account_id; COMMIT;",
                &mut state,
            )
            .unwrap();

        assert_eq!(
            irreversible_tiers(&v),
            vec![ViolationTier::Tier1, ViolationTier::Tier1],
            "savepoint rollback must not turn a pre-existing column into a transaction-created one: {v:?}"
        );
    }

    #[test]
    fn test_reversibility_added_column_after_savepoint_rollback_stays_tier3() {
        let engine = setup_engine();
        let mut state = baseline_with_columns(10, &[("id", "int")]);

        let v = engine
            .analyze(
                "BEGIN; ALTER TABLE t ADD COLUMN val int; SAVEPOINT s; \
                 ALTER TABLE t DROP COLUMN val; ROLLBACK TO s; \
                 ALTER TABLE t DROP COLUMN val; COMMIT;",
                &mut state,
            )
            .unwrap();

        assert_eq!(
            irreversible_tiers(&v),
            vec![ViolationTier::Tier3, ViolationTier::Tier3],
            "savepoint rollback restores the transaction-created provenance: {v:?}"
        );
    }

    #[test]
    fn test_reversibility_added_column_survives_table_rename_before_drop() {
        let engine = setup_engine();
        let mut state = baseline_with_columns(10, &[("id", "int")]);

        let v = engine
            .analyze(
                "BEGIN; ALTER TABLE t ADD COLUMN val int; \
                 ALTER TABLE t RENAME TO t2; \
                 ALTER TABLE t2 DROP COLUMN val; COMMIT;",
                &mut state,
            )
            .unwrap();

        assert_eq!(
            irreversible_tiers(&v),
            vec![ViolationTier::Tier3],
            "renaming the table must not hide that the column was created in the transaction: {v:?}"
        );
    }

    #[test]
    fn test_reversibility_added_column_survives_table_and_column_rename() {
        let engine = setup_engine();
        let mut state = baseline_with_columns(10, &[("id", "int")]);

        let v = engine
            .analyze(
                "BEGIN; ALTER TABLE t ADD COLUMN val int; \
                 ALTER TABLE t RENAME TO t2; \
                 ALTER TABLE t2 RENAME COLUMN val TO val2; \
                 ALTER TABLE t2 DROP COLUMN val2; COMMIT;",
                &mut state,
            )
            .unwrap();

        assert_eq!(
            irreversible_tiers(&v),
            vec![ViolationTier::Tier3],
            "table and column renames must preserve the column's transaction provenance: {v:?}"
        );
    }

    #[test]
    fn test_reversibility_added_column_survives_table_schema_move() {
        let engine = setup_engine();
        let mut state = baseline_with_columns(10, &[("id", "int")]);

        let v = engine
            .analyze(
                "BEGIN; ALTER TABLE t ADD COLUMN val int; CREATE SCHEMA other; \
                 ALTER TABLE t SET SCHEMA other; \
                 ALTER TABLE other.t DROP COLUMN val; COMMIT;",
                &mut state,
            )
            .unwrap();

        assert_eq!(
            irreversible_tiers(&v),
            vec![ViolationTier::Tier3],
            "a schema move changes the relation id and must preserve provenance: {v:?}"
        );
    }

    #[test]
    fn test_reversibility_renamed_table_drop_existing_column_keeps_data_loss_tier() {
        let engine = setup_engine();
        let mut state = baseline_with_columns(10, &[("customer_id", "int")]);

        let v = engine
            .analyze(
                "BEGIN; ALTER TABLE t RENAME TO t2; \
                 ALTER TABLE t2 DROP COLUMN customer_id; COMMIT;",
                &mut state,
            )
            .unwrap();

        assert_eq!(
            irreversible_tiers(&v),
            vec![ViolationTier::Tier1],
            "a pre-existing column keeps its data-loss tier across a table rename: {v:?}"
        );
    }

    #[test]
    fn test_reversibility_reused_table_name_tracks_the_new_relation() {
        let engine = setup_engine();
        let mut state = baseline_with_columns(10, &[("customer_id", "int")]);

        let v = engine
            .analyze(
                "BEGIN; ALTER TABLE t RENAME TO t2; CREATE TABLE t (id int); \
                 ALTER TABLE t DROP COLUMN id; COMMIT;",
                &mut state,
            )
            .unwrap();

        assert_eq!(
            irreversible_tiers(&v),
            vec![ViolationTier::Tier3],
            "a table reusing the old name must not inherit the renamed table's provenance: {v:?}"
        );
    }

    #[test]
    fn test_reversibility_added_column_survives_table_rename_after_savepoint_rollback() {
        let engine = setup_engine();
        let mut state = baseline_with_columns(10, &[("id", "int")]);

        let v = engine
            .analyze(
                "BEGIN; ALTER TABLE t ADD COLUMN val int; SAVEPOINT s; \
                 ALTER TABLE t RENAME TO t2; ALTER TABLE t2 DROP COLUMN val; \
                 ROLLBACK TO s; ALTER TABLE t DROP COLUMN val; COMMIT;",
                &mut state,
            )
            .unwrap();

        assert_eq!(
            irreversible_tiers(&v),
            vec![ViolationTier::Tier3, ViolationTier::Tier3],
            "rolling back a table rename must preserve the added column's provenance: {v:?}"
        );
    }

    #[test]
    fn test_reversibility_added_column_survives_savepoint_release() {
        let engine = setup_engine();
        let mut state = baseline_with_columns(10, &[("id", "int")]);

        let v = engine
            .analyze(
                "BEGIN; ALTER TABLE t ADD COLUMN val int; SAVEPOINT s; \
                 RELEASE s; ALTER TABLE t DROP COLUMN val; COMMIT;",
                &mut state,
            )
            .unwrap();

        assert_eq!(
            irreversible_tiers(&v),
            vec![ViolationTier::Tier3],
            "releasing a savepoint must preserve transaction-created provenance: {v:?}"
        );
    }

    #[test]
    fn test_reversibility_drop_table() {
        let engine = setup_engine();
        let mut cache = crate::common::synced_cache();
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
        let mut cache = crate::common::synced_cache();
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
        rel.apply_column_action(
            &safe_migrate::_internal::model::relation::ColumnAction::Add {
                name: "val".to_string(),
                data_type: Some("int".to_string()),
                not_null: false,
                default: None,
            },
        );
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
        let mut cache = crate::common::synced_cache();
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
        rel.apply_column_action(
            &safe_migrate::_internal::model::relation::ColumnAction::Add {
                name: "val".to_string(),
                data_type: Some("bigint".to_string()),
                not_null: false,
                default: None,
            },
        );
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
        let mut cache = crate::common::synced_cache();
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
        rel.apply_column_action(
            &safe_migrate::_internal::model::relation::ColumnAction::Add {
                name: "data".to_string(),
                data_type: Some("text".to_string()),
                not_null: false,
                default: None,
            },
        );
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
