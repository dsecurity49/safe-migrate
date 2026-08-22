mod common;

mod destructive_rule_tests {
    use crate::common::*;
    use safe_migrate::analysis::state::AnalysisState;
    use safe_migrate::ast::identifiers::ObjectId;
    use safe_migrate::model::column::Column;
    use safe_migrate::model::relation::{Persistence, RelationKind, RelationState};
    use safe_migrate::report::violations::ViolationTier;

    #[test]
    fn test_rule_drop_view_cascade() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE t(id int); CREATE VIEW v AS SELECT * FROM t;",
                &mut state,
            )
            .unwrap();

        // Drop view with cascade
        let v = engine.analyze("DROP VIEW v CASCADE;", &mut state).unwrap();

        assert!(
            v.iter().any(|v| v.rule_id == "destructive-general-cascade"),
            "DROP VIEW CASCADE should trigger GeneralCascadeRule"
        );
    }

    #[test]
    fn test_rule_drop_database() {
        let engine = setup_engine();
        let mut state = setup_state();

        let v = engine
            .analyze("DROP DATABASE test_db;", &mut state)
            .unwrap();

        assert!(
            v.iter().any(|v| v.rule_id == "drop-database"),
            "DROP DATABASE should trigger DropDatabaseRule"
        );
    }

    #[test]
    fn test_rule_create_table_as_select() {
        let engine = setup_engine();
        let mut state = setup_state();

        let v = engine
            .analyze(
                "CREATE TABLE backup AS SELECT * FROM source_table;",
                &mut state,
            )
            .unwrap();

        assert!(
            v.iter().any(|v| v.rule_id == "create-table-as-select"),
            "CREATE TABLE AS SELECT should trigger CreateTableAsSelectRule"
        );
    }

    #[test]
    fn test_rule_type_change_rewrite_varchar_to_text() {
        let engine = setup_engine();

        let mut cache = safe_migrate::db::cache::DbCache::new();
        let mut relation = safe_migrate::model::relation::RelationState::new(
            object_id("public", "t"),
            ObjectId::new("public", "postgres"),
            0,
            Some(500),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        relation.columns.push(Column {
            name: "data".into(),
            data_type: Some("character varying(100)".into()),
            type_id: None,
            is_nullable: false,
            default: None,
            avg_width: None,
            default_expr_text: None,
            type_modifier: Some(104),
        });
        cache.insert_baseline(object_id("public", "t"), relation);

        let mut state = AnalysisState::new(cache);

        let v = engine
            .analyze("ALTER TABLE t ALTER COLUMN data TYPE text;", &mut state)
            .unwrap();

        assert!(
            !v.iter()
                .any(|violation| violation.rule_id == "type-change-rewrite"),
            "varchar to text must not be reported as a rewrite"
        );
    }

    #[test]
    fn test_rule_type_change_narrow_varchar_unbounded() {
        let engine = setup_engine();
        let mut cache = safe_migrate::db::cache::DbCache::new();
        let tid = object_id("public", "t");
        let mut rel = RelationState::new(
            tid.clone(),
            object_id("public", "postgres"),
            0,
            Some(100),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        rel.apply_column_action(&safe_migrate::model::relation::ColumnAction::Add {
            name: "val".to_string(),
            data_type: Some("varchar".to_string()),
            not_null: false,
            default: None,
        });
        cache.insert_baseline(tid, rel);
        let mut state = AnalysisState::new(cache);

        let v = engine
            .analyze(
                "ALTER TABLE t ALTER COLUMN val TYPE varchar(10);",
                &mut state,
            )
            .unwrap();

        assert!(
            v.iter().any(|viol| viol.rule_id == "type-change-rewrite"
                && viol.reason.contains("narrows VARCHAR precision (lossy)")),
            "Unbounded to bounded varchar change should be flagged as lossy narrowing: {:?}",
            v
        );
    }

    /// Varchar narrowing: 255→50 should be flagged as lossy, 50→255 should not
    #[test]
    fn test_rule_varchar_narrowing_lossy() {
        let engine = setup_engine();

        let mut cache = safe_migrate::db::cache::DbCache::new();
        let mut rel = safe_migrate::model::relation::RelationState::new(
            object_id("public", "t"),
            ObjectId::new("public", "postgres"),
            0,
            Some(500),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        // Column with varchar(255): atttypmod = 255 + 4 = 259
        rel.columns.push(Column {
            name: "data".into(),
            data_type: Some("character varying(255)".into()),
            type_id: None,
            is_nullable: true,
            default: None,
            avg_width: None,
            default_expr_text: None,
            type_modifier: Some(259),
        });
        cache.insert_baseline(object_id("public", "t"), rel);

        let mut state = AnalysisState::new(cache);

        // Already has baseline column with type_modifier=259 (varchar(255))
        // Now try narrowing to varchar(50): atttypmod = 50 + 4 = 54
        let v = engine
            .analyze(
                "ALTER TABLE t ALTER COLUMN data TYPE varchar(50);",
                &mut state,
            )
            .unwrap();

        assert!(
            v.iter()
                .any(|v| v.rule_id == "type-change-rewrite" && v.reason.contains("narrows")),
            "255→50 should be flagged as lossy VARCHAR narrowing"
        );

        // Now try widening: varchar(50) → varchar(255) should NOT flag as lossy
        let mut cache2 = safe_migrate::db::cache::DbCache::new();
        let mut rel2 = safe_migrate::model::relation::RelationState::new(
            object_id("public", "t"),
            ObjectId::new("public", "postgres"),
            0,
            Some(500),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        rel2.columns.push(Column {
            name: "data".into(),
            data_type: Some("character varying(50)".into()),
            type_id: None,
            is_nullable: true,
            default: None,
            avg_width: None,
            default_expr_text: None,
            type_modifier: Some(54),
        });
        cache2.insert_baseline(object_id("public", "t"), rel2);
        let mut state2 = AnalysisState::new(cache2);

        let v2 = engine
            .analyze(
                "ALTER TABLE t ALTER COLUMN data TYPE varchar(255);",
                &mut state2,
            )
            .unwrap();

        // Should NOT be flagged as a rewrite
        assert!(
            !v2.iter().any(|v| v.rule_id == "type-change-rewrite"),
            "50→255 should be safe and NOT trigger type-change-rewrite: {:?}",
            v2
        );
    }

    /// text -> varchar(n) is a narrowing change and should be flagged
    #[test]
    fn test_rule_text_to_varchar_narrowing() {
        let engine = setup_engine();

        let mut cache = safe_migrate::db::cache::DbCache::new();
        let mut rel = safe_migrate::model::relation::RelationState::new(
            object_id("public", "t"),
            ObjectId::new("public", "postgres"),
            0,
            Some(500),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        rel.columns.push(Column {
            name: "data".into(),
            data_type: Some("text".into()),
            type_id: None,
            is_nullable: true,
            default: None,
            avg_width: None,
            default_expr_text: None,
            type_modifier: None, // text has no modifier
        });
        cache.insert_baseline(object_id("public", "t"), rel);

        let mut state = AnalysisState::new(cache);

        let v = engine
            .analyze(
                "ALTER TABLE t ALTER COLUMN data TYPE varchar(50);",
                &mut state,
            )
            .unwrap();

        assert!(
            v.iter()
                .any(|v| v.rule_id == "type-change-rewrite" && v.reason.contains("narrows")),
            "text->varchar(50) should be flagged as lossy narrowing: {:?}",
            v
        );
    }

    /// DriftDetectionRule: DROP TABLE that doesn't exist in baseline → Tier 1
    #[test]
    fn test_rule_drift_detection_drop_missing_table() {
        // Simulate a live DB cache with table "existing_tbl"
        let mut cache = safe_migrate::db::cache::DbCache::new();
        cache.insert_baseline(
            object_id("public", "existing_tbl"),
            safe_migrate::model::relation::RelationState::new(
                object_id("public", "existing_tbl"),
                ObjectId::new("public", "postgres"),
                0,
                Some(100),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        let engine = setup_engine();
        let mut state = AnalysisState::new(cache);

        // DROP TABLE that is NOT in baseline
        let v = engine
            .analyze("DROP TABLE nonexistent_tbl;", &mut state)
            .unwrap();

        assert!(
            v.iter().any(|v| v.rule_id == "schema-drift"),
            "DriftDetectionRule should flag DROP on table not in baseline"
        );
        // The cache is authoritative for this schema. Taint produced by this
        // statement must not downgrade the statement's own drift evidence.
        assert_eq!(
            v.iter().find(|v| v.rule_id == "schema-drift").unwrap().tier,
            ViolationTier::Tier1,
            "An exact baseline proves this missing DROP is production drift"
        );
    }

    /// DriftDetectionRule: ALTER TABLE that doesn't exist in baseline → Tier 1
    #[test]
    fn test_rule_drift_detection_alter_missing_table() {
        let mut cache = safe_migrate::db::cache::DbCache::new();
        cache.insert_baseline(
            object_id("public", "existing_tbl"),
            safe_migrate::model::relation::RelationState::new(
                object_id("public", "existing_tbl"),
                ObjectId::new("public", "postgres"),
                0,
                Some(100),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        let engine = setup_engine();
        let mut state = AnalysisState::new(cache);

        // ALTER TABLE that is NOT in baseline
        let v = engine
            .analyze("ALTER TABLE nonexistent_tbl ADD COLUMN x int;", &mut state)
            .unwrap();

        assert!(
            v.iter().any(|v| v.rule_id == "schema-drift"),
            "DriftDetectionRule should flag ALTER on table not in baseline"
        );
        assert_eq!(
            v.iter().find(|v| v.rule_id == "schema-drift").unwrap().tier,
            ViolationTier::Tier1,
            "Drift should be Tier1"
        );
    }

    #[test]
    fn test_rule_drift_detection_drop_existing_table() {
        let mut cache = safe_migrate::db::cache::DbCache::new();
        cache.insert_baseline(
            object_id("public", "existing_tbl"),
            safe_migrate::model::relation::RelationState::new(
                object_id("public", "existing_tbl"),
                ObjectId::new("public", "postgres"),
                0,
                Some(100),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        let engine = setup_engine();
        let mut state = AnalysisState::new(cache);

        // DROP TABLE that is in baseline should NOT flag schema-drift
        let v = engine
            .analyze("DROP TABLE existing_tbl;", &mut state)
            .unwrap();

        assert!(
            !v.iter().any(|v| v.rule_id == "schema-drift"),
            "DriftDetectionRule should NOT flag DROP on table present in baseline: {:?}",
            v
        );
    }

    #[test]
    fn test_rule_drift_detection_non_table_objects() {
        let engine = setup_engine();
        let mut state = setup_state();

        // 1. DROP INDEX
        let v = engine
            .analyze("DROP INDEX nonexistent_idx;", &mut state)
            .unwrap();
        assert!(
            v.iter()
                .any(|v| v.rule_id == "schema-drift" && v.reason.contains("index"))
        );

        // 2. DROP SEQUENCE
        let v = engine
            .analyze("DROP SEQUENCE nonexistent_seq;", &mut state)
            .unwrap();
        assert!(
            v.iter()
                .any(|v| v.rule_id == "schema-drift" && v.reason.contains("sequence"))
        );

        // 3. ALTER TYPE
        let v = engine
            .analyze("ALTER TYPE nonexistent_type ADD VALUE 'val';", &mut state)
            .unwrap();
        assert!(
            v.iter()
                .any(|v| v.rule_id == "schema-drift" && v.reason.contains("type"))
        );

        // 4. ALTER FUNCTION
        let v = engine
            .analyze("ALTER FUNCTION nonexistent_func() IMMUTABLE;", &mut state)
            .unwrap();
        assert!(
            v.iter()
                .any(|v| v.rule_id == "schema-drift" && v.reason.contains("function"))
        );
    }

    #[test]
    fn test_rule_type_change_rewrite_unsafe_small() {
        let engine = setup_engine();

        let mut cache = safe_migrate::db::cache::DbCache::new();
        cache.insert_baseline(
            object_id("public", "t"),
            safe_migrate::model::relation::RelationState::new(
                object_id("public", "t"),
                ObjectId::new("public", "postgres"),
                0,
                Some(500),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );

        let mut state = AnalysisState::new(cache);

        engine
            .analyze("CREATE TABLE t(data int);", &mut state)
            .unwrap();

        let v = engine
            .analyze("ALTER TABLE t ALTER COLUMN data TYPE text;", &mut state)
            .unwrap();

        assert!(
            v.iter().any(|v| v.rule_id == "type-change-rewrite"),
            "int to text should trigger type-change-rewrite"
        );

        // For small tables, it should be Tier2 (not escalated)
        if let Some(viol) = v.iter().find(|v| v.rule_id == "type-change-rewrite") {
            assert_eq!(
                viol.tier,
                ViolationTier::Tier2,
                "Small table unsafe type change should be Tier2"
            );
        }
    }
}
