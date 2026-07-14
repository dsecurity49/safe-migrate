mod common;

mod phase10_bug_fixes_and_sorting_tests {
    use crate::common::*;
    use safe_migrate::analysis::state::AnalysisState;
    use safe_migrate::ast::identifiers::ObjectId;
    use safe_migrate::db::cache::DbCache;
    use safe_migrate::model::relation::{Persistence, RelationKind};
    use safe_migrate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};

    #[test]
    fn test_bug008_index_not_in_baseline_relations() {
        let mut cache = DbCache::new();
        cache.indexes.push(safe_migrate::db::cache::IndexCache {
            index_id: object_id("public", "idx_accounts_username"),
            table_id: object_id("public", "accounts"),
        });
        let state = AnalysisState::new(cache);
        assert!(
            !state
                .baseline_relations
                .contains(&object_id("public", "idx_accounts_username"))
        );
    }

    #[test]
    fn test_bug008_index_in_baseline_indexes() {
        let mut cache = DbCache::new();
        cache.indexes.push(safe_migrate::db::cache::IndexCache {
            index_id: object_id("public", "idx_accounts_username"),
            table_id: object_id("public", "accounts"),
        });
        let state = AnalysisState::new(cache);
        assert!(
            state
                .baseline_indexes
                .contains(&object_id("public", "idx_accounts_username"))
        );
    }

    #[test]
    fn test_bug008_stale_stats_does_not_fire_on_index() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        cache.insert_baseline(
            object_id("public", "accounts"),
            safe_migrate::model::relation::RelationState::new(
                object_id("public", "accounts"),
                ObjectId::new("public", "postgres"),
                0,
                Some(500_000),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        cache.indexes.push(safe_migrate::db::cache::IndexCache {
            index_id: object_id("public", "idx_accounts_username"),
            table_id: object_id("public", "accounts"),
        });

        let mut state = AnalysisState::new(cache);

        let violations = engine
            .analyze("DROP INDEX idx_accounts_username;", &mut state)
            .unwrap();

        for v in &violations {
            if v.reason.contains("statistics are stale") {
                assert!(
                    !v.reason.contains("idx_accounts_username"),
                    "Should not fire stale stats warning on the index itself"
                );
            }
        }
    }

    #[test]
    fn test_add_column_now_default_not_flagged() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        cache.pg_version_num = Some(110000);
        cache.insert_baseline(
            object_id("public", "t"),
            safe_migrate::model::relation::RelationState::new(
                object_id("public", "t"),
                ObjectId::new("public", "postgres"),
                0,
                Some(500_000),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );

        let mut state = AnalysisState::new(cache);

        let violations = engine
            .analyze(
                "ALTER TABLE t ADD COLUMN created_at TIMESTAMP DEFAULT NOW();",
                &mut state,
            )
            .unwrap();

        assert!(
            !violations
                .iter()
                .any(|v| v.rule_id == "size-aware-add-column"),
            "Expected no size-aware-add-column violation for stable DEFAULT NOW() on PG11+, got: {:?}",
            violations
        );
    }

    #[test]
    fn test_drop_index_no_stale_stats_warning() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        cache.insert_baseline(
            object_id("public", "t"),
            safe_migrate::model::relation::RelationState::new(
                object_id("public", "t"),
                ObjectId::new("public", "postgres"),
                0,
                Some(500_000),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        cache.indexes.push(safe_migrate::db::cache::IndexCache {
            index_id: object_id("public", "idx_t_id"),
            table_id: object_id("public", "t"),
        });

        let mut state = AnalysisState::new(cache);

        let violations = engine.analyze("DROP INDEX idx_t_id;", &mut state).unwrap();

        assert!(
            violations
                .iter()
                .any(|v| v.rule_id == "require-concurrent-drop-index"),
            "Expected require-concurrent-drop-index violation"
        );

        assert!(
            !violations
                .iter()
                .any(|v| v.reason.contains("statistics are stale") || v.reason.contains("stale")),
            "Should not emit stale statistics warning on DROP INDEX, got: {:?}",
            violations
        );
    }

    #[test]
    fn test_deterministic_violation_sorting() {
        let engine = setup_engine();

        let mut cache = DbCache::new();
        cache.insert_baseline(
            object_id("public", "t"),
            safe_migrate::model::relation::RelationState::new(
                object_id("public", "t"),
                ObjectId::new("public", "postgres"),
                0,
                Some(500_000),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        let mut state = AnalysisState::new(cache);

        let sql = "CREATE INDEX idx2 ON t(a); CREATE INDEX idx1 ON t(b);";
        let violations = engine.analyze(sql, &mut state).unwrap();

        let idx_violations: Vec<&Violation> = violations
            .iter()
            .filter(|v| {
                v.rule_id == "require-concurrent-index"
                    && v.reason.contains("Synchronous index creation")
            })
            .collect();

        assert_eq!(idx_violations.len(), 2);
        assert_eq!(idx_violations[0].object_name, "public.idx2");
        assert_eq!(idx_violations[1].object_name, "public.idx1");
    }

    #[test]
    #[allow(clippy::useless_vec)]
    fn test_manual_violation_sorting() {
        let v_tier3 = Violation {
            source_range: Some(rowan::TextRange::new(0.into(), 10.into())),
            rule_id: "rule_a",
            operation_kind: OperationKind::DropTable,
            object_kind: ObjectKind::Table,
            object_name: "a".to_string(),
            tier: ViolationTier::Tier3,
            reason: "tier 3".to_string(),
            recipe: "recipe",
            dedup_key: None,
            sql: None,
            fk_dependency_related: false,
        };
        let v_tier1 = Violation {
            source_range: Some(rowan::TextRange::new(0.into(), 10.into())),
            rule_id: "rule_b",
            operation_kind: OperationKind::DropTable,
            object_kind: ObjectKind::Table,
            object_name: "b".to_string(),
            tier: ViolationTier::Tier1,
            reason: "tier 1".to_string(),
            recipe: "recipe",
            dedup_key: None,
            sql: None,
            fk_dependency_related: false,
        };
        let v_range_later = Violation {
            source_range: Some(rowan::TextRange::new(20.into(), 30.into())),
            rule_id: "rule_c",
            operation_kind: OperationKind::DropTable,
            object_kind: ObjectKind::Table,
            object_name: "c".to_string(),
            tier: ViolationTier::Tier1,
            reason: "tier 1 later range".to_string(),
            recipe: "recipe",
            dedup_key: None,
            sql: None,
            fk_dependency_related: false,
        };
        let v_name_later = Violation {
            source_range: Some(rowan::TextRange::new(0.into(), 10.into())),
            rule_id: "rule_b",
            operation_kind: OperationKind::DropTable,
            object_kind: ObjectKind::Table,
            object_name: "z".to_string(),
            tier: ViolationTier::Tier1,
            reason: "tier 1 name later".to_string(),
            recipe: "recipe",
            dedup_key: None,
            sql: None,
            fk_dependency_related: false,
        };

        let mut violations = vec![
            v_tier3.clone(),
            v_tier1.clone(),
            v_range_later.clone(),
            v_name_later.clone(),
        ];

        violations.sort_by(|a, b| {
            a.tier
                .cmp(&b.tier)
                .then_with(|| match (&a.source_range, &b.source_range) {
                    (Some(ar), Some(br)) => ar
                        .start()
                        .cmp(&br.start())
                        .then_with(|| ar.end().cmp(&br.end())),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                })
                .then_with(|| a.object_name.cmp(&b.object_name))
                .then_with(|| a.rule_id.cmp(b.rule_id))
        });

        assert_eq!(violations[0].reason, "tier 1");
        assert_eq!(violations[1].reason, "tier 1 name later");
        assert_eq!(violations[2].reason, "tier 1 later range");
        assert_eq!(violations[3].reason, "tier 3");
    }

    #[test]
    fn test_source_range_excludes_preceding_comments() {
        let engine = setup_engine();
        let mut state = setup_state();

        let sql = "-- This is a preceding comment\n   /* block comment */\n   DROP DATABASE my_db;";
        let violations = engine.analyze(sql, &mut state).unwrap();

        assert!(
            !violations.is_empty(),
            "expected a violation for DROP DATABASE"
        );
        let v = &violations[0];
        let range = v.source_range.expect("expected source_range to be set");

        let expected_start = sql.find("DROP DATABASE").unwrap();
        assert_eq!(usize::from(range.start()), expected_start);
        assert_eq!(usize::from(range.end()), sql.len());
    }

    #[test]
    fn test_bug003_broken_compute_fires_on_drop_function() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE FUNCTION notify_func(int, text) RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';",
                &mut state,
            )
            .unwrap();

        engine
            .analyze(
                "CREATE TABLE events(id int);
                 CREATE TRIGGER trg_events AFTER INSERT ON events FOR EACH ROW EXECUTE FUNCTION notify_func();",
                &mut state,
            )
            .unwrap();

        // Dropping the function with hypothetical parameter types to test normalization
        let v = engine
            .analyze("DROP FUNCTION notify_func(int, text);", &mut state)
            .unwrap();

        assert!(
            v.iter()
                .any(|violation| violation.rule_id == "broken-compute"),
            "Expected broken-compute violation when dropping function used by trigger, even with parameter list"
        );
    }

    #[test]
    fn test_bug004_concurrent_in_txn_skips_on_skipped_mutation() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE TABLE tbl(id int);
                 CREATE INDEX idx_t ON tbl(id);",
                &mut state,
            )
            .unwrap();

        let v = engine
            .analyze(
                "BEGIN;
                 CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_t ON tbl(id);
                 COMMIT;",
                &mut state,
            )
            .unwrap();

        assert!(
            !v.iter()
                .any(|violation| violation.rule_id == "concurrent-in-transaction"),
            "Expected no concurrent-in-transaction violation because the index already exists and statement was skipped"
        );
    }

    #[test]
    fn test_bug005_create_table_as_select_skips_on_skipped_mutation() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE TABLE tbl(id int);", &mut state)
            .unwrap();

        let v = engine
            .analyze("CREATE TABLE IF NOT EXISTS tbl AS SELECT 1;", &mut state)
            .unwrap();

        assert!(
            !v.iter()
                .any(|violation| violation.rule_id == "create-table-as-select"),
            "Expected no create-table-as-select violation because the table already exists and statement was skipped"
        );
    }

    #[test]
    fn test_bug007_broken_compute_no_fire_on_skipped_drop() {
        let engine = setup_engine();
        let mut state = setup_state();

        let v = engine
            .analyze("DROP FUNCTION IF EXISTS nonexistent_func();", &mut state)
            .unwrap();

        assert!(
            !v.iter()
                .any(|violation| violation.rule_id == "broken-compute"),
            "Expected no broken-compute violation for nonexistent function"
        );
    }

    #[test]
    fn test_bug013_confidence_restored_on_rollback() {
        let engine = setup_engine();
        let mut cache = safe_migrate::db::cache::DbCache::new();
        let tid = object_id("public", "t");
        cache.insert_baseline(
            tid.clone(),
            safe_migrate::model::relation::RelationState::new(
                tid.clone(),
                object_id("public", "postgres"),
                0,
                Some(10),
                safe_migrate::model::relation::RelationKind::Table,
                safe_migrate::model::relation::Persistence::Permanent,
                0,
            ),
        );
        let mut state = AnalysisState::new(cache);

        // Opaque statement (like DO block) inside transaction block, then ROLLBACK
        engine
            .analyze(
                "BEGIN;
                 DO $$ BEGIN END $$;
                 ROLLBACK;",
                &mut state,
            )
            .unwrap();

        // Dropping table cascade which normally is Tier 1, but would be downgraded to Tier 2 if confidence is tainted.
        let v = engine.analyze("DROP TABLE t CASCADE;", &mut state).unwrap();

        assert!(
            v.iter().any(|violation| violation.tier
                == safe_migrate::report::violations::ViolationTier::Tier1),
            "Expected Tier1 because confidence should be restored to Exact after rollback"
        );
    }

    #[test]
    fn test_bug014_drop_schema_cascade_cleans_trigger_edges() {
        let engine = setup_engine();
        let mut state = setup_state();

        // 1. Create schema, table, trigger function, trigger, and publication
        engine
            .analyze(
                "CREATE SCHEMA s;
                 CREATE FUNCTION s.notify_func() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
                 CREATE TABLE s.t1(id int);
                 CREATE TRIGGER trg AFTER INSERT ON s.t1 FOR EACH ROW EXECUTE FUNCTION s.notify_func();
                 CREATE PUBLICATION pub FOR TABLE s.t1;",
                &mut state,
            )
            .unwrap();

        // Verify trigger and publication edges are present
        assert!(!state.local.graph.trigger_dependencies.is_empty());
        assert!(!state.local.graph.publication_dependencies.is_empty());

        // 2. Drop schema cascade
        engine
            .analyze("DROP SCHEMA s CASCADE;", &mut state)
            .unwrap();

        // Verify trigger and publication edges are cleaned up
        assert!(state.local.graph.trigger_dependencies.is_empty());
        assert!(state.local.graph.publication_dependencies.is_empty());

        // 3. Drop a completely unrelated function (say public.unrelated())
        engine
            .analyze(
                "CREATE FUNCTION unrelated() RETURNS void LANGUAGE plpgsql AS 'BEGIN END';",
                &mut state,
            )
            .unwrap();

        let v = engine
            .analyze("DROP FUNCTION unrelated();", &mut state)
            .unwrap();

        assert!(
            !v.iter()
                .any(|violation| violation.rule_id == "broken-compute"),
            "Expected no broken-compute violation for unrelated function after schema drop cascade"
        );
    }

    #[test]
    fn test_bug001_vacuum_full_all_tables() {
        let engine = setup_engine();
        let mut state = setup_state();

        let v = engine.analyze("VACUUM FULL;", &mut state).unwrap();

        let violation = v
            .iter()
            .find(|v| v.rule_id == "vacuum-full")
            .expect("Expected vacuum-full violation");

        assert_eq!(violation.object_name, "<all tables>");
    }

    // ─────────────────────────────────────────────
    // Finding 2 — Untested rule: PartitionStrategyMismatchRule
    // ─────────────────────────────────────────────
    #[test]
    fn test_finding2_partition_strategy_mismatch_fires_on_none() {
        let engine = setup_engine();
        let mut cache = safe_migrate::db::cache::DbCache::new();
        let parent_id = object_id("public", "parent");
        let mut parent = safe_migrate::model::relation::RelationState::new(
            parent_id.clone(),
            object_id("public", "postgres"),
            0,
            Some(10),
            safe_migrate::model::relation::RelationKind::Table,
            safe_migrate::model::relation::Persistence::Permanent,
            0,
        );
        parent.partition_type = Some("RANGE".to_string());
        cache.insert_baseline(parent_id, parent);

        let child_id = object_id("public", "child");
        let child = safe_migrate::model::relation::RelationState::new(
            child_id,
            object_id("public", "postgres"),
            0,
            Some(0),
            safe_migrate::model::relation::RelationKind::Table,
            safe_migrate::model::relation::Persistence::Permanent,
            0,
        );
        cache.insert_baseline(object_id("public", "child"), child);

        let mut state = AnalysisState::new(cache);

        let v = engine
            .analyze(
                "ALTER TABLE parent ATTACH PARTITION child FOR VALUES FROM (1) TO (10);",
                &mut state,
            )
            .unwrap();

        let rule_violations: Vec<&str> = v.iter().map(|v| v.rule_id).collect();
        assert!(
            v.iter().any(|v| v.rule_id == "partition-strategy-mismatch"),
            "Expected partition-strategy-mismatch violation when child has no partition strategy. Got: {:?}",
            rule_violations
        );
    }

    #[test]
    fn test_finding2_partition_strategy_mismatch_fires_on_mismatch() {
        let engine = setup_engine();
        let mut cache = safe_migrate::db::cache::DbCache::new();
        let parent_id = object_id("public", "parent");
        let mut parent = safe_migrate::model::relation::RelationState::new(
            parent_id.clone(),
            object_id("public", "postgres"),
            0,
            Some(10),
            safe_migrate::model::relation::RelationKind::Table,
            safe_migrate::model::relation::Persistence::Permanent,
            0,
        );
        parent.partition_type = Some("RANGE".to_string());
        cache.insert_baseline(parent_id, parent);

        let child_id = object_id("public", "child");
        let mut child = safe_migrate::model::relation::RelationState::new(
            child_id,
            object_id("public", "postgres"),
            0,
            Some(0),
            safe_migrate::model::relation::RelationKind::Table,
            safe_migrate::model::relation::Persistence::Permanent,
            0,
        );
        child.partition_type = Some("LIST".to_string());
        cache.insert_baseline(object_id("public", "child"), child);

        let mut state = AnalysisState::new(cache);

        let v = engine
            .analyze(
                "ALTER TABLE parent ATTACH PARTITION child FOR VALUES FROM (1) TO (10);",
                &mut state,
            )
            .unwrap();

        let rule_violations: Vec<&str> = v.iter().map(|v| v.rule_id).collect();
        assert!(
            v.iter().any(|v| v.rule_id == "partition-strategy-mismatch"),
            "Expected partition-strategy-mismatch violation when strategies differ. Got: {:?}",
            rule_violations
        );
    }

    #[test]
    fn test_finding2_partition_strategy_mismatch_silent_on_match() {
        let engine = setup_engine();
        let mut state = setup_state();

        let v = engine
            .analyze(
                "
            CREATE TABLE parent(id int) PARTITION BY RANGE(id);
            CREATE TABLE child(id int) PARTITION BY RANGE(id);
            ALTER TABLE parent ATTACH PARTITION child FOR VALUES FROM (1) TO (10);
        ",
                &mut state,
            )
            .unwrap();

        assert!(
            !v.iter().any(|v| v.rule_id == "partition-strategy-mismatch"),
            "Expected no partition-strategy-mismatch violation when strategies match"
        );
    }

    // ─────────────────────────────────────────────
    // Finding 2 — Untested rule: AlterTypeAddValueRule
    // ─────────────────────────────────────────────
    #[test]
    fn test_finding2_alter_type_add_value_fires_inside_txn() {
        let engine = setup_engine();
        let mut state = setup_state();

        let v = engine
            .analyze(
                "BEGIN; ALTER TYPE public.mood ADD VALUE 'ok'; COMMIT;",
                &mut state,
            )
            .unwrap();

        assert!(
            v.iter().any(|v| v.rule_id == "alter-type-add-value-txn"),
            "Expected alter-type-add-value-txn violation inside transaction"
        );
    }

    #[test]
    fn test_finding2_alter_type_add_value_silent_outside_txn() {
        let engine = setup_engine();
        let mut state = setup_state();

        let v = engine
            .analyze("ALTER TYPE public.mood ADD VALUE 'ok';", &mut state)
            .unwrap();

        assert!(
            !v.iter().any(|v| v.rule_id == "alter-type-add-value-txn"),
            "Expected no alter-type-add-value-txn violation outside transaction"
        );
    }

    // ─────────────────────────────────────────────
    // Finding 8 — DropColumn IF EXISTS regression
    // ─────────────────────────────────────────────
    #[test]
    fn test_finding8_drop_column_if_exists_noop() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();

        let v = engine
            .analyze(
                "ALTER TABLE t DROP COLUMN IF EXISTS nonexistent_col;",
                &mut state,
            )
            .unwrap();

        // Should not trigger irreversible-migration for a column that never existed
        assert!(
            !v.iter().any(|v| v.rule_id == "irreversible-migration"),
            "ReversibilityRule should not fire on DROP COLUMN IF EXISTS of nonexistent column"
        );
    }

    #[test]
    fn test_finding8_drop_column_if_exists_with_existing_column() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE TABLE t(id int, name text);", &mut state)
            .unwrap();

        let v = engine
            .analyze("ALTER TABLE t DROP COLUMN IF EXISTS name;", &mut state)
            .unwrap();

        // Should trigger irreversible-migration because 'name' existed and was dropped
        assert!(
            v.iter().any(|v| v.rule_id == "irreversible-migration"),
            "ReversibilityRule should fire on DROP COLUMN IF EXISTS of an existing column"
        );
    }

    #[test]
    fn test_finding8_drop_column_no_if_exists_on_nonexistent() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();

        let _v = engine
            .analyze("ALTER TABLE t DROP COLUMN nonexistent_col;", &mut state)
            .unwrap();

        // Without IF EXISTS, confidence should be tainted (table in unknown state)
        assert_eq!(
            state.local.confidence,
            safe_migrate::analysis::state::Confidence::Tainted,
            "Confidence should be Tainted when dropping a nonexistent column without IF EXISTS"
        );
    }
}

// ─────────────────────────────────────────────
// 11. Exhaustive CLI-equivalent Fuzz Tests
// ─────────────────────────────────────────────
