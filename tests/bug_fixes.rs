mod common;

mod phase10_bug_fixes_and_sorting_tests {
    use crate::common::*;
    use safe_migrate::_internal::analysis::state::{AnalysisState, Confidence};
    use safe_migrate::_internal::ast::identifiers::ObjectId;
    use safe_migrate::_internal::db::cache::DbCache;
    use safe_migrate::_internal::model::relation::{Persistence, RelationKind};
    use safe_migrate::_internal::report::violations::{
        ObjectKind, OperationKind, Violation, ViolationTier,
    };

    fn baseline_index(
        index_id: ObjectId,
        table_id: ObjectId,
    ) -> safe_migrate::_internal::db::cache::IndexCache {
        safe_migrate::_internal::db::cache::IndexCache {
            index_id,
            table_id,
            using_method: "btree".into(),
            key_columns: vec!["id".into()],
            included_columns: Vec::new(),
            dependency_columns: vec!["id".into()],
            dependency_columns_known: true,
            has_expression_keys: false,
            has_predicate: false,
            is_unique: false,
            is_valid: true,
            is_ready: true,
            is_live: true,
            has_default_sort_order: true,
            has_default_opclasses: true,
            has_default_collations: true,
        }
    }

    #[test]
    fn comment_on_is_schema_neutral_and_preserves_confidence() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "COMMENT ON TABLE future_table IS 'created elsewhere';",
                &mut state,
            )
            .expect("Squawk should parse COMMENT ON statements");

        assert!(violations.is_empty());
        assert_eq!(state.local.confidence, Confidence::Exact);
    }

    #[test]
    fn duplicate_column_assignments_remain_opaque() {
        let engine = setup_engine();
        for sql in [
            "UPDATE users SET display_name = 'first', display_name = 'second';",
            "INSERT INTO users (id) VALUES (1) ON CONFLICT (id) DO UPDATE
             SET display_name = 'first', display_name = 'second';",
        ] {
            let mut state = setup_state();
            let violations = engine
                .analyze(sql, &mut state)
                .expect("Squawk should parse duplicate assignments");

            assert!(
                violations
                    .iter()
                    .any(|violation| violation.rule_id == "opaque-dynamic-sql"),
                "duplicate DML assignment must remain opaque: {sql}"
            );
            assert_eq!(state.local.confidence, Confidence::Tainted);
        }
    }

    #[test]
    fn non_ascii_sql_before_execute_prefix_does_not_panic_normalization() {
        let engine = setup_engine();
        let mut state = setup_state();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine.analyze("SELECT 'é';", &mut state)
        }));

        assert!(
            result.is_ok(),
            "normalizing valid non-ASCII SQL must not panic"
        );
    }

    #[test]
    fn test_bug008_index_not_in_baseline_relations() {
        let mut cache = DbCache::new();
        cache.indexes.push(baseline_index(
            object_id("public", "idx_accounts_username"),
            object_id("public", "accounts"),
        ));
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
        cache.indexes.push(baseline_index(
            object_id("public", "idx_accounts_username"),
            object_id("public", "accounts"),
        ));
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
            safe_migrate::_internal::model::relation::RelationState::new(
                object_id("public", "accounts"),
                ObjectId::new("public", "postgres"),
                0,
                Some(500_000),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        cache.indexes.push(baseline_index(
            object_id("public", "idx_accounts_username"),
            object_id("public", "accounts"),
        ));

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
    fn stale_constraint_stats_do_not_flag_unrelated_alter_table_actions() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        cache.insert_baseline(
            object_id("public", "accounts"),
            safe_migrate::_internal::model::relation::RelationState::new(
                object_id("public", "accounts"),
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
                "ALTER TABLE accounts ADD COLUMN display_name text;",
                &mut state,
            )
            .unwrap();

        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "blocking-constraint")
        );
    }

    #[test]
    fn test_add_column_now_default_not_flagged() {
        let engine = setup_engine();
        let mut cache = DbCache::new();
        cache.pg_version_num = Some(110000);
        cache.insert_baseline(
            object_id("public", "t"),
            safe_migrate::_internal::model::relation::RelationState::new(
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
            safe_migrate::_internal::model::relation::RelationState::new(
                object_id("public", "t"),
                ObjectId::new("public", "postgres"),
                0,
                Some(500_000),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        cache.indexes.push(baseline_index(
            object_id("public", "idx_t_id"),
            object_id("public", "t"),
        ));

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
            safe_migrate::_internal::model::relation::RelationState::new(
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
                "CREATE FUNCTION notify_func() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';",
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

        let v = engine
            .analyze("DROP FUNCTION notify_func();", &mut state)
            .unwrap();

        assert!(
            v.iter()
                .any(|violation| violation.rule_id == "broken-compute"),
            "expected the trigger dependency to explain the rejected drop"
        );
    }

    #[test]
    fn concurrent_index_if_not_exists_still_fails_inside_a_transaction() {
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
            v.iter()
                .any(|violation| violation.rule_id == "concurrent-in-transaction"),
            "PostgreSQL checks the transaction restriction before IF NOT EXISTS can skip the index"
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
        let mut cache = safe_migrate::_internal::db::cache::DbCache::new();
        let tid = object_id("public", "t");
        cache.insert_baseline(
            tid.clone(),
            safe_migrate::_internal::model::relation::RelationState::new(
                tid.clone(),
                object_id("public", "postgres"),
                0,
                Some(10),
                safe_migrate::_internal::model::relation::RelationKind::Table,
                safe_migrate::_internal::model::relation::Persistence::Permanent,
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
                == safe_migrate::_internal::report::violations::ViolationTier::Tier1),
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
        assert!(
            state
                .local
                .graph
                .edges()
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::_internal::analysis::graph::DependencyKind::TriggerOnTable { .. }
                ))
                .count()
                != 0
        );
        assert!(
            state
                .local
                .graph
                .edges()
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::_internal::analysis::graph::DependencyKind::PublicationIncludes { .. }
                ))
                .count()
                != 0
        );

        // 2. Drop schema cascade
        engine
            .analyze("DROP SCHEMA s CASCADE;", &mut state)
            .unwrap();

        // Verify trigger and publication edges are cleaned up
        assert!(
            state
                .local
                .graph
                .edges()
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::_internal::analysis::graph::DependencyKind::TriggerOnTable { .. }
                ))
                .count()
                == 0
        );
        assert!(
            state
                .local
                .graph
                .edges()
                .iter()
                .filter(|e| matches!(
                    e.kind,
                    safe_migrate::_internal::analysis::graph::DependencyKind::PublicationIncludes { .. }
                ))
                .count()
                == 0
        );

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
    // Partition strategy matching.
    // ─────────────────────────────────────────────
    #[test]
    fn test_finding2_partition_strategy_mismatch_silent_on_regular_child() {
        let engine = setup_engine();
        let mut cache = safe_migrate::_internal::db::cache::DbCache::new();
        let parent_id = object_id("public", "parent");
        let mut parent = safe_migrate::_internal::model::relation::RelationState::new(
            parent_id.clone(),
            object_id("public", "postgres"),
            0,
            Some(0),
            safe_migrate::_internal::model::relation::RelationKind::Table,
            safe_migrate::_internal::model::relation::Persistence::Permanent,
            0,
        );
        parent.partition_type = Some("RANGE".to_string());
        cache.insert_baseline(parent_id, parent);

        let child_id = object_id("public", "child");
        let child = safe_migrate::_internal::model::relation::RelationState::new(
            child_id,
            object_id("public", "postgres"),
            0,
            Some(0),
            safe_migrate::_internal::model::relation::RelationKind::Table,
            safe_migrate::_internal::model::relation::Persistence::Permanent,
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

        // A regular (non-partitioned) table attached to a RANGE parent is valid SQL.
        // The rule should only fire when the child HAS a partition strategy that mismatches.
        assert!(
            !v.iter().any(|v| v.rule_id == "partition-strategy-mismatch"),
            "partition-strategy-mismatch should NOT fire for attaching a regular table"
        );
    }

    #[test]
    fn test_finding2_partition_strategy_mismatch_fires_on_mismatch() {
        let engine = setup_engine();
        let mut cache = safe_migrate::_internal::db::cache::DbCache::new();
        let parent_id = object_id("public", "parent");
        let mut parent = safe_migrate::_internal::model::relation::RelationState::new(
            parent_id.clone(),
            object_id("public", "postgres"),
            0,
            Some(10),
            safe_migrate::_internal::model::relation::RelationKind::Table,
            safe_migrate::_internal::model::relation::Persistence::Permanent,
            0,
        );
        parent.partition_type = Some("RANGE".to_string());
        cache.insert_baseline(parent_id, parent);

        let child_id = object_id("public", "child");
        let mut child = safe_migrate::_internal::model::relation::RelationState::new(
            child_id,
            object_id("public", "postgres"),
            0,
            Some(0),
            safe_migrate::_internal::model::relation::RelationKind::Table,
            safe_migrate::_internal::model::relation::Persistence::Permanent,
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
    // Enum additions inside transactions.
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

        let finding = v
            .iter()
            .find(|v| v.rule_id == "alter-type-add-value-txn")
            .expect("Expected alter-type-add-value-txn violation inside transaction");
        assert_eq!(finding.tier, ViolationTier::Tier2);
        assert!(
            finding
                .reason
                .contains("does not allow the new value to be used until commit")
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

    #[test]
    fn alter_type_rename_value_is_not_reported_as_add_value() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "BEGIN; ALTER TYPE public.mood RENAME VALUE 'sad' TO 'blue'; COMMIT;",
                &mut state,
            )
            .unwrap();

        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "alter-type-add-value-txn")
        );
    }

    // ─────────────────────────────────────────────
    // Guarded column drops.
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
    fn drop_nonexistent_column_without_if_exists_reports_exact_conflict() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();

        let violations = engine
            .analyze("ALTER TABLE t DROP COLUMN nonexistent_col;", &mut state)
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict"
                && violation.tier == ViolationTier::Tier1
                && violation
                    .reason
                    .contains("column 'nonexistent_col' does not exist")
        }));
        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "irreversible-migration"),
            "A failed DROP COLUMN did not perform an irreversible operation"
        );
        assert_eq!(
            state.local.confidence,
            safe_migrate::_internal::analysis::state::Confidence::Exact,
            "A known PostgreSQL column conflict does not make simulation uncertain"
        );
    }

    // ─────────────────────────────────────────────
    // Bug 16 — Duplicate column name on Rename
    // ─────────────────────────────────────────────
    #[test]
    fn test_bug016_rename_prevents_duplicate_column_name() {
        use safe_migrate::_internal::model::column::Column;
        use safe_migrate::_internal::model::relation::ColumnAction;
        use safe_migrate::_internal::model::relation::RelationState;

        let mut rel = RelationState::new(
            ObjectId::new("public", "t"),
            ObjectId::new("public", "postgres"),
            0,
            Some(10),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        rel.columns.push(Column {
            name: "a".into(),
            data_type: Some("int".into()),
            type_id: None,
            is_nullable: true,
            default: None,
            avg_width: None,
            default_expr_text: None,
            type_modifier: None,
        });
        rel.columns.push(Column {
            name: "b".into(),
            data_type: Some("int".into()),
            type_id: None,
            is_nullable: true,
            default: None,
            avg_width: None,
            default_expr_text: None,
            type_modifier: None,
        });

        // Rename "a" to "b" — "b" already exists, so rename should be a no-op
        rel.apply_column_action(&ColumnAction::Rename {
            from: "a".into(),
            to: "b".into(),
        });

        assert_eq!(rel.columns.len(), 2, "no new column should be created");
        assert!(
            rel.has_column("a"),
            "column 'a' should still exist (rename skipped)"
        );
        assert!(rel.has_column("b"), "column 'b' should still exist");
    }

    // ─────────────────────────────────────────────
    // Bug 17 — SetType/SetDefault on nonexistent column
    // ─────────────────────────────────────────────
    #[test]
    fn test_bug017_set_type_on_nonexistent_column_is_a_conflict() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();

        let violations = engine
            .analyze(
                "ALTER TABLE t ALTER COLUMN nonexistent_col SET DATA TYPE text;",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict" && violation.reason.contains("nonexistent_col")
        }));
        assert_eq!(state.local.confidence, Confidence::Exact);
    }

    #[test]
    fn test_bug017_set_default_on_nonexistent_column_is_a_conflict() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();

        let violations = engine
            .analyze(
                "ALTER TABLE t ALTER COLUMN nonexistent_col SET DEFAULT 42;",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict" && violation.reason.contains("nonexistent_col")
        }));
        assert_eq!(state.local.confidence, Confidence::Exact);
    }

    #[test]
    fn test_bug017_set_type_on_existing_column_succeeds() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();

        engine
            .analyze(
                "ALTER TABLE t ALTER COLUMN id SET DATA TYPE bigint;",
                &mut state,
            )
            .unwrap();

        // Confidence should remain Exact since the column exists
        assert_eq!(
            state.local.confidence,
            safe_migrate::_internal::analysis::state::Confidence::Exact,
            "Confidence should remain Exact when SET TYPE on existing column"
        );
    }

    #[test]
    fn alter_quoted_column_resolves_the_created_column() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                r#"CREATE TABLE entries ("Camel" int);
                   ALTER TABLE entries ALTER COLUMN "Camel" TYPE bigint;"#,
                &mut state,
            )
            .unwrap();

        assert_eq!(state.local.confidence, Confidence::Exact);
    }
    // ─────────────────────────────────────────────
    // Bug 9 — Privilege enum consistency: All variant
    // ─────────────────────────────────────────────
    #[test]
    fn test_bug009_privilege_all_variant_consistency() {
        use safe_migrate::_internal::model::relation::Privilege;
        use safe_migrate::_internal::model::relation::PrivilegeMatrix;
        use std::collections::HashSet;

        // 1. Both enums now have All (compile-time check — relation::Privilege::All exists)
        let _all = Privilege::All;

        let mut matrix = PrivilegeMatrix::default();
        let role = object_id("public", "test_role");
        let mut all_privileges = HashSet::new();
        all_privileges.insert(Privilege::All);

        // 2. Grant All, then check individual privileges
        matrix.grant(role.clone(), all_privileges);
        assert!(matrix.has_privilege(&role, Privilege::Select));
        assert!(matrix.has_privilege(&role, Privilege::Insert));
        assert!(matrix.has_privilege(&role, Privilege::Update));
        assert!(matrix.has_privilege(&role, Privilege::Delete));
        assert!(matrix.has_privilege(&role, Privilege::Truncate));
        assert!(matrix.has_privilege(&role, Privilege::References));
        assert!(matrix.has_privilege(&role, Privilege::Trigger));
        assert!(matrix.has_privilege(&role, Privilege::Maintain));

        // 3. has_privilege for All itself should also work
        assert!(matrix.has_privilege(&role, Privilege::All));

        // 4. Revoke All clears everything
        let mut revoke_all = HashSet::new();
        revoke_all.insert(Privilege::All);
        matrix.revoke(&role, &revoke_all);
        assert!(!matrix.has_privilege(&role, Privilege::Select));
        assert!(!matrix.has_privilege(&role, Privilege::All));
    }

    #[test]
    fn postgres17_all_grant_tracks_maintain_without_leaking_to_older_versions() {
        use safe_migrate::_internal::model::relation::{Privilege, RelationOverlay};

        let engine = setup_engine();
        for (version, expected) in [(170_000, true), (160_000, false)] {
            let mut cache = cache_with_table("public", "t_large", None);
            cache.pg_version_num = Some(version);
            let mut state = AnalysisState::new(cache);
            engine
                .analyze("GRANT ALL ON TABLE t_large TO app_user;", &mut state)
                .expect("GRANT ALL should analyze");

            let Some(RelationOverlay::Present(relation)) =
                state.local.relations.get(&object_id("public", "t_large"))
            else {
                panic!("baseline relation should remain present");
            };
            let grantee = object_id("", "app_user");
            assert_eq!(
                relation
                    .privileges
                    .grants
                    .get(&grantee)
                    .is_some_and(|privileges| privileges.contains(&Privilege::Maintain)),
                expected,
                "PG {version} GRANT ALL MAINTAIN expansion mismatch"
            );
        }
    }
    // ─────────────────────────────────────────────
    // Bug 14 — Directive parsing tolerates whitespace
    // ─────────────────────────────────────────────
    #[test]
    fn test_bug014_directive_ignore_with_spaces() {
        let engine = setup_engine();
        let mut state = setup_state();

        let sql = "/* safe-migrate: ignore ( drop-database ) */ DROP DATABASE my_db;";
        let violations = engine.analyze(sql, &mut state).unwrap();

        assert!(
            !violations.iter().any(|v| v.rule_id == "drop-database"),
            "ignore directive with spaces before parens should suppress the rule"
        );
    }

    #[test]
    fn test_bug014_directive_ignore_no_spaces() {
        let engine = setup_engine();
        let mut state = setup_state();

        let sql = "/* safe-migrate: ignore(drop-database) */ DROP DATABASE my_db;";
        let violations = engine.analyze(sql, &mut state).unwrap();

        assert!(
            !violations.iter().any(|v| v.rule_id == "drop-database"),
            "ignore directive without spaces should still work"
        );
    }

    #[test]
    fn test_bug014_directive_ignore_file_with_spaces() {
        let engine = setup_engine();
        let mut state = setup_state();

        let sql = "/* safe-migrate: ignore-file ( drop-database ) */ DROP DATABASE my_db;";
        let violations = engine.analyze(sql, &mut state).unwrap();

        assert!(
            !violations.iter().any(|v| v.rule_id == "drop-database"),
            "ignore-file directive with spaces before parens should suppress the rule"
        );
    }

    #[test]
    fn test_bug014_directive_comment_variations() {
        let engine = setup_engine();
        let mut state = setup_state();

        // Line comment variant
        let sql = "-- safe-migrate: ignore(drop-database)\nDROP DATABASE my_db;";
        let violations = engine.analyze(sql, &mut state).unwrap();

        assert!(
            !violations.iter().any(|v| v.rule_id == "drop-database"),
            "ignore directive in line comment should suppress the rule"
        );
    }

    #[test]
    fn directives_in_sql_literals_do_not_suppress_rules() {
        let engine = setup_engine();
        let mut state = setup_state();

        let sql = "SELECT 'safe-migrate: ignore-file(drop-database)'; DROP DATABASE my_db;";
        let violations = engine.analyze(sql, &mut state).unwrap();

        assert!(
            violations.iter().any(|v| v.rule_id == "drop-database"),
            "directive-like text in a SQL literal must not suppress a rule"
        );
    }

    // ─────────────────────────────────────────────
    // Bug 15 — stmt_text strips leading comments
    // ─────────────────────────────────────────────
    #[test]
    fn test_bug015_violation_sql_strips_leading_line_comments() {
        let engine = setup_engine();
        let mut state = setup_state();

        let sql = "-- preceding line comment\nDROP DATABASE my_db;";
        let violations = engine.analyze(sql, &mut state).unwrap();

        let v = violations
            .iter()
            .find(|v| v.rule_id == "drop-database")
            .expect("Expected drop-database violation");

        let sql_text = v.sql.as_ref().expect("Expected sql field to be set");
        assert!(
            !sql_text.starts_with("--"),
            "Violation sql should not include leading comments. Got: {:?}",
            sql_text
        );
    }

    #[test]
    fn test_bug015_violation_sql_strips_leading_block_comments() {
        let engine = setup_engine();
        let mut state = setup_state();

        let sql = "/* preceding block comment */ DROP DATABASE my_db;";
        let violations = engine.analyze(sql, &mut state).unwrap();

        let v = violations
            .iter()
            .find(|v| v.rule_id == "drop-database")
            .expect("Expected drop-database violation");

        let sql_text = v.sql.as_ref().expect("Expected sql field to be set");
        assert!(
            !sql_text.starts_with("/*"),
            "Violation sql should not include leading block comments. Got: {:?}",
            sql_text
        );
    }

    // ─────────────────────────────────────────────
    // Bug 12 — Partition threshold integer division floor at 1
    // ─────────────────────────────────────────────
    #[test]
    fn test_bug012_partition_threshold_floor_at_one() {
        let config = safe_migrate::_internal::engine::config::Config {
            tier1_threshold_rows: 1,
            tier2_threshold_rows: 1,
            ..Default::default()
        };
        let engine = safe_migrate::_internal::engine::engine::SafeMigrateEngine::new(config);
        let mut cache = safe_migrate::_internal::db::cache::DbCache::new();

        let parent_id = object_id("public", "parent");
        let child_id = object_id("public", "child");
        let mut parent = safe_migrate::_internal::model::relation::RelationState::new(
            parent_id.clone(),
            object_id("public", "postgres"),
            0,
            Some(0),
            safe_migrate::_internal::model::relation::RelationKind::Table,
            safe_migrate::_internal::model::relation::Persistence::Permanent,
            0,
        );
        parent.partition_type = Some("RANGE".to_string());
        cache.insert_baseline(parent_id, parent);

        let mut child = safe_migrate::_internal::model::relation::RelationState::new(
            child_id.clone(),
            object_id("public", "postgres"),
            0,
            Some(0),
            safe_migrate::_internal::model::relation::RelationKind::Table,
            safe_migrate::_internal::model::relation::Persistence::Permanent,
            0,
        );
        child.partition_type = Some("RANGE".to_string());
        cache.insert_baseline(child_id, child);

        let mut state = safe_migrate::api::AnalysisState::new(cache);

        let violations = engine
            .analyze(
                "ALTER TABLE child ADD FOREIGN KEY (parent_id) REFERENCES parent(id);",
                &mut state,
            )
            .unwrap();

        let tier1_violations: Vec<&safe_migrate::_internal::report::violations::Violation> =
            violations
                .iter()
                .filter(|v| {
                    v.tier == safe_migrate::_internal::report::violations::ViolationTier::Tier1
                        && v.rule_id == "blocking-constraint"
                })
                .collect();

        assert!(
            tier1_violations.is_empty(),
            "Partitioned tables with 0 rows should not trigger Tier1 with threshold=1 (adjusted threshold should floor at 1, not 0). Found: {:?}",
            tier1_violations
        );
    }

    #[test]
    fn test_bug018_drop_schema_no_cascade_conflicts_when_table_exists() {
        // 1a: DROP SCHEMA without CASCADE must produce a chain-conflict violation
        // when the schema still contains tables.
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE SCHEMA myschema; CREATE TABLE myschema.t1(id int);",
                &mut state,
            )
            .unwrap();

        let violations = engine.analyze("DROP SCHEMA myschema;", &mut state).unwrap();

        let conflict = violations.iter().find(|v| v.rule_id == "chain-conflict");
        assert!(
            conflict.is_some(),
            "Expected chain-conflict violation for DROP SCHEMA without CASCADE on non-empty schema, got: {:?}",
            violations
        );
        assert!(
            conflict.unwrap().reason.contains("CASCADE"),
            "Conflict reason should mention CASCADE, got: {}",
            conflict.unwrap().reason
        );
    }

    #[test]
    fn drop_schema_without_cascade_taints_when_emptiness_is_not_complete_evidence() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE SCHEMA myschema;", &mut state)
            .unwrap();

        let violations = engine.analyze("DROP SCHEMA myschema;", &mut state).unwrap();

        assert!(
            !violations.iter().any(|v| v.rule_id == "chain-conflict"),
            "an apparently empty schema is uncertain rather than a conflict: {violations:?}"
        );
        assert!(state.local.schemas.contains_key("myschema"));
        assert_eq!(state.local.confidence, Confidence::Tainted);
    }

    #[test]
    fn test_bug018_drop_schema_cascade_still_applied_with_table() {
        // 1a: DROP SCHEMA CASCADE must still succeed (no conflict) even with tables.
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE SCHEMA myschema; CREATE TABLE myschema.t1(id int);",
                &mut state,
            )
            .unwrap();

        let violations = engine
            .analyze("DROP SCHEMA myschema CASCADE;", &mut state)
            .unwrap();

        let conflict = violations.iter().find(|v| v.rule_id == "chain-conflict");
        assert!(
            conflict.is_none(),
            "Expected no chain-conflict for DROP SCHEMA CASCADE, got: {:?}",
            violations
        );
    }
}
// ─────────────────────────────────────────────
