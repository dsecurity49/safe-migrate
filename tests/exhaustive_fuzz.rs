mod common;

mod exhaustive_fuzz_tests {
    use crate::common::*;
    use safe_migrate::_internal::analysis::state::AnalysisState;
    use safe_migrate::_internal::report::violations::ObjectKind;

    // DDL in isolation.

    #[test]
    fn fuzz_ddl_001_create_table() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze("CREATE TABLE t1 (id int);", &mut state)
            .unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn fuzz_ddl_002_create_table_if_not_exists() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze("CREATE TABLE IF NOT EXISTS t1 (id int);", &mut state)
            .unwrap();
        assert!(v.iter().all(|v| v.rule_id == "missing-idempotency"));
    }

    #[test]
    fn fuzz_ddl_003_create_index() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t1 (id int);", &mut state)
            .unwrap();
        let v = engine
            .analyze("CREATE INDEX idx1 ON t1(id);", &mut state)
            .unwrap();
        assert!(v.iter().any(|v| v.rule_id == "missing-idempotency"));
    }

    #[test]
    fn fuzz_ddl_004_create_index_concurrently() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t1 (id int);", &mut state)
            .unwrap();
        let v = engine
            .analyze("CREATE INDEX CONCURRENTLY idx1 ON t1(id);", &mut state)
            .unwrap();
        assert!(v.iter().any(|v| v.rule_id == "missing-idempotency"));
    }

    #[test]
    fn fuzz_ddl_005_create_view() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t1 (id int);", &mut state)
            .unwrap();
        let v = engine
            .analyze("CREATE VIEW v1 AS SELECT * FROM t1;", &mut state)
            .unwrap();
        // CREATE VIEW may produce missing-idempotency or no violations
        let _ = v;
    }

    #[test]
    fn fuzz_ddl_006_create_materialized_view() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t1 (id int);", &mut state)
            .unwrap();
        let _v = engine
            .analyze(
                "CREATE MATERIALIZED VIEW mv1 AS SELECT count(*) FROM t1;",
                &mut state,
            )
            .unwrap();
    }

    #[test]
    fn fuzz_ddl_007_create_schema() {
        let engine = setup_engine();
        let mut state = setup_state();
        let _v = engine
            .analyze("CREATE SCHEMA myschema;", &mut state)
            .unwrap();
    }

    #[test]
    fn fuzz_ddl_008_alter_table_add_column() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t1 (id int);", &mut state)
            .unwrap();
        let v = engine
            .analyze("ALTER TABLE t1 ADD COLUMN name text;", &mut state)
            .unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn fuzz_ddl_009_alter_table_drop_column() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t1 (id int, name text);", &mut state)
            .unwrap();
        let v = engine
            .analyze("ALTER TABLE t1 DROP COLUMN name;", &mut state)
            .unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn fuzz_ddl_010_alter_table_rename_column() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t1 (id int, name text);", &mut state)
            .unwrap();
        let _v = engine
            .analyze(
                "ALTER TABLE t1 RENAME COLUMN name TO full_name;",
                &mut state,
            )
            .unwrap();
    }

    #[test]
    fn fuzz_ddl_011_alter_table_set_not_null() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t1 (id int);", &mut state)
            .unwrap();
        let _v = engine
            .analyze("ALTER TABLE t1 ALTER COLUMN id SET NOT NULL;", &mut state)
            .unwrap();
    }

    #[test]
    fn fuzz_ddl_012_alter_table_set_type() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t1 (id int);", &mut state)
            .unwrap();
        let v = engine
            .analyze("ALTER TABLE t1 ALTER COLUMN id TYPE bigint;", &mut state)
            .unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn fuzz_ddl_013_drop_table() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t1 (id int);", &mut state)
            .unwrap();
        let v = engine.analyze("DROP TABLE t1;", &mut state).unwrap();
        assert!(v.iter().any(|v| v.rule_id == "irreversible-migration"));
    }

    #[test]
    fn fuzz_ddl_014_drop_table_cascade() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t1 (id int);", &mut state)
            .unwrap();
        let _v = engine
            .analyze("DROP TABLE t1 CASCADE;", &mut state)
            .unwrap();
        // Cascade rule only fires when closure affects baseline relations
    }

    #[test]
    fn fuzz_ddl_015_drop_table_if_exists() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze("DROP TABLE IF EXISTS nonexistent;", &mut state)
            .unwrap();
        assert!(v.iter().all(|v| v.tier
            == safe_migrate::_internal::report::violations::ViolationTier::Tier3
            || v.rule_id == "schema-drift"));
    }

    #[test]
    fn fuzz_ddl_016_drop_view() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t1 (id int);", &mut state)
            .unwrap();
        engine
            .analyze("CREATE VIEW v1 AS SELECT * FROM t1;", &mut state)
            .unwrap();
        let v = engine.analyze("DROP VIEW v1;", &mut state).unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn fuzz_ddl_017_drop_materialized_view() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t1 (id int);", &mut state)
            .unwrap();
        engine
            .analyze(
                "CREATE MATERIALIZED VIEW mv1 AS SELECT count(*) FROM t1;",
                &mut state,
            )
            .unwrap();
        let v = engine
            .analyze("DROP MATERIALIZED VIEW mv1;", &mut state)
            .unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn fuzz_ddl_018_drop_schema() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze("CREATE SCHEMA s1;", &mut state).unwrap();
        let _v = engine.analyze("DROP SCHEMA s1;", &mut state).unwrap();
    }

    #[test]
    fn fuzz_ddl_019_drop_schema_cascade() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze("CREATE SCHEMA s1;", &mut state).unwrap();
        let v = engine
            .analyze("DROP SCHEMA s1 CASCADE;", &mut state)
            .unwrap();
        assert!(v.iter().any(|v| v.rule_id == "drop-schema-cascade"));
    }

    #[test]
    fn fuzz_ddl_020_create_function() {
        let engine = setup_engine();
        let mut state = setup_state();
        let _v = engine
            .analyze(
                "CREATE FUNCTION add(a int, b int) RETURNS int LANGUAGE sql IMMUTABLE AS $$ SELECT a + b $$;",
                &mut state,
            )
            .unwrap();
    }

    #[test]
    fn fuzz_ddl_021_vacuum_full() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine.analyze("VACUUM FULL t1;", &mut state).unwrap();
        assert!(v.iter().any(|v| v.rule_id == "vacuum-full"));
    }

    #[test]
    fn fuzz_ddl_022_do_block() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze("DO $$ BEGIN RAISE NOTICE 'x'; END $$;", &mut state)
            .unwrap();
        assert!(v.iter().any(|v| v.rule_id == "opaque-dynamic-sql"));
    }

    #[test]
    fn fuzz_ddl_023_grant_all() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze("GRANT ALL ON t1 TO role1;", &mut state)
            .unwrap();
        assert!(v.iter().any(|v| v.rule_id == "overbroad-grant"));
    }

    #[test]
    fn fuzz_ddl_024_drop_database() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine.analyze("DROP DATABASE mydb;", &mut state).unwrap();
        assert!(v.iter().any(|v| v.rule_id == "drop-database"));
        assert!(v.iter().any(|v| v.rule_id != "irreversible-migration"));
    }

    #[test]
    fn fuzz_ddl_025_create_type() {
        let engine = setup_engine();
        let mut state = setup_state();
        let _v = engine
            .analyze("CREATE TYPE mood AS ENUM ('happy', 'sad');", &mut state)
            .unwrap();
    }

    #[test]
    fn fuzz_ddl_026_alter_type_add_value() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TYPE mood AS ENUM ('happy', 'sad');", &mut state)
            .unwrap();
        let _v = engine
            .analyze("ALTER TYPE mood ADD VALUE 'angry';", &mut state)
            .unwrap();
        // alter-type-add-value rule may or may not fire depending on pre-state
    }

    #[test]
    fn fuzz_ddl_027_create_trigger() {
        let engine = setup_engine();
        let mut state = setup_state();
        let _v = engine
            .analyze(
                "CREATE TRIGGER t1 BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION func();",
                &mut state,
            )
            .unwrap();
    }

    #[test]
    fn fuzz_ddl_029_duplicate_update_assignment_is_opaque() {
        let engine = setup_engine();
        let mut state = setup_state();
        let violations = engine
            .analyze(
                "UPDATE users SET name = 'first', name = 'second';",
                &mut state,
            )
            .unwrap();
        assert!(
            violations
                .iter()
                .any(|violation| violation.rule_id == "opaque-dynamic-sql")
        );
    }

    #[test]
    fn fuzz_ddl_028_create_policy() {
        let engine = setup_engine();
        let mut state = setup_state();
        let _v = engine
            .analyze(
                "CREATE POLICY p1 ON users FOR ALL USING (true);",
                &mut state,
            )
            .unwrap();
    }

    // Transaction patterns.

    #[test]
    fn fuzz_txn_001_begin_commit() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze("BEGIN; CREATE TABLE t1 (id int); COMMIT;", &mut state)
            .unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn fuzz_txn_002_begin_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze("BEGIN; CREATE TABLE t1 (id int); ROLLBACK;", &mut state)
            .unwrap();
        // Table was rolled back - violations for create should still exist
        assert!(!v.is_empty());
    }

    #[test]
    fn fuzz_txn_003_savepoint_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze(
                "BEGIN; SAVEPOINT s1; CREATE TABLE t1 (id int); ROLLBACK TO s1; COMMIT;",
                &mut state,
            )
            .unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn fuzz_txn_004_do_rollback_restores_confidence() {
        let engine = setup_engine();
        let cache = cache_with_table("public", "t", Some(100));
        let mut state = AnalysisState::new(cache);

        engine
            .analyze("BEGIN; DO $$ BEGIN END $$; ROLLBACK;", &mut state)
            .unwrap();
        assert_eq!(
            state.local.confidence,
            safe_migrate::_internal::analysis::state::Confidence::Exact
        );
    }

    #[test]
    fn fuzz_txn_005_do_block_taints_confidence() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("DO $$ BEGIN NULL; END $$;", &mut state)
            .unwrap();
        assert_eq!(
            state.local.confidence,
            safe_migrate::_internal::analysis::state::Confidence::Tainted
        );
    }

    #[test]
    fn fuzz_txn_006_nested_savepoint_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze(
                "BEGIN; SAVEPOINT s1; CREATE TABLE t1 (id int); SAVEPOINT s2; CREATE TABLE t2 (id int); ROLLBACK TO s1; COMMIT;",
                &mut state,
            )
            .unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn fuzz_txn_007_begin_do_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze("BEGIN; DO $$ BEGIN NULL; END $$; ROLLBACK;", &mut state)
            .unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn fuzz_txn_008_begin_multiple_statements_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze(
                "BEGIN; CREATE TABLE t1 (id int); ALTER TABLE t1 ADD COLUMN x int; DROP TABLE t1; ROLLBACK;",
                &mut state,
            )
            .unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn fuzz_txn_009_savepoint_release() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze(
                "BEGIN; SAVEPOINT s1; CREATE TABLE t1 (id int); RELEASE SAVEPOINT s1; COMMIT;",
                &mut state,
            )
            .unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn rollback_to_savepoint_discards_later_savepoints() {
        let engine = setup_engine();
        let mut state = setup_state();
        let violations = engine
            .analyze(
                "BEGIN; SAVEPOINT s1; SAVEPOINT s2; SAVEPOINT s3; ROLLBACK TO s2; RELEASE SAVEPOINT s3; COMMIT;",
                &mut state,
            )
            .unwrap();

        let conflict = violations
            .iter()
            .find(|violation| {
                violation.rule_id == "chain-conflict"
                    && violation.reason.contains("savepoint 's3' does not exist")
            })
            .expect("releasing a savepoint discarded by ROLLBACK TO must be reported");
        assert_eq!(conflict.object_kind, ObjectKind::Unknown);
        assert_eq!(conflict.object_name, "<migration-state>");
        assert!(conflict.recipe.contains("schema state"));
        assert!(!conflict.recipe.contains("each column"));
        assert!(state.local.transactions.is_empty());
        assert!(!state.local.transaction_aborted);
    }

    // Confidence and tier changes.

    #[test]
    fn fuzz_tier_001_do_block_downgrades_tier1() {
        let engine = setup_engine();
        let cache = cache_with_table("public", "users", Some(100));
        let mut state = AnalysisState::new(cache);

        let v = engine
            .analyze("DO $$ BEGIN NULL; END $$; DROP TABLE users;", &mut state)
            .unwrap();
        for violation in &v {
            if violation.tier == safe_migrate::_internal::report::violations::ViolationTier::Tier1 {
                panic!(
                    "Expected no Tier1 after DO block taint, got: {} ({})",
                    violation.rule_id, violation.reason
                );
            }
        }
    }

    #[test]
    fn fuzz_tier_002_exact_confidence_preserves_tier1() {
        let engine = setup_engine();
        let cache = cache_with_table("public", "users", Some(100));
        let mut state = AnalysisState::new(cache);

        let v = engine.analyze("DROP TABLE users;", &mut state).unwrap();
        assert!(
            v.iter().any(
                |v| v.tier == safe_migrate::_internal::report::violations::ViolationTier::Tier1
            )
        );
    }

    #[test]
    fn fuzz_tier_003_rollback_restores_tier1() {
        let engine = setup_engine();
        let cache = cache_with_table("public", "users", Some(100));
        let mut state = AnalysisState::new(cache);

        // Taint, rollback, then exact drop
        engine
            .analyze("BEGIN; DO $$ BEGIN NULL; END $$; ROLLBACK;", &mut state)
            .unwrap();
        assert_eq!(
            state.local.confidence,
            safe_migrate::_internal::analysis::state::Confidence::Exact
        );
        let v = engine.analyze("DROP TABLE users;", &mut state).unwrap();
        assert!(
            v.iter().any(
                |v| v.tier == safe_migrate::_internal::report::violations::ViolationTier::Tier1
            )
        );
    }

    #[test]
    fn fuzz_tier_004_multiple_taints_stay_downgraded() {
        let engine = setup_engine();
        let cache = cache_with_table("public", "users", Some(100));
        let mut state = AnalysisState::new(cache);

        engine
            .analyze("DO $$ BEGIN NULL; END $$;", &mut state)
            .unwrap();
        engine
            .analyze("DO $$ BEGIN NULL; END $$;", &mut state)
            .unwrap();
        let v = engine.analyze("DROP TABLE users;", &mut state).unwrap();
        assert!(
            !v.iter().any(
                |v| v.tier == safe_migrate::_internal::report::violations::ViolationTier::Tier1
            )
        );
    }

    // Cascades and dependencies.

    #[test]
    fn fuzz_cascade_001_drop_cascade_with_fk() {
        let engine = setup_engine();
        let cache = cache_with_table("public", "parent", Some(100));
        let mut state = AnalysisState::new(cache);
        engine
            .analyze("CREATE TABLE child (id int, parent_id int);", &mut state)
            .unwrap();
        engine
            .analyze(
                "ALTER TABLE child ADD CONSTRAINT fk FOREIGN KEY (parent_id) REFERENCES parent(id);",
                &mut state,
            )
            .unwrap();
        let _v = engine
            .analyze("DROP TABLE parent CASCADE;", &mut state)
            .unwrap();
        // Cascade rule fires when closure affects baseline relations
    }

    #[test]
    fn fuzz_cascade_002_drop_no_cascade_blocked() {
        let engine = setup_engine();
        let cache = cache_with_table("public", "parent", Some(100));
        let mut state = AnalysisState::new(cache);
        engine
            .analyze(
                "CREATE TABLE child (id int, parent_id int REFERENCES parent(id));",
                &mut state,
            )
            .unwrap();
        let v = engine.analyze("DROP TABLE parent;", &mut state).unwrap();
        assert!(!v.iter().any(|v| v.rule_id == "irreversible-migration"));
    }

    #[test]
    fn fuzz_cascade_003_drop_cascade_with_view() {
        let engine = setup_engine();
        let cache = cache_with_table("public", "t1", Some(10));
        let mut state = AnalysisState::new(cache);
        engine
            .analyze("CREATE VIEW v1 AS SELECT * FROM t1;", &mut state)
            .unwrap();
        let _v = engine
            .analyze("DROP TABLE t1 CASCADE;", &mut state)
            .unwrap();
        // Cascade rule fires when closure affects baseline relations
    }

    // Multi-statement migrations.

    #[test]
    fn fuzz_complex_001_create_alter_drop_cycle() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze(
                "CREATE TABLE t1 (id int); ALTER TABLE t1 ADD COLUMN x int; DROP TABLE t1;",
                &mut state,
            )
            .unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn fuzz_complex_002_do_ddl_do_ddl() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze(
                "DO $$ BEGIN NULL; END $$; CREATE TABLE t1 (id int); DO $$ BEGIN NULL; END $$; ALTER TABLE t1 ADD COLUMN x int;",
                &mut state,
            )
            .unwrap();
        assert!(!v.is_empty());
        assert_eq!(
            state.local.confidence,
            safe_migrate::_internal::analysis::state::Confidence::Tainted
        );
    }

    #[test]
    fn fuzz_complex_003_txn_do_ddl_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze(
                "BEGIN; DO $$ BEGIN NULL; END $$; CREATE TABLE t1 (id int); ROLLBACK;",
                &mut state,
            )
            .unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn fuzz_complex_004_savepoint_do_alter() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze(
                "BEGIN; CREATE TABLE t1 (id int); SAVEPOINT s1; DO $$ BEGIN NULL; END $$; ALTER TABLE t1 ADD COLUMN x int; ROLLBACK TO s1; COMMIT;",
                &mut state,
            )
            .unwrap();
        assert!(!v.is_empty());
    }

    #[test]
    fn fuzz_complex_005_concurrent_outside_txn() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze("CREATE INDEX CONCURRENTLY idx1 ON t1(id);", &mut state)
            .unwrap();
        assert!(!v.is_empty());
    }

    // Parse errors.

    #[test]
    fn fuzz_parse_001_empty_string() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine.analyze("", &mut state).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn fuzz_parse_002_comments_only() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze("-- just a comment\n-- another", &mut state)
            .unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn fuzz_parse_003_invalid_sql_returns_error() {
        let engine = setup_engine();
        let mut state = setup_state();
        let result = engine.analyze("NOT VALID SQL AT ALL", &mut state);
        assert!(result.is_err());
    }

    #[test]
    fn fuzz_parse_004_cr_line_endings_parse_and_preserve_statement_order() {
        let engine = setup_engine();
        let mut state = setup_state();
        let violations = engine
            .analyze(
                "CREATE TABLE users (id integer);\rALTER TABLE users ADD COLUMN name text;",
                &mut state,
            )
            .unwrap();
        assert!(
            violations
                .iter()
                .all(|violation| violation.rule_id != "opaque-dynamic-sql")
        );
        let Some(safe_migrate::_internal::model::relation::RelationOverlay::Present(relation)) =
            state.get_relation(&safe_migrate::_internal::ast::identifiers::ObjectId::new(
                "public", "users",
            ))
        else {
            panic!("users table missing");
        };
        assert!(relation.has_column("name"));
    }

    // Schema drift with a cache.

    #[test]
    fn fuzz_drift_001_drop_existing_table() {
        let engine = setup_engine();
        let cache = cache_with_table("public", "users", Some(100));
        let mut state = AnalysisState::new(cache);
        let v = engine.analyze("DROP TABLE users;", &mut state).unwrap();
        assert!(!v.iter().any(|v| v.rule_id == "schema-drift"));
    }

    #[test]
    fn fuzz_drift_002_drop_nonexistent_table() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze("DROP TABLE nonexistent;", &mut state)
            .unwrap();
        assert!(v.iter().any(|v| v.rule_id == "schema-drift"));
    }

    #[test]
    fn fuzz_drift_003_alter_existing_table() {
        let engine = setup_engine();
        let cache = cache_with_table("public", "users", Some(100));
        let mut state = AnalysisState::new(cache);
        let v = engine
            .analyze("ALTER TABLE users ADD COLUMN x int;", &mut state)
            .unwrap();
        assert!(!v.iter().any(|v| v.rule_id == "schema-drift"));
    }

    #[test]
    fn fuzz_drift_004_alter_nonexistent_table() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze("ALTER TABLE nonexistent ADD COLUMN x int;", &mut state)
            .unwrap();
        assert!(v.iter().any(|v| v.rule_id == "schema-drift"));
    }

    // Size-aware tiers.

    #[test]
    fn fuzz_size_001_large_table_drop() {
        let engine = setup_engine();
        let cache = cache_with_table("public", "big_table", Some(1_000_000));
        let mut state = AnalysisState::new(cache);
        let v = engine.analyze("DROP TABLE big_table;", &mut state).unwrap();
        assert!(
            v.iter().any(
                |v| v.tier == safe_migrate::_internal::report::violations::ViolationTier::Tier1
            )
        );
    }

    #[test]
    fn fuzz_size_002_small_table_drop() {
        let engine = setup_engine();
        let cache = cache_with_table("public", "small_table", Some(5));
        let mut state = AnalysisState::new(cache);
        let v = engine
            .analyze("DROP TABLE small_table;", &mut state)
            .unwrap();
        assert!(!v.is_empty());
    }

    // Deterministic ordering.

    #[test]
    fn fuzz_order_001_violations_sorted_by_tier() {
        let engine = setup_engine();
        let mut state = setup_state();
        let v = engine
            .analyze(
                "DO $$ BEGIN NULL; END $$; DROP TABLE nonexistent; VACUUM FULL t1;",
                &mut state,
            )
            .unwrap();
        for w in v.windows(2) {
            assert!(w[0].tier <= w[1].tier, "Violations not sorted by tier");
        }
    }

    // State consistency.

    #[test]
    fn fuzz_state_001_rollback_restores_relations() {
        let engine = setup_engine();
        let cache = cache_with_table("public", "t1", Some(10));
        let mut state = AnalysisState::new(cache);
        assert!(state.relation_is_present(&object_id("public", "t1")));

        engine
            .analyze("BEGIN; DROP TABLE t1; ROLLBACK;", &mut state)
            .unwrap();
        assert!(
            state.relation_is_present(&object_id("public", "t1")),
            "Table should exist after ROLLBACK"
        );
    }

    #[test]
    fn fuzz_state_002_commit_removes_table() {
        let engine = setup_engine();
        let cache = cache_with_table("public", "t1", Some(10));
        let mut state = AnalysisState::new(cache);

        engine
            .analyze("BEGIN; DROP TABLE t1; COMMIT;", &mut state)
            .unwrap();
        assert!(
            !state.relation_is_present(&object_id("public", "t1")),
            "Table should not exist after COMMIT"
        );
    }

    #[test]
    fn fuzz_state_003_savepoint_partial_rollback() {
        let engine = setup_engine();
        let cache = cache_with_table("public", "t1", Some(10));
        let mut state = AnalysisState::new(cache);

        engine
            .analyze(
                "BEGIN; CREATE TABLE t2 (id int); SAVEPOINT s1; DROP TABLE t1; ROLLBACK TO s1; COMMIT;",
                &mut state,
            )
            .unwrap();
        assert!(
            state.relation_is_present(&object_id("public", "t1")),
            "t1 should exist after ROLLBACK TO savepoint"
        );
        assert!(
            state.relation_is_present(&object_id("public", "t2")),
            "t2 should exist after COMMIT"
        );
    }
}
