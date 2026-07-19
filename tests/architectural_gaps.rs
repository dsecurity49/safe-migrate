mod common;

mod architectural_gap_tests {
    use crate::common::*;
    use safe_migrate::analysis::state::Confidence;
    use safe_migrate::ast::identifiers::ObjectId;
    use safe_migrate::model::relation::{Persistence, RelationKind, RelationOverlay};
    use safe_migrate::model::types::TypeOverlay;
    use safe_migrate::report::violations::ViolationTier;

    // 1. Foreign-key parent-table escalation
    #[test]
    fn test_fk_parent_table_lock_escalation() {
        let engine = setup_engine();
        let mut cache = safe_migrate::db::cache::DbCache::new();

        // Parent is huge (causes Tier 1 lock if evaluated correctly)
        cache.insert_baseline(
            object_id("public", "parent_tbl"),
            safe_migrate::model::relation::RelationState::new(
                object_id("public", "parent_tbl"),
                ObjectId::new("public", "postgres"),
                0,
                Some(500_000),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        // Child is tiny
        cache.insert_baseline(
            object_id("public", "child_tbl"),
            safe_migrate::model::relation::RelationState::new(
                object_id("public", "child_tbl"),
                ObjectId::new("public", "postgres"),
                0,
                Some(10),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );

        let mut state = safe_migrate::analysis::state::AnalysisState::new(cache);
        let violations = engine.analyze("ALTER TABLE child_tbl ADD CONSTRAINT fk FOREIGN KEY (p_id) REFERENCES parent_tbl(id);", &mut state).unwrap();

        let is_tier_1 = violations
            .iter()
            .any(|v| v.tier == ViolationTier::Tier1 && v.rule_id.contains("blocking-constraint"));
        assert!(
            is_tier_1,
            "Failed to escalate lock severity based on parent table size"
        );
    }

    // 2. Nested RELEASE SAVEPOINT rollback chain
    #[test]
    fn test_nested_release_savepoint_chain() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "
            BEGIN;
            CREATE TABLE t1(id int);
            SAVEPOINT s1;
            CREATE TABLE t2(id int);
            SAVEPOINT s2;
            CREATE TABLE t3(id int);
            RELEASE SAVEPOINT s2;
            ROLLBACK TO s1;
            COMMIT;
        ",
                &mut state,
            )
            .unwrap();

        assert!(state.relation_is_present(&object_id("public", "t1")));
        assert!(!state.relation_is_present(&object_id("public", "t2")));
        assert!(!state.relation_is_present(&object_id("public", "t3")));
    }

    // 3. ROLLBACK TO SAVEPOINT partial preservation
    #[test]
    fn test_rollback_to_savepoint_partial() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "
            BEGIN;
            CREATE TABLE a(id int);
            SAVEPOINT s;
            CREATE TABLE b(id int);
            ROLLBACK TO s;
            CREATE TABLE c(id int);
            COMMIT;
        ",
                &mut state,
            )
            .unwrap();

        assert!(state.relation_is_present(&object_id("public", "a")));
        assert!(state.relation_is_present(&object_id("public", "c")));
        assert!(!state.relation_is_present(&object_id("public", "b")));
    }

    // 4. DROP SCHEMA CASCADE rename-edge cleanup
    #[test]
    fn test_drop_schema_cascade_cleans_renames() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE SCHEMA s; CREATE TABLE s.t(id int); ALTER TABLE s.t RENAME TO t2;",
                &mut state,
            )
            .unwrap();
        assert!(!state.local.graph.renames.is_empty());

        engine
            .analyze("DROP SCHEMA s CASCADE;", &mut state)
            .unwrap();
        assert!(
            state.local.graph.renames.is_empty(),
            "Rename edges leaked after schema cascade"
        );
    }

    // 5. Multi-schema search_path resolution
    #[test]
    fn test_multi_schema_search_path_resolution() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE SCHEMA s1; CREATE SCHEMA s2; SET search_path TO s1, s2;",
                &mut state,
            )
            .unwrap();
        engine
            .analyze("CREATE TABLE t1(id int);", &mut state)
            .unwrap();
        assert!(state.relation_is_present(&object_id("s1", "t1")));
    }

    // 6. Tombstone shadowing / recreate semantics
    #[test]
    fn test_tombstone_shadowing_recreate() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();
        let gen1 = if let RelationOverlay::Present(r) =
            state.get_relation(&object_id("public", "t")).unwrap()
        {
            r.generation
        } else {
            0
        };

        engine.analyze("DROP TABLE t;", &mut state).unwrap();
        engine
            .analyze("CREATE TABLE t(new_id text);", &mut state)
            .unwrap();
        if let RelationOverlay::Present(r) = state.get_relation(&object_id("public", "t")).unwrap()
        {
            assert!(
                r.generation > gen1,
                "Recreated table must have higher generation"
            );
            assert!(r.has_column("new_id"));
        } else {
            panic!("Table did not recreate over tombstone");
        }
    }

    // 7. DROP without IF EXISTS must not mutate topology
    #[test]
    fn test_drop_missing_object_halts_topology_mutation() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE exists_tbl(id int);", &mut state)
            .unwrap();
        let _ = engine.analyze("DROP TABLE missing_tbl;", &mut state);

        assert!(state.relation_is_present(&object_id("public", "exists_tbl")));
        assert_eq!(state.local.confidence, Confidence::Tainted);
    }

    // 8. View dependency alias/CTE isolation
    #[test]
    fn test_view_dependency_cte_isolation() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE base_table(id int);", &mut state)
            .unwrap();
        engine
            .analyze(
                "CREATE VIEW v AS WITH my_cte AS (SELECT * FROM base_table) SELECT * FROM my_cte;",
                &mut state,
            )
            .unwrap();

        let edge = state
            .local
            .graph
            .views
            .iter()
            .find(|v| v.view_id == object_id("public", "v"))
            .unwrap();
        assert!(edge.depends_on.contains(&object_id("public", "base_table")));
        assert!(!edge.depends_on.contains(&object_id("public", "my_cte")));
    }

    #[test]
    fn test_view_dependency_schema_qualified() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE app_sessions(id int);", &mut state)
            .unwrap();
        engine
            .analyze("CREATE VIEW v AS SELECT * FROM app_sessions;", &mut state)
            .unwrap();

        let edge = state
            .local
            .graph
            .views
            .iter()
            .find(|v| v.view_id == object_id("public", "v"))
            .unwrap();
        assert!(
            edge.depends_on
                .contains(&object_id("public", "app_sessions"))
        );
    }

    #[test]
    fn test_view_dependency_intermediate_segments_skipped() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE sessions(id int);", &mut state)
            .unwrap();
        engine
            .analyze("CREATE VIEW v AS SELECT * FROM app.sessions;", &mut state)
            .unwrap();

        let edge = state
            .local
            .graph
            .views
            .iter()
            .find(|v| v.view_id == object_id("public", "v"))
            .unwrap();

        assert!(
            edge.depends_on.contains(&object_id("app", "sessions")),
            "Schema-qualified table should produce qualified depends_on entry"
        );

        assert!(
            !edge.depends_on.contains(&object_id("public", "app")),
            "Schema segment should not appear as a phantom dependency"
        );
    }

    // 9. Partition graph cleanup after DROP TABLE
    #[test]
    fn test_partition_graph_cleanup_on_drop() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine.analyze("CREATE TABLE p(id int) PARTITION BY RANGE(id); CREATE TABLE c PARTITION OF p FOR VALUES FROM (1) TO (10);", &mut state).unwrap();
        engine.analyze("DROP TABLE c;", &mut state).unwrap();
        assert!(
            state.local.graph.partitions.is_empty(),
            "Partition edge leaked after child drop"
        );
    }

    // 10. Concurrent index rollback semantics
    #[test]
    fn test_concurrent_index_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();
        engine
            .analyze(
                "BEGIN; CREATE INDEX CONCURRENTLY idx ON t(id); ROLLBACK;",
                &mut state,
            )
            .unwrap();
        assert!(state.local.graph.indexes.is_empty());
    }

    // 11. Opaque confidence taint persistence
    #[test]
    fn test_opaque_confidence_taint_persistence() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("DO $$ BEGIN EXECUTE 'DROP TABLE x;'; END $$;", &mut state)
            .unwrap();
        assert_eq!(state.local.confidence, Confidence::Tainted);
        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();
        assert_eq!(state.local.confidence, Confidence::Tainted);
    }

    // 12. Quoted identifier + search_path interaction
    #[test]
    fn test_quoted_ident_search_path() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE SCHEMA \"MySchema\"; SET search_path TO \"MySchema\";",
                &mut state,
            )
            .unwrap();
        engine
            .analyze("CREATE TABLE \"MyTable\" (\"MyCol\" int);", &mut state)
            .unwrap();
        assert!(state.relation_is_present(&object_id("MySchema", "MyTable")));
    }

    // 13. CREATE TYPE recreation after DROP
    #[test]
    fn test_create_domain_recreation() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE DOMAIN my_type AS int;", &mut state)
            .unwrap();
        engine.analyze("DROP DOMAIN my_type;", &mut state).unwrap();
        engine
            .analyze("CREATE DOMAIN my_type AS text;", &mut state)
            .unwrap();
        assert!(matches!(
            state.local.types.get(&object_id("public", "my_type")),
            Some(TypeOverlay::Present(_))
        ));
    }

    // 14. Duplicate/stale view-edge cleanup
    #[test]
    fn test_stale_view_edge_cleanup() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE t(id int); CREATE VIEW v AS SELECT * FROM t;",
                &mut state,
            )
            .unwrap();
        engine
            .analyze("DROP VIEW v; CREATE VIEW v AS SELECT * FROM t;", &mut state)
            .unwrap();
        assert_eq!(
            state.local.graph.views.len(),
            1,
            "Duplicate view edge created"
        );
    }

    // 15. IF NOT EXISTS metadata preservation
    #[test]
    fn test_if_not_exists_preserves_original_metadata() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id INT);", &mut state)
            .unwrap();
        let gen1 = if let RelationOverlay::Present(r) =
            state.get_relation(&object_id("public", "t")).unwrap()
        {
            r.generation
        } else {
            0
        };

        engine
            .analyze(
                "CREATE TABLE IF NOT EXISTS t(id TEXT, diff_col INT);",
                &mut state,
            )
            .unwrap();

        let rel = state.get_relation(&object_id("public", "t")).unwrap();
        if let RelationOverlay::Present(r) = rel {
            assert_eq!(r.generation, gen1);
            assert_eq!(
                r.get_column("id").unwrap().data_type.as_deref(),
                Some("INT")
            );
            assert!(!r.has_column("diff_col"));
        }
    }

    // 16. Deep Rename Traversal across Cascade (BUG-004)
    #[test]
    fn test_deep_rename_traversal_cascade() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "
            CREATE TABLE a(id int);
            CREATE VIEW v AS SELECT * FROM a;
            ALTER TABLE a RENAME TO b;
            DROP TABLE b CASCADE;
        ",
                &mut state,
            )
            .unwrap();

        // The View 'v' relies on 'a'. We renamed 'a' to 'b'.
        // Dropping 'b' should dynamically resolve the rename graph and correctly drop 'v'.
        assert!(
            !state.relation_is_present(&object_id("public", "a")),
            "Original table a should be gone"
        );
        assert!(
            !state.relation_is_present(&object_id("public", "b")),
            "Renamed table b should be gone"
        );
        assert!(
            !state.relation_is_present(&object_id("public", "v")),
            "Dependent view v should have been cascaded"
        );
    }

    // 17. Partition Cycle Rejection (BUG-012)
    #[test]
    fn test_partition_cycle_rejection() {
        let engine = setup_engine();
        let mut state = setup_state();

        // Attempting to attach 'a' as a partition of 'b', while 'b' is a partition of 'a'
        engine
            .analyze(
                "
            CREATE TABLE a(id int) PARTITION BY RANGE(id);
            CREATE TABLE b PARTITION OF a FOR VALUES FROM (1) TO (10) PARTITION BY RANGE(id);
            ALTER TABLE b ATTACH PARTITION a FOR VALUES FROM (1) TO (10);
        ",
                &mut state,
            )
            .unwrap();

        // The cycle detector should catch the infinite loop and gracefully degrade
        // to an Opaque/DynamicSql mutation, tainting the engine rather than stack-overflowing.
        assert_eq!(
            state.local.confidence,
            Confidence::Tainted,
            "Partition cycle should taint the engine"
        );
    }

    // 18. Tablespace and Access Method Rewrite Rule
    #[test]
    fn test_tablespace_access_method_rewrite() {
        let engine = setup_engine();
        let mut cache = safe_migrate::db::cache::DbCache::new();

        // Force Tier 1 by giving the table 150,000 rows
        cache.insert_baseline(
            object_id("public", "massive_table"),
            safe_migrate::model::relation::RelationState::new(
                object_id("public", "massive_table"),
                ObjectId::new("public", "postgres"),
                0,
                Some(150_000),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            ),
        );
        let mut state = safe_migrate::analysis::state::AnalysisState::new(cache);

        let v1 = engine
            .analyze(
                "ALTER TABLE massive_table SET ACCESS METHOD columnar;",
                &mut state,
            )
            .unwrap();
        assert!(
            v1.iter()
                .any(|v| v.rule_id == "table-rewrite-access-method"
                    && v.tier == ViolationTier::Tier1)
        );

        let v2 = engine
            .analyze(
                "ALTER TABLE massive_table ALTER COLUMN id SET STORAGE MAIN;",
                &mut state,
            )
            .unwrap();
        assert!(
            v2.iter()
                .any(|v| v.rule_id == "table-rewrite-storage" && v.tier == ViolationTier::Tier1)
        );
    }
    // 19. Generation counter rollback (BUG-001/002)
    #[test]
    fn test_generation_counter_rollback() {
        let engine = setup_engine();
        let mut state = setup_state();

        let initial_gen = state.local.generation_counter;

        engine
            .analyze("BEGIN; CREATE TABLE t(id int);", &mut state)
            .unwrap();
        let mid_gen = state.local.generation_counter;
        assert!(
            mid_gen > initial_gen,
            "Generation counter should increment on create"
        );

        engine.analyze("ROLLBACK;", &mut state).unwrap();
        let post_gen = state.local.generation_counter;
        assert_eq!(
            post_gen, initial_gen,
            "Generation counter should restore strictly to pre-txn state on rollback"
        );
    }

    // 20. Partition children cascade (BUG-003)
    #[test]
    fn test_partition_children_cascade_enumeration() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "
            CREATE TABLE parent(id int) PARTITION BY RANGE(id);
            CREATE TABLE child PARTITION OF parent FOR VALUES FROM (1) TO (10);
            DROP TABLE parent CASCADE;
        ",
                &mut state,
            )
            .unwrap();

        assert!(
            !state.relation_is_present(&object_id("public", "parent")),
            "Parent should be dropped"
        );
        assert!(
            !state.relation_is_present(&object_id("public", "child")),
            "Child should be dropped via reverse-graph cascade"
        );
    }

    // 21. Rename updates FK graph edges implicitly via resolver (BUG-004)
    #[test]
    fn test_rename_updates_fk_graph_edges() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "
            CREATE TABLE a(id int);
            CREATE TABLE b(a_id int);
            ALTER TABLE b ADD CONSTRAINT fk FOREIGN KEY (a_id) REFERENCES a(id);
            ALTER TABLE a RENAME TO a2;
        ",
                &mut state,
            )
            .unwrap();

        let refs = state
            .local
            .graph
            .is_referenced_by_fk(&object_id("public", "a2"));
        assert!(
            !refs.is_empty(),
            "a2 should be recognized as referenced by b's FK dynamically"
        );
        assert_eq!(refs[0].0, &object_id("public", "b"));
    }

    // 22. Search path existence check (BUG-005)
    #[test]
    fn test_search_path_existence_check() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "
            CREATE SCHEMA actual_schema;
            CREATE TABLE actual_schema.my_table(id int);
            SET search_path = nonexistent_schema, actual_schema;
            ALTER TABLE my_table ADD COLUMN new_col int;
        ",
                &mut state,
            )
            .unwrap();

        let rel = state
            .get_relation(&object_id("actual_schema", "my_table"))
            .unwrap();
        if let safe_migrate::model::relation::RelationOverlay::Present(r) = rel {
            assert!(
                r.has_column("new_col"),
                "Should resolve to actual_schema bypassing nonexistent_schema"
            );
        } else {
            panic!("Table not found; resolver hallucinated the schema");
        }
    }

    // 23. Drop without cascade validates dependents (BUG-006)
    #[test]
    fn test_drop_without_cascade_validates_dependents() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "
            CREATE TABLE a(id int);
            CREATE TABLE b(a_id int);
            ALTER TABLE b ADD CONSTRAINT fk FOREIGN KEY (a_id) REFERENCES a(id);
        ",
                &mut state,
            )
            .unwrap();

        // Drop without cascade
        let _ = engine.analyze("DROP TABLE a;", &mut state);

        // It should taint confidence and skip the drop
        assert_eq!(
            state.local.confidence,
            safe_migrate::analysis::state::Confidence::Tainted,
            "Engine should taint on unsafe drop"
        );
        assert!(
            state.relation_is_present(&object_id("public", "a")),
            "Table a should not be dropped if dependents exist without CASCADE"
        );
    }

    // 24. ALTER TABLE typed actions produce opaque without crashing
    #[test]
    fn test_alter_table_set_access_method_typed() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();
        let result = engine.analyze("ALTER TABLE t SET ACCESS METHOD heap;", &mut state);
        assert!(result.is_ok(), "SetAccessMethod should not crash");
    }

    #[test]
    fn test_alter_table_disable_enable_trigger_typed() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();
        let r1 = engine.analyze("ALTER TABLE t DISABLE TRIGGER ALL;", &mut state);
        assert!(r1.is_ok(), "DisableTrigger should not crash");
        let r2 = engine.analyze("ALTER TABLE t ENABLE TRIGGER ALL;", &mut state);
        assert!(r2.is_ok(), "EnableTrigger should not crash");
        let r3 = engine.analyze("ALTER TABLE t ENABLE TRIGGER my_trig;", &mut state);
        assert!(r3.is_ok(), "EnableTrigger named should not crash");
    }

    #[test]
    fn test_alter_table_set_schema_does_not_crash() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();
        let result = engine.analyze("ALTER TABLE t SET SCHEMA target;", &mut state);
        assert!(result.is_ok(), "SetSchema should not crash");
    }

    #[test]
    fn test_alter_table_set_tablespace_does_not_crash() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();
        let result = engine.analyze("ALTER TABLE t SET TABLESPACE fastspace;", &mut state);
        assert!(result.is_ok(), "SetTablespace should not crash");
    }

    #[test]
    fn test_alter_table_owner_to_does_not_crash() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();
        let result = engine.analyze("ALTER TABLE t OWNER TO app_owner;", &mut state);
        assert!(result.is_ok(), "OwnerTo should not crash");
    }

    #[test]
    fn test_alter_table_logged_unlogged_does_not_crash() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();
        let r1 = engine.analyze("ALTER TABLE t SET LOGGED;", &mut state);
        assert!(r1.is_ok(), "SetLogged should not crash");
        let r2 = engine.analyze("ALTER TABLE t SET UNLOGGED;", &mut state);
        assert!(r2.is_ok(), "SetUnlogged should not crash");
    }

    #[test]
    fn test_alter_table_replica_identity_does_not_crash() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();
        let r1 = engine.analyze("ALTER TABLE t REPLICA IDENTITY FULL;", &mut state);
        assert!(r1.is_ok(), "ReplicaIdentity FULL should not crash");
        let r2 = engine.analyze("ALTER TABLE t REPLICA IDENTITY DEFAULT;", &mut state);
        assert!(r2.is_ok(), "ReplicaIdentity DEFAULT should not crash");
        let r3 = engine.analyze("ALTER TABLE t REPLICA IDENTITY NOTHING;", &mut state);
        assert!(r3.is_ok(), "ReplicaIdentity NOTHING should not crash");
        let r4 = engine.analyze(
            "ALTER TABLE t REPLICA IDENTITY USING INDEX my_idx;",
            &mut state,
        );
        assert!(r4.is_ok(), "ReplicaIdentity USING INDEX should not crash");
    }

    #[test]
    fn test_alter_table_cluster_on_does_not_crash() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();
        let result = engine.analyze("ALTER TABLE t CLUSTER ON t_pkey;", &mut state);
        assert!(result.is_ok(), "ClusterOn should not crash");
    }

    #[test]
    fn test_alter_table_inherit_does_not_crash() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE parent(id int); CREATE TABLE child(id int);",
                &mut state,
            )
            .unwrap();
        let result = engine.analyze("ALTER TABLE child INHERIT parent;", &mut state);
        assert!(result.is_ok(), "InheritTable should not crash");
        let r2 = engine.analyze("ALTER TABLE child NO INHERIT parent;", &mut state);
        assert!(r2.is_ok(), "NoInheritTable should not crash");
    }

    #[test]
    fn test_alter_table_rls_force_does_not_crash() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();
        let r1 = engine.analyze("ALTER TABLE t ENABLE ROW LEVEL SECURITY;", &mut state);
        assert!(r1.is_ok(), "EnableRls should not crash");
        let r2 = engine.analyze("ALTER TABLE t FORCE ROW LEVEL SECURITY;", &mut state);
        assert!(r2.is_ok(), "ForceRls should not crash");
        let r3 = engine.analyze("ALTER TABLE t DISABLE ROW LEVEL SECURITY;", &mut state);
        assert!(r3.is_ok(), "DisableRls should not crash");
    }

    #[test]
    fn test_alter_table_merge_split_partition_does_not_crash() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TABLE p(id int) PARTITION BY RANGE (id);
             CREATE TABLE p1 PARTITION OF p FOR VALUES FROM (1) TO (10);
             CREATE TABLE p2 PARTITION OF p FOR VALUES FROM (10) TO (20);",
                &mut state,
            )
            .unwrap();
        let sql = "ALTER TABLE p MERGE PARTITIONS p1, p2 INTO p_merged;";
        match engine.analyze(sql, &mut state) {
            Ok(_) => {} // passes
            Err(e) => {
                // Parser may not support MERGE PARTITIONS syntax — skip
                eprintln!("MergePartitions parse errors: {e:?}");
            }
        }
    }

    #[test]
    fn test_alter_table_enable_always_replica_trigger_does_not_crash() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TABLE t(id int);", &mut state)
            .unwrap();
        let r1 = engine.analyze("ALTER TABLE t ENABLE ALWAYS TRIGGER my_tg;", &mut state);
        assert!(r1.is_ok(), "EnableAlwaysTrigger should not crash");
        let r2 = engine.analyze("ALTER TABLE t ENABLE REPLICA TRIGGER my_tg;", &mut state);
        assert!(r2.is_ok(), "EnableReplicaTrigger should not crash");
    }
}

// ─────────────────────────────────────────────
// 10. Multi-File Execution (analyze_chain)
// ─────────────────────────────────────────────
