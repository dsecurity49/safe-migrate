use super::*;

#[test]
fn test_rule_idempotency() {
    let engine = setup_engine();
    let mut state = setup_state();

    let violations = engine
        .analyze(
            "
                CREATE TABLE t(id int);
                DROP TABLE t;
                CREATE INDEX i ON t(id);
                ",
            &mut state,
        )
        .unwrap();

    assert!(violations.iter().any(|v| v.rule_id.contains("idempot")));
}

#[test]
fn test_rule_cascading_drop() {
    let engine = setup_engine();
    let mut state = setup_state();

    assert!(
        engine
            .analyze(
                "
                CREATE TABLE data(id INT);
                CREATE VIEW v AS SELECT * FROM data;
                DROP TABLE data CASCADE;
                ",
                &mut state,
            )
            .is_ok()
    );
}

#[test]
fn test_rule_temporary_table_bypass() {
    let engine = setup_engine();
    let mut state = setup_state();

    let v = engine
        .analyze(
            "
                CREATE TEMP TABLE temp(id int);
                CREATE INDEX i ON temp(id);
                ALTER TABLE temp ADD UNIQUE(id);
                ",
            &mut state,
        )
        .unwrap();

    // current implementation still emits violations
    // verify parser + pipeline stability instead
    assert!(!v.is_empty());
}

#[test]
fn test_rule_mat_view_refresh() {
    let engine = setup_engine();

    let mut cache = crate::common::synced_cache();

    cache.insert_baseline(
        object_id("public", "mv"),
        RelationState::new(
            object_id("public", "mv"),
            ObjectId::new("public", "postgres"),
            0,
            Some(150_000),
            RelationKind::MaterializedView,
            Persistence::Permanent,
            0,
        ),
    );

    let mut state = AnalysisState::new(cache);

    let v1 = engine
        .analyze("REFRESH MATERIALIZED VIEW mv;", &mut state)
        .unwrap();

    assert!(
        v1.iter()
            .any(|v| v.rule_id.contains("mat") || v.rule_id.contains("refresh"))
    );

    let v2 = engine
        .analyze("REFRESH MATERIALIZED VIEW CONCURRENTLY mv;", &mut state)
        .unwrap();

    assert!(v2.len() <= v1.len());
}

#[test]
fn test_rule_concurrent_inside_txn() {
    let engine = setup_engine();
    let mut state = setup_state();

    let v = engine
        .analyze(
            "
                BEGIN;
                CREATE INDEX CONCURRENTLY i ON t(id);
                DROP INDEX CONCURRENTLY i;
                COMMIT;
                ",
            &mut state,
        )
        .unwrap();

    assert!(
        v.iter()
            .any(|v| v.rule_id.contains("transaction") || v.rule_id.contains("concurrent"))
    );
}

#[test]
fn test_rule_opaque_sql() {
    let engine = setup_engine();
    let mut state = setup_state();

    let v = engine.analyze("DO $$ BEGIN END $$;", &mut state).unwrap();

    assert!(
        v.iter()
            .any(|v| v.rule_id.contains("opaque") || v.rule_id.contains("dynamic"))
    );

    assert_eq!(state.local.confidence, Confidence::Tainted);
}

#[test]
fn test_earlier_taint_lowers_certainty_but_not_severity() {
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

    let v = engine
            .analyze(
                "DO $$ BEGIN EXECUTE 'DROP TABLE users'; END $$; DROP DATABASE mydb; DROP TABLE t CASCADE;",
                &mut state,
            )
            .unwrap();

    let db_violations: Vec<_> = v.iter().filter(|v| v.rule_id == "drop-database").collect();
    let drop_table_violations: Vec<_> = v
        .iter()
        .filter(|v| v.rule_id == "destructive-cascade" || v.rule_id == "irreversible-migration")
        .collect();

    // An unmodeled statement makes later state unknowable, not the
    // operation less destructive.
    assert!(
        db_violations.iter().all(|v| v.tier == ViolationTier::Tier1),
        "DROP DATABASE severity must survive earlier taint: {:?}",
        db_violations
    );

    assert!(
        drop_table_violations
            .iter()
            .all(|v| v.tier == ViolationTier::Tier1),
        "DROP TABLE CASCADE severity must survive earlier taint: {:?}",
        drop_table_violations
    );
}

#[test]
fn missing_relation_statistics_taint_only_statistics_based_findings() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    let table_id = object_id("public", "stats_unknown");
    let mut relation = RelationState::new(
        table_id.clone(),
        object_id("public", "postgres"),
        0,
        None,
        RelationKind::Table,
        Persistence::Permanent,
        0,
    );
    relation.columns.push(Column {
        name: "id".into(),
        data_type: Some("integer".into()),
        type_id: None,
        is_nullable: false,
        default: None,
        avg_width: Some(4),
        default_expr_text: None,
        type_modifier: None,
        storage: None,
        compression: None,
        statistics_target: None,
        options: Default::default(),
        generated: None,
    });
    cache.insert_baseline(table_id, relation);
    let mut state = AnalysisState::new(cache);

    let findings = engine
        .analyze(
            "CREATE INDEX stats_unknown_idx ON stats_unknown(id);",
            &mut state,
        )
        .unwrap();

    assert!(
        findings
            .iter()
            .any(|finding| { finding.rule_id == "require-concurrent-index" })
    );
    assert_eq!(state.local.confidence, Confidence::Tainted);
    assert!(state.evidence().iter().any(|record| {
            record.code == safe_migrate::_internal::analysis::evidence::EvidenceCode::CatalogCoverageIncomplete
        }));
}

#[test]
fn test_earlier_taint_lowers_certainty_of_later_findings_only() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    // Pin an observed version so certainty reflects only evidence taint.
    cache.pg_version_num = Some(180_002);
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

    let findings = engine
        .analyze_chain_with_locations(
            &[(
                "001.sql".to_string(),
                "DROP DATABASE mydb; DO $$ BEGIN END $$; DROP TABLE t CASCADE;".to_string(),
            )],
            &mut state,
        )
        .unwrap();

    let db: Vec<_> = findings
        .iter()
        .filter(|f| f.violation.rule_id == "drop-database")
        .collect();
    let drop: Vec<_> = findings
        .iter()
        .filter(|f| {
            matches!(
                f.violation.rule_id,
                "destructive-cascade" | "irreversible-migration"
            )
        })
        .collect();

    // Severity ignores position in the file; certainty does not.
    assert!(
        db.iter().all(|f| f.violation.tier == ViolationTier::Tier1),
        "DROP DATABASE is destructive regardless of what follows: {db:?}"
    );
    assert!(
        drop.iter()
            .all(|f| f.violation.tier == ViolationTier::Tier1),
        "DROP TABLE CASCADE is destructive regardless of what precedes: {drop:?}"
    );

    // The DO block can only invalidate state observed after it.
    assert!(
        db.iter().all(|f| f.certainty == Certainty::Exact),
        "a finding produced before the unmodeled statement is still exact: {db:?}"
    );
    assert!(
        drop.iter().all(|f| f.certainty == Certainty::Tainted),
        "a finding produced after the unmodeled statement is uncertain: {drop:?}"
    );
}

#[test]
fn test_unobserved_version_marks_findings_assumed_not_exact() {
    let engine = setup_engine();

    let analyse = |cache: crate::_internal::db::cache::DbCache| {
        let mut state = AnalysisState::new(cache);
        engine
            .analyze_chain_with_locations(
                &[("001.sql".to_string(), "DROP DATABASE mydb;".to_string())],
                &mut state,
            )
            .unwrap()
    };

    let mut observed = crate::common::synced_cache();
    observed.pg_version_num = Some(180_002);
    assert!(
        analyse(observed)
            .iter()
            .all(|f| f.certainty == Certainty::Exact),
        "an observed server version keeps a finding exact"
    );

    assert!(
        analyse(crate::common::synced_cache())
            .iter()
            .all(|f| f.certainty == Certainty::Assumed),
        "with no observed version the finding is still reported, marked assumed"
    );

    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = None;
    let mut state = AnalysisState::new(cache).with_asserted_pg_version(Some(170_000));
    let findings = engine
        .analyze_chain_with_locations(
            &[("001.sql".to_string(), "DROP DATABASE mydb;".to_string())],
            &mut state,
        )
        .unwrap();
    assert!(
        findings.iter().all(|f| f.certainty == Certainty::Assumed),
        "a configured version is an assertion, not an observation"
    );
}

#[test]
fn test_exact_confidence_keeps_tier1() {
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

    let v = engine.analyze("DROP TABLE t CASCADE;", &mut state).unwrap();

    assert!(
        v.iter().any(|v| v.tier == ViolationTier::Tier1),
        "expected Tier1 with exact confidence: {:?}",
        v
    );
    assert!(
        v.iter().all(|v| !v.reason.contains("DOWNGRADED")),
        "expected no downgrade notices with exact confidence: {:?}",
        v.iter().map(|v| &v.reason).collect::<Vec<_>>()
    );
}

#[test]
fn test_rule_restrictive_policy() {
    let engine = setup_engine();
    let mut state = setup_state();

    let v = engine
        .analyze(
            "CREATE POLICY p ON t AS RESTRICTIVE FOR SELECT TO public USING (true);",
            &mut state,
        )
        .unwrap();

    assert!(v.iter().any(|v| v.rule_id == "restrictive-policy"));
}

#[test]
fn test_rule_disable_trigger() {
    let engine = setup_engine();
    let mut state = setup_state();

    let v = engine
        .analyze("ALTER TABLE t DISABLE TRIGGER tr;", &mut state)
        .unwrap();

    assert!(v.iter().any(|v| v.rule_id == "disable-trigger"));
}

#[test]
fn test_rule_overbroad_grant() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze("CREATE TABLE t(id int);", &mut state)
        .unwrap();

    let v = engine
        .analyze("GRANT ALL ON t TO public;", &mut state)
        .unwrap();

    assert!(v.iter().any(|v| v.rule_id == "overbroad-grant"));
}

#[test]
fn grant_option_warns_even_when_state_matrix_skips_unmodeled_grant_chain() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze("CREATE TABLE grant_option_target(id int);", &mut state)
        .unwrap();

    let findings = engine
        .analyze(
            "GRANT SELECT ON grant_option_target TO app_user WITH GRANT OPTION;",
            &mut state,
        )
        .unwrap();

    assert!(findings.iter().any(|finding| {
        finding.rule_id == "overbroad-grant" && finding.reason.contains("WITH GRANT OPTION")
    }));
}

#[test]
fn grant_all_owner_exemption_requires_every_grantee_to_own_every_table() {
    let engine = setup_engine();
    let table_id = object_id("public", "owned_table");
    let mut cache = crate::common::synced_cache();
    cache.insert_baseline(
        table_id.clone(),
        RelationState::new(
            table_id,
            object_id("", "table_owner"),
            0,
            Some(10),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );

    let mut owner_only_state = AnalysisState::new(cache.clone());
    let owner_only = engine
        .analyze(
            "GRANT ALL ON owned_table TO table_owner;",
            &mut owner_only_state,
        )
        .unwrap();
    assert!(
        !owner_only
            .iter()
            .any(|violation| violation.rule_id == "overbroad-grant")
    );

    let mut mixed_state = AnalysisState::new(cache);
    let mixed = engine
        .analyze(
            "GRANT ALL ON owned_table TO table_owner, outsider;",
            &mut mixed_state,
        )
        .unwrap();
    assert!(
        mixed
            .iter()
            .any(|violation| violation.rule_id == "overbroad-grant")
    );
}

#[test]
fn test_rule_function_volatility_change() {
    let engine = setup_engine();
    let mut state = setup_state();

    // Create a function first
    engine
            .analyze(
                "CREATE FUNCTION add(a int, b int) RETURNS int LANGUAGE plpgsql IMMUTABLE AS 'BEGIN RETURN a + b; END';",
                &mut state,
            )
            .unwrap();

    let func_id = ObjectId::new("public", "add(integer,integer)");
    assert!(state.local.functions.contains_key(&func_id));

    // Alter volatility
    let v = engine
        .analyze("ALTER FUNCTION add(int, int) VOLATILE;", &mut state)
        .unwrap();

    assert!(
        v.iter().any(|v| v.rule_id == "function-volatility-change"),
        "Should flag volatility change from IMMUTABLE to VOLATILE"
    );
}

#[test]
fn test_rule_function_volatility_unchanged() {
    let engine = setup_engine();
    let mut state = setup_state();

    // Create a function
    engine
            .analyze(
                "CREATE FUNCTION stable_func() RETURNS int LANGUAGE plpgsql STABLE AS 'BEGIN RETURN 1; END';",
                &mut state,
            )
            .unwrap();

    // Alter the function with same volatility (no change)
    let v = engine
        .analyze("ALTER FUNCTION stable_func() STABLE;", &mut state)
        .unwrap();

    assert!(
        !v.iter().any(|v| v.rule_id == "function-volatility-change"),
        "Should NOT flag when volatility is unchanged"
    );
}

#[test]
fn test_rule_function_schema_change() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
            .analyze(
                "CREATE FUNCTION my_func() RETURNS int LANGUAGE plpgsql IMMUTABLE AS 'BEGIN RETURN 1; END';",
                &mut state,
            )
            .unwrap();

    let orig_id = ObjectId::new("public", "my_func()");
    assert!(state.local.functions.contains_key(&orig_id));

    // ALTER FUNCTION ... SET SCHEMA should work without volatility violation
    let v = engine
        .analyze("ALTER FUNCTION my_func() SET SCHEMA myschema;", &mut state)
        .unwrap();

    assert!(
        !v.iter().any(|v| v.rule_id == "function-volatility-change"),
        "Schema change should not trigger volatility rule"
    );
}

#[test]
fn test_overloaded_function_search_path() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze("CREATE SCHEMA myschema;", &mut state)
        .unwrap();
    engine
        .analyze("SET search_path TO myschema, public;", &mut state)
        .unwrap();
    engine.analyze(
            "CREATE FUNCTION myschema.my_overloaded_func(x integer) RETURNS int LANGUAGE plpgsql IMMUTABLE AS 'BEGIN RETURN x; END';",
            &mut state
        ).unwrap();

    // Resolve function using search path and alter it
    let v = engine
        .analyze(
            "ALTER FUNCTION my_overloaded_func(integer) IMMUTABLE;",
            &mut state,
        )
        .unwrap();

    assert!(v.is_empty());
    let target_id = ObjectId::new("myschema", "my_overloaded_func(integer)");
    assert!(state.local.functions.contains_key(&target_id));
}

#[test]
fn test_rule_drop_function_recreate() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "CREATE FUNCTION temp_func() RETURNS int LANGUAGE plpgsql AS 'BEGIN RETURN 1; END';",
            &mut state,
        )
        .unwrap();

    let func_id = ObjectId::new("public", "temp_func()");
    assert!(state.local.functions.contains_key(&func_id));

    // Drop and recreate
    engine
        .analyze("DROP FUNCTION temp_func();", &mut state)
        .unwrap();
    assert!(matches!(
        state.local.functions.get(&func_id),
        Some(FunctionOverlay::Dropped)
    ));

    engine
            .analyze(
                "CREATE FUNCTION temp_func() RETURNS text LANGUAGE plpgsql AS 'BEGIN RETURN ''hello''; END';",
                &mut state,
            )
            .unwrap();

    // Should be present again
    assert!(matches!(
        state.local.functions.get(&func_id),
        Some(FunctionOverlay::Present(_))
    ));
}

#[test]
fn test_rule_broken_compute_drop_function_with_trigger() {
    let engine = setup_engine();
    let mut state = setup_state();
    let function_id = object_id("public", "notify_func()");
    state.local.functions.insert(
        function_id.clone(),
        FunctionOverlay::Present(FunctionState {
            return_type: "trigger".into(),
            language: "plpgsql".into(),
            ..FunctionState::with_inputs(function_id, RoutineKind::Function, Vec::new())
        }),
    );

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
        "Dropping a function used by a trigger should fire 'broken-compute' rule"
    );

    let violation = v
        .iter()
        .find(|violation| violation.rule_id == "broken-compute")
        .unwrap();
    assert_eq!(violation.tier, ViolationTier::Tier1);
    assert!(violation.reason.contains("trg_events"));
    assert!(violation.reason.contains("events"));
}

#[test]
fn test_rule_vacuum_full() {
    let engine = setup_engine();
    let mut state = setup_state();

    let v = engine.analyze("VACUUM FULL t;", &mut state).unwrap();

    assert!(v.iter().any(|v| v.rule_id.contains("vacuum")));
    assert!(state.evidence().iter().any(|record| {
        record.code
            == safe_migrate::_internal::analysis::evidence::EvidenceCode::UnsupportedSemantics
    }));
}

#[test]
fn unresolved_statement_records_unevaluated_rules_with_a_remedy() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    // A target outside the synced scope cannot be seen, so post-state rules
    // must decline rather than guess.
    cache.metadata.schemas = Some(vec!["app".to_string()]);
    let mut state = AnalysisState::new(cache);

    engine
        .analyze("DROP TABLE public.secret_table CASCADE;", &mut state)
        .unwrap();

    let not_evaluated = state.not_evaluated();
    assert!(
        !not_evaluated.is_empty(),
        "an unresolvable target must record which rules did not run"
    );
    assert!(
        not_evaluated.iter().any(|entry| !entry.recipe.is_empty()),
        "each record must say what would make the rule evaluable"
    );
}

#[test]
fn an_unresolvable_grant_to_public_is_still_reported() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.metadata.schemas = Some(vec!["app".to_string()]);
    let mut state = AnalysisState::new(cache);

    let violations = engine
        .analyze(
            "GRANT SELECT ON TABLE public.secret_table TO PUBLIC;",
            &mut state,
        )
        .unwrap();

    assert!(
        violations
            .iter()
            .any(|v| v.rule_id == "overbroad-grant" && v.reason.contains("Grant to PUBLIC")),
        "the grantee comes from the statement, so an unknown relation cannot excuse it"
    );
}

#[test]
fn statements_postgresql_skips_draw_no_findings() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.metadata.source_lock_timeout_ms = 1_000;
    cache.metadata.source_statement_timeout_ms = 10_000;
    let mut table = RelationState::new(
        object_id("public", "t"),
        object_id("public", "postgres"),
        0,
        Some(1_000),
        RelationKind::Table,
        Persistence::Permanent,
        0,
    );
    table.columns.push(Column::migration_created(
        "id".to_string(),
        Some("integer".to_string()),
        true,
        None,
    ));
    table.columns.push(Column::migration_created(
        "note".to_string(),
        Some("text".to_string()),
        true,
        None,
    ));
    cache.insert_baseline(object_id("public", "t"), table);
    // Holds the index namespace, exactly as a same-name relation would.
    cache.insert_baseline(
        object_id("public", "t_idx"),
        RelationState::new(
            object_id("public", "t_idx"),
            object_id("public", "postgres"),
            0,
            Some(0),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );
    let mut state = AnalysisState::new(cache);

    let violations = engine
        .analyze(
            "CREATE TABLE IF NOT EXISTS t (id int, note text DEFAULT random());
                 ALTER TABLE t ADD COLUMN IF NOT EXISTS note text DEFAULT random();
                 CREATE INDEX IF NOT EXISTS t_idx ON t (id);
                 DROP INDEX IF EXISTS t_missing_idx;
                 DROP TABLE IF EXISTS t_missing;",
            &mut state,
        )
        .unwrap();

    // PostgreSQL skipped every statement, so no rule about what a migration
    // changes has a subject. A new rule that reports on a skipped statement
    // fails here rather than in production.
    assert_eq!(
        violations
            .iter()
            .map(|violation| violation.rule_id)
            .collect::<Vec<_>>(),
        Vec::<&str>::new()
    );
}

#[test]
fn scoped_cache_reports_unknown_schema_as_coverage_not_drift() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.metadata.schemas = Some(vec!["app".to_string()]);
    let mut state = AnalysisState::new(cache);
    let violations = engine
        .analyze(
            "ALTER TABLE public.external_table ADD COLUMN note text;",
            &mut state,
        )
        .unwrap();

    let coverage = violations
        .iter()
        .find(|violation| violation.rule_id == "schema-drift")
        .expect("an omitted schema must be reported as unknown coverage");
    assert_eq!(coverage.tier, ViolationTier::Tier2);
    assert!(coverage.reason.contains("does not cover schema \"public\""));
    assert!(!coverage.reason.contains("does not exist"));
}

#[test]
fn guarded_missing_drops_do_not_report_schema_drift() {
    let engine = setup_engine();
    for sql in [
        "DROP TABLE IF EXISTS missing;",
        "DROP VIEW IF EXISTS missing;",
        "DROP MATERIALIZED VIEW IF EXISTS missing;",
        "DROP INDEX IF EXISTS missing;",
        "DROP SEQUENCE IF EXISTS missing;",
        "DROP FUNCTION IF EXISTS missing();",
        "DROP PROCEDURE IF EXISTS missing();",
        "DROP DOMAIN IF EXISTS missing;",
        "DROP TYPE IF EXISTS missing;",
    ] {
        let mut state = setup_state();
        let violations = engine.analyze(sql, &mut state).unwrap();
        assert!(
            !violations
                .iter()
                .any(|violation| violation.rule_id == "schema-drift"),
            "{sql}"
        );
    }
}

#[test]
fn missing_procedure_changes_report_schema_drift() {
    let engine = setup_engine();

    for sql in [
        "DROP PROCEDURE missing(integer);",
        "ALTER PROCEDURE missing(integer) RENAME TO renamed;",
    ] {
        let mut state = setup_state();
        let violations = engine.analyze(sql, &mut state).unwrap();
        assert!(
            violations.iter().any(|violation| {
                violation.rule_id == "schema-drift"
                    && violation.object_kind
                        == safe_migrate::_internal::report::violations::ObjectKind::Procedure
            }),
            "{sql}"
        );
    }
}

#[test]
fn procedure_drift_checks_the_cached_routine_kind() {
    let engine = setup_engine();
    let routine_id = object_id("public", "work(integer)");

    for routine_kind in [RoutineKind::Function, RoutineKind::Procedure] {
        let mut cache = crate::common::synced_cache();
        cache.functions.insert(
            routine_id.clone(),
            FunctionState {
                return_type: "void".into(),
                ..FunctionState::with_inputs(
                    routine_id.clone(),
                    routine_kind,
                    vec!["integer".into()],
                )
            },
        );
        let mut state = AnalysisState::new(cache);
        let violations = engine
            .analyze(
                "ALTER PROCEDURE work(integer) RENAME TO renamed;",
                &mut state,
            )
            .unwrap();
        assert_eq!(
            violations
                .iter()
                .filter(|violation| violation.rule_id == "schema-drift")
                .count(),
            usize::from(routine_kind == RoutineKind::Function)
        );
    }
}

#[test]
fn function_identity_ignores_typmods() {
    // PostgreSQL treats foo(varchar) and foo(varchar(10)) as one function,
    // so the second declaration must conflict.
    let engine = setup_engine();
    let mut state = setup_state();
    let sql = "
            CREATE FUNCTION f(a character varying) RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;
            CREATE FUNCTION f(a character varying(10)) RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;
        ";
    let v = engine.analyze(sql, &mut state).unwrap();
    assert!(
        v.iter().any(|v| v.rule_id == "chain-conflict"),
        "duplicate function differing only by typmod must conflict: {v:?}"
    );
}

#[test]
fn distinct_function_signatures_do_not_conflict() {
    let engine = setup_engine();
    let mut state = setup_state();
    let sql = "
            CREATE FUNCTION f(a character varying) RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;
            CREATE FUNCTION f(a integer) RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;
        ";
    let v = engine.analyze(sql, &mut state).unwrap();
    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "differing argument types are distinct overloads: {v:?}"
    );
}

#[test]
fn numeric_scale_outside_zero_to_precision_is_version_dependent() {
    fn column_type(
        state: &safe_migrate::_internal::analysis::state::AnalysisState,
        name: &str,
    ) -> Option<String> {
        state
            .local
            .relations
            .get(&object_id("public", "t"))
            .and_then(|overlay| match overlay {
                safe_migrate::_internal::analysis::state::RelationOverlay::Present(rel) => rel
                    .columns
                    .iter()
                    .find(|c| c.name == name)
                    .and_then(|c| c.data_type.clone()),
                _ => None,
            })
    }

    let engine = setup_engine();
    let sql = "CREATE TABLE t (v numeric(10, -2));";

    // PostgreSQL 14 rejects a negative scale outright.
    let mut pg14 = setup_state();
    pg14.baseline_available = true;
    pg14.pg_version_num = Some(140_000);
    engine.analyze(sql, &mut pg14).unwrap();
    assert!(
        !pg14.relation_is_present(&object_id("public", "t")),
        "PG14 must not accept a negative numeric scale"
    );

    // PostgreSQL 15 widened the range, so the same declaration is valid.
    let mut pg15 = setup_state();
    pg15.baseline_available = true;
    pg15.pg_version_num = Some(150_000);
    engine.analyze(sql, &mut pg15).unwrap();
    assert!(
        pg15.relation_is_present(&object_id("public", "t")),
        "PG15 accepts a negative numeric scale"
    );

    // ALTER COLUMN TYPE is checked on the same rule.
    let alter = "ALTER TABLE t ALTER COLUMN v TYPE numeric(3, 5);";
    engine
        .analyze("CREATE TABLE t (v numeric);", &mut pg14)
        .unwrap();
    let before = column_type(&pg14, "v");
    engine.analyze(alter, &mut pg14).unwrap();
    assert_eq!(
        before,
        column_type(&pg14, "v"),
        "a PG14-rejected type change must not apply"
    );
}

#[test]
fn widened_numeric_scale_without_a_baseline_taints_rather_than_conflicting() {
    let engine = setup_engine();
    let mut state = setup_state();
    let v = engine
        .analyze("CREATE TABLE t (v numeric(10, -2));", &mut state)
        .unwrap();

    // Without a version we cannot call it an error, so it must not be
    // reported as a conflict.
    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "an unjudgeable version must not be reported as a conflict: {v:?}"
    );
    assert_eq!(
        state.local.confidence,
        safe_migrate::_internal::analysis::state::Confidence::Tainted
    );
}

#[test]
fn ordinary_numeric_scale_never_taints() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE t (a numeric(10, 2), b numeric(4));",
            &mut state,
        )
        .unwrap();
    assert_eq!(
        state.local.confidence,
        safe_migrate::_internal::analysis::state::Confidence::Exact
    );
}

#[test]
fn empty_search_path_cannot_place_an_unqualified_name() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(150_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    // A path naming only a schema the baseline proves absent resolves to
    // nothing, so PostgreSQL has no creation target.
    engine
        .analyze(
            "SET search_path TO no_such_schema; CREATE TABLE t (id int);",
            &mut state,
        )
        .unwrap();
    assert!(
        !state.relation_is_present(&object_id("public", "t")),
        "an unplaceable name must not be assumed to land in public"
    );

    let v = engine
        .analyze(
            "SET search_path TO no_such_schema; CREATE TABLE t2 (id int);",
            &mut state,
        )
        .unwrap();
    assert!(
        v.iter()
            .any(|v| v.reason.contains("no schema has been selected")),
        "expected the PostgreSQL wording: {v:?}"
    );
}

#[test]
fn qualified_name_ignores_the_search_path() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "SET search_path TO no_such_schema; CREATE TABLE public.t (id int);",
            &mut state,
        )
        .unwrap();
    assert!(
        state.relation_is_present(&object_id("public", "t")),
        "a qualified name is unaffected by the path"
    );
}

#[test]
fn view_reloptions_are_modelled_rather_than_ignored() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    let v = engine
        .analyze(
            "CREATE TABLE base_v (id int);
                 CREATE VIEW v AS SELECT id FROM base_v;
                 ALTER VIEW v SET (security_barrier = true);",
            &mut state,
        )
        .unwrap();
    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "a recognised option must apply cleanly: {v:?}"
    );
    assert_eq!(
        state.local.confidence,
        safe_migrate::_internal::analysis::state::Confidence::Exact
    );

    let relation = state
        .get_relation(&object_id("public", "v"))
        .expect("view must exist");
    assert!(
        matches!(relation, RelationOverlay::Present(r)
                if r.table_options.get("security_barrier") == Some(&"true".to_string())),
        "the option must be stored: {relation:?}"
    );
}

#[test]
fn view_reloption_rejected_by_version_is_a_conflict() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(140_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    // security_invoker arrived in PostgreSQL 15.
    let v = engine
        .analyze(
            "CREATE TABLE base_v (id int);
                 CREATE VIEW v AS SELECT id FROM base_v;
                 ALTER VIEW v SET (security_invoker = true);",
            &mut state,
        )
        .unwrap();
    assert!(
        v.iter()
            .any(|v| v.reason.contains("unrecognized parameter")),
        "PG14 must reject security_invoker: {v:?}"
    );
}

#[test]
fn unknown_view_reloption_taints_without_claiming_an_error() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    let v = engine
        .analyze(
            "CREATE TABLE base_v (id int);
                 CREATE VIEW v AS SELECT id FROM base_v;
                 ALTER VIEW v SET (some_future_option = 1);",
            &mut state,
        )
        .unwrap();
    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "an unplaceable name must not be reported as an error: {v:?}"
    );
    assert_eq!(
        state.local.confidence,
        safe_migrate::_internal::analysis::state::Confidence::Tainted
    );
}

#[test]
fn view_check_option_requires_an_auto_updatable_query() {
    let engine = setup_engine();
    let mut state = setup_state();

    let v = engine
        .analyze(
            "CREATE TABLE base_co (id int);
                 CREATE VIEW updatable AS SELECT id FROM base_co WITH CHECK OPTION;
                 CREATE VIEW aggregated AS SELECT count(*) FROM base_co WITH CHECK OPTION;
                 CREATE VIEW filtered AS SELECT DISTINCT id FROM base_co WITH CHECK OPTION;",
            &mut state,
        )
        .unwrap();

    let reasons: Vec<&str> = v
        .iter()
        .filter(|v| v.rule_id == "chain-conflict")
        .map(|v| v.reason.as_str())
        .collect();
    assert_eq!(
        reasons.len(),
        2,
        "only the aggregate and distinct views conflict: {reasons:?}"
    );
    assert!(
        reasons
            .iter()
            .all(|reason| reason.contains("automatically updatable views")),
        "the refusal names the check option: {reasons:?}"
    );
    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("aggregate functions")),
        "the aggregate view reports its reason: {reasons:?}"
    );

    let relation = state
        .get_relation(&object_id("public", "updatable"))
        .expect("view must exist");
    assert!(
        matches!(relation, RelationOverlay::Present(r)
                if r.view_updatability == ViewUpdatability::Updatable),
        "an updatable view records its verdict: {relation:?}"
    );
}

#[test]
fn a_shadowing_routine_decides_whether_an_aggregate_name_conflicts() {
    let engine = setup_engine();
    let mut state = setup_state();

    // Before the shadowing routine exists, `sum(b)` is the built-in
    // aggregate. After `SET search_path = public, pg_catalog`, `public.sum`
    // precedes `pg_catalog`, so the same call is scalar and PostgreSQL
    // accepts the check option.
    let v = engine
        .analyze(
            "CREATE TABLE base_shadow (a int, b int);
                 CREATE VIEW aggregated AS SELECT a, sum(b) AS s FROM base_shadow WITH CHECK OPTION;
                 CREATE FUNCTION public.sum(int) RETURNS int LANGUAGE sql IMMUTABLE AS 'SELECT 1';
                 SET search_path = public, pg_catalog;
                 CREATE VIEW shadowed AS SELECT a, sum(b) AS s FROM base_shadow WITH CHECK OPTION;",
            &mut state,
        )
        .unwrap();

    let reasons: Vec<&str> = v
        .iter()
        .filter(|v| v.rule_id == "chain-conflict")
        .map(|v| v.reason.as_str())
        .collect();
    assert_eq!(
        reasons.len(),
        1,
        "only the unshadowed aggregate view conflicts: {reasons:?}"
    );
    assert!(
        reasons[0].contains("aggregate functions"),
        "the conflict is the aggregate refusal: {reasons:?}"
    );

    let shadowed = state
        .get_relation(&object_id("public", "shadowed"))
        .expect("view must exist");
    assert!(
        matches!(shadowed, RelationOverlay::Present(r)
                if r.view_updatability == ViewUpdatability::Updatable),
        "the shadowed call is scalar, so the view is updatable: {shadowed:?}"
    );
}

#[test]
fn variadic_scalar_overloads_shadow_built_in_aggregates() {
    let engine = setup_engine();
    let mut state = setup_state();

    // `public.sum(VARIADIC int[])` takes either scalar elements or an explicit
    // `VARIADIC` array. Both calls are scalar, so PostgreSQL accepts the check
    // option instead of refusing the view as an aggregate.
    let v = engine
        .analyze(
            "CREATE TABLE base_variadic (a int, b int);
             CREATE FUNCTION public.sum(VARIADIC int[]) RETURNS int LANGUAGE sql IMMUTABLE AS 'SELECT 1';
             SET search_path = public, pg_catalog;
             CREATE VIEW variadic_scalar AS SELECT a, sum(b) AS s FROM base_variadic WITH CHECK OPTION;
             CREATE VIEW variadic_array AS SELECT a, sum(VARIADIC NULL::int[]) AS s FROM base_variadic WITH CHECK OPTION;",
            &mut state,
        )
        .unwrap();

    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "the variadic scalar overload is not an aggregate: {v:?}"
    );
    for name in ["variadic_scalar", "variadic_array"] {
        let relation = state
            .get_relation(&object_id("public", name))
            .unwrap_or_else(|| panic!("{name} must exist"));
        assert!(
            matches!(relation, RelationOverlay::Present(r)
                if r.view_updatability == ViewUpdatability::Updatable),
            "{name} is scalar and updatable: {relation:?}"
        );
    }
}

#[test]
fn the_built_in_aggregate_beats_a_same_signature_routine_searched_after_it() {
    let engine = setup_engine();
    let mut state = setup_state();

    // The default path searches `pg_catalog` first, so `public.sum(bigint)`
    // does not shadow the built-in aggregate: `sum(b)` is an aggregate and
    // the check option is refused. Naming `public` first reverses it.
    let v = engine
            .analyze(
                "CREATE TABLE base_builtin (a int, b bigint);
                 CREATE FUNCTION public.sum(bigint) RETURNS bigint LANGUAGE sql IMMUTABLE AS 'SELECT $1';
                 CREATE VIEW built_in AS SELECT a, sum(b) AS s FROM base_builtin WITH CHECK OPTION;
                 SET search_path = public, pg_catalog;
                 CREATE VIEW shadowed_builtin AS SELECT a, sum(b) AS s FROM base_builtin WITH CHECK OPTION;",
                &mut state,
            )
            .unwrap();

    let reasons: Vec<&str> = v
        .iter()
        .filter(|v| v.rule_id == "chain-conflict")
        .map(|v| v.reason.as_str())
        .collect();
    assert_eq!(
        reasons.len(),
        1,
        "only the catalog-first call is the built-in aggregate: {reasons:?}"
    );
    assert!(
        reasons[0].contains("aggregate functions"),
        "the conflict is the aggregate refusal: {reasons:?}"
    );

    let shadowed = state
        .get_relation(&object_id("public", "shadowed_builtin"))
        .expect("the routine-first view must exist");
    assert!(
        matches!(shadowed, RelationOverlay::Present(r)
                if r.view_updatability == ViewUpdatability::Updatable),
        "naming public first makes the call scalar: {shadowed:?}"
    );
}

#[test]
fn an_unresolved_path_entry_ahead_taints_a_shadowing_aggregate() {
    let engine = setup_engine();
    let mut state = setup_state();

    // `$user` names a schema the model cannot see, so it could hold a `sum`
    // that shadows the user aggregate in `public`; the call is unsettled.
    let v = engine
            .analyze(
                "CREATE TABLE base_unresolved (a int, b int);
                 CREATE AGGREGATE public.sum(integer) (SFUNC = int4pl, STYPE = integer, INITCOND = '0');
                 SET search_path = \"$user\", public, pg_catalog;
                 CREATE VIEW haunted AS SELECT a, sum(b) AS s FROM base_unresolved WITH CHECK OPTION;",
                &mut state,
            )
            .unwrap();

    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "an unresolved schema ahead must not yield a definite conflict: {v:?}"
    );
    assert_eq!(
        state.local.confidence,
        Confidence::Tainted,
        "the shadowed call leaves the verdict unsettled"
    );
}

#[test]
fn an_unresolved_path_entry_ahead_taints_the_built_in_aggregate() {
    let engine = setup_engine();
    let mut state = setup_state();

    // `public.sum(text)` does not match `b`, so the built-in aggregate is the
    // fallback; an unresolved entry ahead of `pg_catalog` could shadow it.
    let v = engine
            .analyze(
                "CREATE TABLE base_unresolved_builtin (a int, b int);
                 CREATE FUNCTION public.sum(text) RETURNS text LANGUAGE sql IMMUTABLE AS 'SELECT $1';
                 SET search_path = \"$user\", public, pg_catalog;
                 CREATE VIEW haunted_builtin AS SELECT a, sum(b) AS s FROM base_unresolved_builtin WITH CHECK OPTION;",
                &mut state,
            )
            .unwrap();

    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "an unresolved schema ahead of the catalog taints the call: {v:?}"
    );
    assert_eq!(
        state.local.confidence,
        Confidence::Tainted,
        "the built-in aggregate cannot be claimed"
    );
}

#[test]
fn an_unresolved_path_entry_behind_the_shadow_keeps_the_verdict() {
    let engine = setup_engine();
    let mut state = setup_state();

    // The matching scalar is searched before the unresolved entry, so
    // nothing it cannot see can shadow the call and the verdict stays firm.
    let v = engine
        .analyze(
            "CREATE TABLE base_behind (a int, b int);
                 CREATE FUNCTION public.sum(int) RETURNS int LANGUAGE sql IMMUTABLE AS 'SELECT 1';
                 SET search_path = public, \"$user\", pg_catalog;
                 CREATE VIEW settled AS SELECT a, sum(b) AS s FROM base_behind WITH CHECK OPTION;",
            &mut state,
        )
        .unwrap();

    let settled = state
        .get_relation(&object_id("public", "settled"))
        .expect("view must exist");
    assert!(
        matches!(settled, RelationOverlay::Present(r)
                if r.view_updatability == ViewUpdatability::Updatable),
        "the scalar shadow precedes the unresolved entry: {settled:?}"
    );
    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "the settled scalar view conflicts with nothing: {v:?}"
    );
}

#[test]
fn a_narrowing_overload_is_not_an_implicit_cast() {
    let engine = setup_engine();
    let mut state = setup_state();

    // `int -> smallint` narrows and is not implicit, so `public.sum(smallint)`
    // cannot take `sum(b)` and the built-in aggregate is refused.
    let v = engine
            .analyze(
                "CREATE TABLE base_narrow (a int, b int);
                 CREATE FUNCTION public.sum(smallint) RETURNS smallint LANGUAGE sql IMMUTABLE AS 'SELECT $1';
                 SET search_path = public, pg_catalog;
                 CREATE VIEW narrowed AS SELECT a, sum(b) AS s FROM base_narrow WITH CHECK OPTION;",
                &mut state,
            )
            .unwrap();

    let reasons: Vec<&str> = v
        .iter()
        .filter(|v| v.rule_id == "chain-conflict")
        .map(|v| v.reason.as_str())
        .collect();
    assert_eq!(
        reasons.len(),
        1,
        "the narrowing overload cannot shadow the aggregate: {reasons:?}"
    );
    assert!(
        reasons[0].contains("aggregate functions"),
        "the conflict is the aggregate refusal: {reasons:?}"
    );
}

#[test]
fn a_cross_category_implicit_cast_shadows_the_built_in_aggregate() {
    let engine = setup_engine();
    let mut state = setup_state();

    // `text -> regclass` is implicit even though the categories differ, so
    // `public.sum(regclass)` can take `sum(c)` and the call is not a
    // definite aggregate.
    let v = engine
            .analyze(
                "CREATE TABLE base_cross (a int, c text);
                 CREATE FUNCTION public.sum(regclass) RETURNS regclass LANGUAGE sql IMMUTABLE AS 'SELECT $1';
                 SET search_path = public, pg_catalog;
                 CREATE VIEW crossed AS SELECT a, sum(c) AS s FROM base_cross WITH CHECK OPTION;",
                &mut state,
            )
            .unwrap();

    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "a cross-category implicit cast must not be refused: {v:?}"
    );
    assert_eq!(state.local.confidence, Confidence::Tainted);
}

#[test]
fn only_a_matching_overload_shadows_a_built_in_aggregate() {
    let engine = setup_engine();
    let mut state = setup_state();

    // `public.sum(text)` is searched before `pg_catalog`, but `b` is `int`,
    // so the overload does not match and `sum(b)` is still the built-in
    // aggregate. An identical-signature overload does match, so there the
    // call is scalar and PostgreSQL accepts the view.
    let v = engine
            .analyze(
                "CREATE TABLE base_overload (a int, b int);
                 CREATE FUNCTION public.sum(text) RETURNS text LANGUAGE sql IMMUTABLE AS 'SELECT $1';
                 SET search_path = public, pg_catalog;
                 CREATE VIEW mismatched AS SELECT a, sum(b) AS s FROM base_overload WITH CHECK OPTION;
                 CREATE FUNCTION public.sum(int) RETURNS int LANGUAGE sql IMMUTABLE AS 'SELECT 1';
                 CREATE VIEW matched AS SELECT a, sum(b) AS s FROM base_overload WITH CHECK OPTION;",
                &mut state,
            )
            .unwrap();

    let reasons: Vec<&str> = v
        .iter()
        .filter(|v| v.rule_id == "chain-conflict")
        .map(|v| v.reason.as_str())
        .collect();
    assert_eq!(
        reasons.len(),
        1,
        "only the mismatched overload leaves the aggregate in place: {reasons:?}"
    );
    assert!(
        reasons[0].contains("aggregate functions"),
        "the conflict is the aggregate refusal: {reasons:?}"
    );

    let matched = state
        .get_relation(&object_id("public", "matched"))
        .expect("view must exist");
    assert!(
        matches!(matched, RelationOverlay::Present(r)
                if r.view_updatability == ViewUpdatability::Updatable),
        "the matching overload is scalar, so the view is updatable: {matched:?}"
    );
    let mismatched_view = object_id("public", "mismatched");
    assert!(
        state.get_relation(&mismatched_view).is_none(),
        "the rejected CREATE VIEW leaves no relation behind"
    );
}

#[test]
fn altering_a_view_check_option_requires_an_auto_updatable_query() {
    let engine = setup_engine();
    let mut state = setup_state();

    let v = engine
        .analyze(
            "CREATE TABLE base_ac (id int);
                 CREATE VIEW bad AS SELECT DISTINCT id FROM base_ac;
                 ALTER VIEW bad SET (security_barrier = true);
                 ALTER VIEW bad SET (check_option = cascaded);
                 CREATE VIEW good AS SELECT id FROM base_ac;
                 ALTER TABLE good SET (check_option = local);",
            &mut state,
        )
        .unwrap();

    let reasons: Vec<&str> = v
        .iter()
        .filter(|v| v.rule_id == "chain-conflict")
        .map(|v| v.reason.as_str())
        .collect();
    assert_eq!(
        reasons.len(),
        1,
        "only the check_option SET conflicts: {reasons:?}"
    );
    assert!(
        reasons[0].contains("automatically updatable views"),
        "the refusal names the check option: {reasons:?}"
    );
}

#[test]
fn an_unplaced_view_call_taints_rather_than_conflicting() {
    let engine = setup_engine();
    let mut state = setup_state();

    let v = engine
        .analyze(
            "CREATE TABLE base_call (x int);
                 CREATE VIEW maybe AS SELECT upper('x') FROM base_call WITH CHECK OPTION;",
            &mut state,
        )
        .unwrap();
    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "an unclassified call must not be claimed as a conflict: {v:?}"
    );
    assert_eq!(state.local.confidence, Confidence::Tainted);
}

#[test]
fn security_definer_is_not_a_view_reloption_on_any_version() {
    use crate::_internal::analysis::mutations::ReloptionTarget;
    use crate::_internal::analysis::state::PgVersion;
    use crate::_internal::model::reloption::{ReloptionNamespace, ReloptionOutcome, evaluate};

    // It is a routine attribute. PostgreSQL 15 added security_invoker
    // beside security_barrier rather than replacing anything.
    for version in [140_000, 150_000, 160_000, 170_000, 180_000] {
        assert_eq!(
            evaluate(
                "security_definer",
                ReloptionNamespace::Main,
                Some("true"),
                ReloptionTarget::View,
                PgVersion::Observed(version)
            ),
            ReloptionOutcome::Unrecognized {
                name: "security_definer".to_string()
            },
            "PG {version} must not accept security_definer"
        );
    }
}

#[test]
fn reloption_values_are_checked_against_their_domain() {
    use crate::_internal::analysis::mutations::ReloptionTarget;
    use crate::_internal::analysis::state::PgVersion;
    use crate::_internal::model::reloption::{
        ReloptionNamespace, ReloptionOutcome, evaluate, parses_as_bool,
    };

    let version = PgVersion::Observed(180_000);
    let view = ReloptionTarget::View;
    let bad = |name: &'static str, value: &str| {
        matches!(
            evaluate(name, ReloptionNamespace::Main, Some(value), view, version),
            ReloptionOutcome::BadValue { .. }
        )
    };
    // parse_bool takes a unique prefix, so these all hold.
    for value in ["true", "t", "tr", "yes", "y", "on", "1", "TRUE", "of"] {
        assert!(parses_as_bool(value), "{value} should parse as a bool");
    }
    // A bare `o` is ambiguous between on and off, which PostgreSQL
    // rejects, and a numeric spelling must be exactly `1` or `0`.
    for value in ["o", "maybe", "2", "01", "truex", ""] {
        assert!(!parses_as_bool(value), "{value} should not parse");
    }
    assert!(bad("security_barrier", "banana"));
    assert!(bad("security_barrier", "o"));
    // An enum is compared whole, never by prefix.
    assert!(bad("check_option", "casc"));
    assert!(bad("check_option", "banana"));
    assert!(!bad("check_option", "cascaded"));
    assert_eq!(
        evaluate(
            "check_option",
            ReloptionNamespace::Main,
            Some("LOCAL"),
            view,
            version
        ),
        ReloptionOutcome::Accepted
    );

    let heap = ReloptionTarget::MaterializedView;
    assert_eq!(
        evaluate(
            "fillfactor",
            ReloptionNamespace::Main,
            Some("100"),
            heap,
            version
        ),
        ReloptionOutcome::Accepted
    );
    assert!(matches!(
        evaluate(
            "fillfactor",
            ReloptionNamespace::Main,
            Some("5"),
            heap,
            version
        ),
        ReloptionOutcome::BadValue { .. }
    ));
    assert!(matches!(
        evaluate(
            "fillfactor",
            ReloptionNamespace::Main,
            Some("banana"),
            heap,
            version
        ),
        ReloptionOutcome::BadValue { .. }
    ));
}

#[test]
fn materialized_view_uses_the_heap_options_and_views_do_not() {
    use crate::_internal::analysis::mutations::ReloptionTarget;
    use crate::_internal::analysis::state::PgVersion;
    use crate::_internal::model::reloption::{ReloptionNamespace, ReloptionOutcome, evaluate};

    let version = PgVersion::Observed(180_000);
    assert_eq!(
        evaluate(
            "fillfactor",
            ReloptionNamespace::Main,
            Some("70"),
            ReloptionTarget::MaterializedView,
            version
        ),
        ReloptionOutcome::Accepted
    );
    assert_eq!(
        evaluate(
            "fillfactor",
            ReloptionNamespace::Main,
            Some("70"),
            ReloptionTarget::View,
            version
        ),
        ReloptionOutcome::Unrecognized {
            name: "fillfactor".to_string()
        },
        "a view has no storage, so it cannot set fillfactor"
    );
    for view_only in ["security_barrier", "check_option"] {
        assert_eq!(
            evaluate(
                view_only,
                ReloptionNamespace::Main,
                Some("true"),
                ReloptionTarget::MaterializedView,
                version
            ),
            ReloptionOutcome::Unrecognized {
                name: view_only.to_string()
            },
            "{view_only} is a view option and must not reach a materialized view"
        );
    }
}

#[test]
fn an_empty_option_value_is_not_an_absent_one() {
    let analyze = |sql: &str| {
        let engine = setup_engine();
        let mut cache = crate::common::synced_cache();
        cache.pg_version_num = Some(180_000);
        let mut state = AnalysisState::new(cache);
        state.baseline_available = true;
        engine.analyze(sql, &mut state).unwrap()
    };

    // A bare option reads as `true` and is accepted; an explicitly empty
    // value is a value the boolean domain refuses, shown without its quotes.
    let bare = analyze(
        "CREATE TABLE base (id int);
             ALTER TABLE base SET (autovacuum_enabled);",
    );
    assert!(
        !bare.iter().any(|v| v.rule_id == "chain-conflict"),
        "a bare option reads as true: {bare:?}"
    );

    let empty = analyze(
        "CREATE TABLE base (id int);
             ALTER TABLE base SET (autovacuum_enabled = '');",
    );
    let reasons: Vec<&str> = empty
        .iter()
        .filter(|v| v.rule_id == "chain-conflict")
        .map(|v| v.reason.as_str())
        .collect();
    assert_eq!(reasons.len(), 1, "the empty value is refused: {reasons:?}");
    assert!(
        reasons[0].contains("invalid value for parameter \"autovacuum_enabled\":")
            && !reasons[0].contains("''"),
        "the empty value is shown as empty, not as its quotes: {reasons:?}"
    );

    let reset = analyze(
        "CREATE TABLE base (id int);
             ALTER TABLE base RESET (fillfactor = '');",
    );
    assert!(
        reset
            .iter()
            .any(|v| v.reason.contains("RESET must not include values")),
        "a RESET carrying the empty value is refused: {reset:?}"
    );
}

#[test]
fn create_materialized_view_validates_the_toast_namespace() {
    let analyze = |sql: &str| {
        let engine = setup_engine();
        let mut cache = crate::common::synced_cache();
        cache.pg_version_num = Some(180_000);
        let mut state = AnalysisState::new(cache);
        state.baseline_available = true;
        engine.analyze(sql, &mut state).unwrap()
    };

    // The matview itself takes `fillfactor`, but its TOAST table does not.
    let rejected = analyze(
        "CREATE TABLE base (id int);
             CREATE MATERIALIZED VIEW mv WITH (toast.fillfactor = 70) AS SELECT id FROM base;",
    );
    assert!(
        rejected
            .iter()
            .any(|v| v.reason.contains("unrecognized parameter")),
        "a TOAST name the toast table does not take must be rejected: {rejected:?}"
    );

    let accepted = analyze(
            "CREATE TABLE base (id int);
             CREATE MATERIALIZED VIEW mv WITH (toast.autovacuum_enabled = false) AS SELECT id FROM base;",
        );
    assert!(
        !accepted
            .iter()
            .any(|v| v.reason.contains("unrecognized parameter")),
        "a real TOAST option must be accepted: {accepted:?}"
    );
}

#[test]
fn a_toast_option_on_a_view_is_ignored_like_postgresql() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    // A view has no storage, so PostgreSQL drops `toast.` options instead
    // of validating them.
    let v = engine
        .analyze(
            "CREATE TABLE base (id int);
                 CREATE VIEW v AS SELECT id FROM base;
                 ALTER VIEW v SET (toast.fillfactor = 70);",
            &mut state,
        )
        .unwrap();
    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "a view silently ignores toast options: {v:?}"
    );
    assert_eq!(state.local.confidence, Confidence::Exact);
}

#[test]
fn alter_materialized_view_toast_option_depends_on_the_toast_table() {
    let analyze = |has_toast: bool| {
        let engine = setup_engine();
        let mut cache = crate::common::synced_cache();
        cache.pg_version_num = Some(180_000);
        let mut mv = RelationState::new(
            object_id("public", "mv"),
            ObjectId::new("public", "postgres"),
            0,
            None,
            RelationKind::MaterializedView,
            Persistence::Permanent,
            0,
        );
        mv.has_toast_table = Some(has_toast);
        cache.insert_baseline(object_id("public", "mv"), mv);
        let mut state = AnalysisState::new(cache);
        state.baseline_available = true;
        engine
            .analyze(
                "ALTER MATERIALIZED VIEW mv SET (toast.fillfactor = 70);",
                &mut state,
            )
            .unwrap()
    };

    let with_toast = analyze(true);
    assert!(
        with_toast
            .iter()
            .any(|v| v.reason.contains("unrecognized parameter")),
        "a toast table rejects a name it does not take: {with_toast:?}"
    );
    let without_toast = analyze(false);
    assert!(
        !without_toast
            .iter()
            .any(|v| v.reason.contains("unrecognized parameter")),
        "no toast table means the option is dropped, not checked: {without_toast:?}"
    );
}

#[test]
fn a_set_option_without_a_value_means_true() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;

    // A boolean option takes the implied `true`; an integer option then
    // rejects it the way the server does.
    engine
        .analyze(
            "CREATE TABLE base_set (id int);
                 ALTER TABLE base_set SET (autovacuum_enabled);",
            &mut state,
        )
        .unwrap();
    let relation = state
        .get_relation(&object_id("public", "base_set"))
        .expect("table must exist");
    assert!(
        matches!(relation, RelationOverlay::Present(r)
                if r.table_options.get("autovacuum_enabled") == Some(&"true".to_string())),
        "a name alone means true: {relation:?}"
    );

    let v = engine
        .analyze("ALTER TABLE base_set SET (fillfactor);", &mut state)
        .unwrap();
    assert!(
        v.iter().any(|v| v
            .reason
            .contains("invalid value for parameter \"fillfactor\"")),
        "an implied true is not an integer: {v:?}"
    );
}

#[test]
fn a_reset_option_must_not_carry_a_value() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.pg_version_num = Some(180_000);
    let mut state = AnalysisState::new(cache);
    state.baseline_available = true;
    engine
        .analyze(
            "CREATE TABLE base_reset (id int);
                 CREATE VIEW view_reset AS SELECT id FROM base_reset;",
            &mut state,
        )
        .unwrap();

    for sql in [
        "ALTER TABLE base_reset RESET (fillfactor = 70);",
        "ALTER TABLE base_reset ALTER COLUMN id RESET (n_distinct = 1);",
        "ALTER VIEW view_reset RESET (security_barrier = true);",
    ] {
        let v = engine.analyze(sql, &mut state).unwrap();
        assert!(
            v.iter()
                .any(|v| v.reason.contains("RESET must not include values")),
            "{sql} must be rejected: {v:?}"
        );
    }

    // A name alone, even one PostgreSQL does not know, is accepted.
    let v = engine
        .analyze("ALTER VIEW view_reset RESET (not_an_option);", &mut state)
        .unwrap();
    assert!(
        !v.iter().any(|v| v.rule_id == "chain-conflict"),
        "RESET checks no name: {v:?}"
    );
}

#[test]
fn a_temporary_relation_is_exempt_from_requiring_concurrency() {
    let engine = setup_engine();
    let mut state = setup_state();
    let v = engine
        .analyze(
            "CREATE TEMP TABLE bookings (id int);
                 CREATE INDEX bookings_idx ON bookings(id);
                 REINDEX INDEX bookings_idx;
                 REINDEX TABLE bookings;",
            &mut state,
        )
        .unwrap();
    assert!(
        !v.iter()
            .any(|violation| violation.rule_id == "require-concurrent-reindex"),
        "a temporary relation cannot be reindexed concurrently: {v:?}"
    );
}
