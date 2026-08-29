mod common;

mod invariant_sequences {
    use crate::common::invariants::{assert_cache_invariants, assert_state_invariants};
    use crate::common::{cache_with_table, object_id, setup_engine, setup_state};
    use safe_migrate::analysis::state::AnalysisState;
    use safe_migrate::model::relation::RelationOverlay;
    use safe_migrate::model::schema::SchemaOverlay;

    fn analyze_and_validate(state: &mut AnalysisState, sql: &str) {
        let findings = setup_engine()
            .analyze(sql, state)
            .expect("scenario statement should analyze");
        assert_state_invariants(state);
        if sql.contains("missing_column") {
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == "chain-conflict")
            );
        }
    }

    #[test]
    fn state_invariants_hold_across_ddl_conflict_and_savepoint_rollback() {
        let mut state = setup_state();

        analyze_and_validate(
            &mut state,
            "CREATE TABLE accounts (id bigint PRIMARY KEY, email text);",
        );
        analyze_and_validate(
            &mut state,
            "CREATE TABLE orders (id bigint PRIMARY KEY, account_id bigint);",
        );
        analyze_and_validate(
            &mut state,
            "ALTER TABLE orders ADD CONSTRAINT orders_account_fk FOREIGN KEY (account_id) REFERENCES accounts(id) NOT VALID;",
        );
        analyze_and_validate(&mut state, "BEGIN;");
        analyze_and_validate(&mut state, "ALTER TABLE accounts RENAME TO customers;");
        analyze_and_validate(&mut state, "SAVEPOINT before_failure;");
        analyze_and_validate(
            &mut state,
            "ALTER TABLE customers DROP COLUMN missing_column;",
        );
        analyze_and_validate(&mut state, "ROLLBACK TO SAVEPOINT before_failure;");
        analyze_and_validate(&mut state, "COMMIT;");

        assert!(state.relation_is_present(&object_id("public", "customers")));
        assert!(!state.relation_is_present(&object_id("public", "accounts")));
    }

    #[test]
    fn cache_hydration_preserves_baseline_identity_and_state_invariants() {
        let table_id = object_id("app", "cached_accounts");
        let cache = cache_with_table("app", "cached_accounts", Some(42));
        assert_cache_invariants(&cache);
        let state = AnalysisState::with_baseline(cache, true);

        assert_state_invariants(&state);
        assert!(state.baseline_available);
        assert!(state.baseline_relations.contains(&table_id));
        assert!(state.relation_is_present(&table_id));
        assert!(matches!(
            state.local.relations.get(&table_id),
            Some(RelationOverlay::Present(relation)) if relation.estimated_rows == Some(42)
        ));
        assert!(matches!(
            state.local.schemas.get("app"),
            Some(SchemaOverlay::Present(schema)) if schema.name == "app"
        ));
    }

    #[test]
    fn deterministic_generated_sequences_restore_every_modeled_family() {
        let mut state = setup_state();

        for sequence in 0..16 {
            let schema = format!("generated_{sequence}");
            for sql in [
                "BEGIN;".to_string(),
                format!("CREATE SCHEMA {schema};"),
                format!("CREATE TABLE {schema}.items (id bigint PRIMARY KEY, value text);"),
                format!("CREATE INDEX items_value_idx ON {schema}.items(value);"),
                format!("CREATE VIEW {schema}.item_ids AS SELECT id FROM {schema}.items;"),
                format!("CREATE TYPE {schema}.item_state AS ENUM ('new', 'ready');"),
                format!("CREATE SEQUENCE {schema}.item_counter;"),
                format!(
                    "CREATE FUNCTION {schema}.item_identity(value integer) RETURNS integer LANGUAGE SQL IMMUTABLE AS $$ SELECT value $$;"
                ),
                format!(
                    "CREATE FUNCTION {schema}.item_rank() RETURNS bigint AS 'window_row_number' LANGUAGE internal WINDOW;"
                ),
                format!(
                    "CREATE PROCEDURE {schema}.refresh_items() LANGUAGE SQL AS $$ SELECT 1 $$;"
                ),
                format!(
                    "CREATE AGGREGATE {schema}.sum_items(integer) (SFUNC = int4pl, STYPE = integer, INITCOND = '0');"
                ),
                "SAVEPOINT generated_checkpoint;".to_string(),
                format!("ALTER TABLE {schema}.items RENAME TO renamed_items;"),
                format!("DROP VIEW {schema}.item_ids;"),
                "ROLLBACK TO SAVEPOINT generated_checkpoint;".to_string(),
                "ROLLBACK;".to_string(),
            ] {
                analyze_and_validate(&mut state, &sql);
            }

            assert!(state.local.transactions.is_empty());
            assert!(!state.local.transaction_aborted);
            assert!(!state.local.schemas.contains_key(&schema));
            assert!(state.local.relations.keys().all(|id| id.schema != schema));
            assert!(state.local.types.keys().all(|id| id.schema != schema));
            assert!(state.local.sequences.keys().all(|id| id.schema != schema));
            assert!(state.local.functions.keys().all(|id| id.schema != schema));
            assert!(state.local.graph.edges().iter().all(|edge| {
                edge.dependent.schema != schema && edge.referenced.schema != schema
            }));
            assert_state_invariants(&state);
        }
    }

    #[test]
    fn guarded_absent_operations_are_idempotent_and_rejections_only_abort() {
        let mut state = AnalysisState::new(cache_with_table("public", "kept", Some(10)));
        let initial_generation = state.local.generation_counter;

        for _ in 0..8 {
            let findings = setup_engine()
                .analyze(
                    "DROP TABLE IF EXISTS absent_table; DROP TYPE IF EXISTS absent_type;",
                    &mut state,
                )
                .expect("guarded absent operations should analyze");
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.rule_id == "chain-conflict"),
                "guarded absence must not conflict: {findings:?}"
            );
            assert!(state.relation_is_present(&object_id("public", "kept")));
            assert_state_invariants(&state);
        }
        assert_eq!(state.local.generation_counter, initial_generation);

        let findings = setup_engine()
            .analyze(
                "BEGIN; DROP TABLE absent_table; DROP TABLE kept;",
                &mut state,
            )
            .expect("rejected transaction sequence should analyze");
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "missing unguarded object must conflict: {findings:?}"
        );
        assert!(state.local.transaction_aborted);
        assert!(state.relation_is_present(&object_id("public", "kept")));
        assert_state_invariants(&state);

        analyze_and_validate(&mut state, "ROLLBACK;");
        assert!(!state.local.transaction_aborted);
        assert!(state.relation_is_present(&object_id("public", "kept")));
    }

    #[test]
    fn inverse_rename_preserves_view_dependencies() {
        let mut state = setup_state();
        for sql in [
            "CREATE TABLE rename_source (id bigint);",
            "CREATE VIEW rename_view AS SELECT id FROM rename_source;",
        ] {
            analyze_and_validate(&mut state, sql);
        }

        let source = object_id("public", "rename_source");
        let view = object_id("public", "rename_view");
        assert!(
            state
                .local
                .graph
                .edges()
                .iter()
                .any(|edge| { edge.dependent == view && edge.referenced == source })
        );

        analyze_and_validate(
            &mut state,
            "ALTER TABLE rename_source RENAME TO renamed_source;",
        );
        analyze_and_validate(
            &mut state,
            "ALTER TABLE renamed_source RENAME TO rename_source;",
        );

        assert!(state.relation_is_present(&source));
        assert!(!state.relation_is_present(&object_id("public", "renamed_source")));
        assert!(
            state
                .local
                .graph
                .edges()
                .iter()
                .any(|edge| { edge.dependent == view && edge.referenced == source })
        );
        assert_state_invariants(&state);
    }

    #[test]
    fn structured_cross_family_rollback_is_exact_and_reports_are_repeatable() {
        let statements = [
            "BEGIN;",
            "CREATE SCHEMA phase5;",
            "SET LOCAL search_path TO phase5, public;",
            "SET LOCAL lock_timeout = '750ms';",
            "SET LOCAL statement_timeout = '3s';",
            "CREATE ROLE phase5_owner;",
            "SET LOCAL SESSION AUTHORIZATION phase5_owner;",
            "CREATE TABLE phase5.parent (id integer) PARTITION BY RANGE (id);",
            "CREATE TABLE phase5.child (id integer);",
            "ALTER TABLE phase5.parent ATTACH PARTITION phase5.child FOR VALUES FROM (0) TO (10);",
            "ALTER TABLE phase5.parent DETACH PARTITION phase5.child;",
            "CREATE FUNCTION phase5.identity(value integer) RETURNS integer LANGUAGE SQL IMMUTABLE AS $$ SELECT value $$;",
            "CREATE FUNCTION phase5.identity(value text) RETURNS text LANGUAGE SQL IMMUTABLE AS $$ SELECT value $$;",
            "CREATE PUBLICATION phase5_changes FOR TABLE phase5.parent;",
            "CREATE SUBSCRIPTION phase5_sub CONNECTION 'host=publisher.invalid' PUBLICATION phase5_changes WITH (connect=false);",
            "SAVEPOINT phase5_checkpoint;",
            "ALTER PUBLICATION phase5_changes RENAME TO phase5_renamed_changes;",
            "ALTER SUBSCRIPTION phase5_sub RENAME TO phase5_renamed_sub;",
            "ROLLBACK TO SAVEPOINT phase5_checkpoint;",
            "ROLLBACK;",
        ];

        let run = || {
            let mut state = setup_state();
            let mut reports = Vec::new();
            for sql in statements {
                let findings = setup_engine()
                    .analyze(sql, &mut state)
                    .expect("structure-aware statement should analyze");
                assert_state_invariants(&state);
                reports.push(
                    serde_json::to_string(&safe_migrate::Reporter::json_report(
                        &findings,
                        &state.local.confidence,
                    ))
                    .expect("report should serialize"),
                );
            }

            assert!(state.local.transactions.is_empty());
            assert!(!state.local.transaction_aborted);
            assert_eq!(state.local.search_path, ["public"]);
            assert!(!state.local.schemas.contains_key("phase5"));
            assert!(state.local.relations.keys().all(|id| id.schema != "phase5"));
            assert!(state.local.functions.keys().all(|id| id.schema != "phase5"));
            assert!(!state.local.publications.contains_key("phase5_changes"));
            assert!(!state.local.subscriptions.contains_key("phase5_sub"));
            assert!(
                !state
                    .local
                    .roles
                    .contains_key(&object_id("", "phase5_owner"))
            );
            assert!(state.local.graph.edges().iter().all(|edge| {
                edge.dependent.schema != "phase5" && edge.referenced.schema != "phase5"
            }));
            assert_state_invariants(&state);
            reports
        };

        assert_eq!(
            run(),
            run(),
            "repeated analysis must produce identical reports"
        );
    }
}
