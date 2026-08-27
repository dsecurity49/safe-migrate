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
            assert!(state.local.graph.edges.iter().all(|edge| {
                edge.dependent.schema != schema && edge.referenced.schema != schema
            }));
            assert_state_invariants(&state);
        }
    }
}
