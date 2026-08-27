mod common;

mod invariant_sequences {
    use crate::common::{cache_with_table, object_id, setup_engine, setup_state};
    use safe_migrate::analysis::graph::DependencyKind;
    use safe_migrate::analysis::state::AnalysisState;
    use safe_migrate::analysis::transaction::TransactionFrameKind;
    use safe_migrate::db::cache::DbCache;
    use safe_migrate::model::function::FunctionOverlay;
    use safe_migrate::model::relation::RelationOverlay;
    use safe_migrate::model::replication::{PublicationOverlay, SubscriptionOverlay};
    use safe_migrate::model::role::RoleOverlay;
    use safe_migrate::model::schema::SchemaOverlay;
    use safe_migrate::model::sequence::SequenceOverlay;
    use safe_migrate::model::trigger::TriggerOverlay;
    use safe_migrate::model::types::TypeOverlay;
    use std::collections::HashSet;

    fn assert_cache_invariants(cache: &DbCache) {
        for (id, relation) in &cache.relations {
            assert_eq!(
                id, &relation.id,
                "cached relation map key disagrees with state"
            );
        }
        for (id, ty) in &cache.types {
            assert_eq!(id, &ty.id, "cached type map key disagrees with state");
        }
        for (id, function) in &cache.functions {
            assert_eq!(
                id, &function.id,
                "cached function map key disagrees with state"
            );
        }
        for (id, sequence) in &cache.sequences {
            assert_eq!(
                id, &sequence.id,
                "cached sequence map key disagrees with state"
            );
            if let Some((table_id, _)) = &sequence.owned_by {
                assert!(
                    cache.relations.contains_key(table_id),
                    "cached owned sequence must reference a cached relation"
                );
            }
        }
        for (id, role) in &cache.roles {
            assert_eq!(id, &role.id, "cached role map key disagrees with state");
        }
        for (name, schema) in &cache.schemas {
            assert_eq!(
                name, &schema.name,
                "cached schema map key disagrees with state"
            );
        }
        for (name, publication) in &cache.publications {
            assert_eq!(
                name, &publication.name,
                "cached publication map key disagrees with state"
            );
        }
        for (name, subscription) in &cache.subscriptions {
            assert_eq!(
                name, &subscription.name,
                "cached subscription map key disagrees with state"
            );
        }

        let mut constraint_keys = HashSet::new();
        for constraint in &cache.constraints {
            assert!(
                cache.relations.contains_key(&constraint.table_id),
                "cached constraint must reference a cached relation"
            );
            assert!(
                constraint_keys.insert((constraint.table_id.clone(), constraint.name.clone())),
                "cached constraints must have unique table/name identities"
            );
        }
        for index in &cache.indexes {
            assert!(
                cache.relations.contains_key(&index.table_id),
                "cached index must reference a cached relation"
            );
        }
        for trigger in &cache.triggers {
            assert!(
                cache.relations.contains_key(&trigger.table_id),
                "cached trigger must reference a cached relation"
            );
        }
        for foreign_key in &cache.foreign_keys {
            assert!(
                cache.relations.contains_key(&foreign_key.from_table)
                    && cache.relations.contains_key(&foreign_key.to_table),
                "cached foreign key must reference cached relations"
            );
        }
    }

    fn assert_state_invariants(state: &AnalysisState) {
        let local = &state.local;

        for (name, schema) in &local.schemas {
            if let SchemaOverlay::Present(schema) = schema {
                assert_eq!(name, &schema.name, "schema map key disagrees with state");
            }
        }
        for (id, relation) in &local.relations {
            if let RelationOverlay::Present(relation) = relation {
                assert_eq!(id, &relation.id, "relation map key disagrees with state");
            }
        }
        for (id, ty) in &local.types {
            if let TypeOverlay::Present(ty) = ty {
                assert_eq!(id, &ty.id, "type map key disagrees with state");
            }
        }
        for (id, function) in &local.functions {
            if let FunctionOverlay::Present(function) = function {
                assert_eq!(id, &function.id, "function map key disagrees with state");
            }
        }
        for (id, sequence) in &local.sequences {
            if let SequenceOverlay::Present(sequence) = sequence {
                assert_eq!(id, &sequence.id, "sequence map key disagrees with state");
            }
        }
        for (id, role) in &local.roles {
            if let RoleOverlay::Present(role) = role {
                assert_eq!(id, &role.id, "role map key disagrees with state");
            }
        }
        for (name, publication) in &local.publications {
            if let PublicationOverlay::Present(publication) = publication {
                assert_eq!(
                    name, &publication.name,
                    "publication map key disagrees with state"
                );
            }
        }
        for (name, subscription) in &local.subscriptions {
            if let SubscriptionOverlay::Present(subscription) = subscription {
                assert_eq!(
                    name, &subscription.name,
                    "subscription map key disagrees with state"
                );
            }
        }
        for (id, trigger) in &local.triggers {
            if let TriggerOverlay::Present(trigger) = trigger {
                assert_eq!(id, &trigger.id, "trigger map key disagrees with state");
                assert!(
                    !matches!(
                        local.relations.get(&trigger.table_id),
                        Some(RelationOverlay::Dropped)
                    ),
                    "present trigger belongs to a dropped relation"
                );
            }
        }
        for ((table_id, name), constraint) in &local.constraints {
            assert_eq!(
                table_id, &constraint.table_id,
                "constraint table key disagrees with state"
            );
            assert_eq!(
                name, &constraint.name,
                "constraint name key disagrees with state"
            );
            assert!(
                !matches!(
                    local.relations.get(table_id),
                    Some(RelationOverlay::Dropped)
                ),
                "constraint belongs to a dropped relation"
            );
        }
        for key in &local.pending_validation {
            let constraint = local
                .constraints
                .get(key)
                .expect("pending validation must reference a known constraint");
            assert!(
                !constraint.validated,
                "validated constraint cannot be pending"
            );
        }

        for edge in &local.graph.edges {
            match &edge.kind {
                DependencyKind::ForeignKey {
                    constraint_name: Some(name),
                    ..
                } => assert!(
                    local
                        .constraints
                        .contains_key(&(edge.dependent.clone(), name.clone())),
                    "foreign-key edge must have a matching constraint"
                ),
                DependencyKind::ViewDependency { .. } => {
                    assert!(matches!(
                        local.relations.get(&edge.dependent),
                        Some(RelationOverlay::Present(relation))
                            if matches!(
                                relation.kind,
                                safe_migrate::model::relation::RelationKind::View
                                    | safe_migrate::model::relation::RelationKind::MaterializedView
                            )
                    ));
                    assert!(!matches!(
                        local.relations.get(&edge.referenced),
                        Some(RelationOverlay::Dropped)
                    ));
                }
                DependencyKind::SequenceOwnedBy { column } => assert!(matches!(
                    local.sequences.get(&edge.dependent),
                    Some(SequenceOverlay::Present(sequence))
                        if sequence.owned_by == Some((edge.referenced.clone(), column.clone()))
                )),
                DependencyKind::TriggerOnTable { trigger_id, .. } => assert!(matches!(
                    local.triggers.get(trigger_id),
                    Some(TriggerOverlay::Present(trigger)) if trigger.table_id == edge.referenced
                )),
                DependencyKind::PublicationIncludes { publication_name } => assert!(matches!(
                    local.publications.get(publication_name),
                    Some(PublicationOverlay::Present(publication)) if publication.name == *publication_name
                )),
                DependencyKind::IndexOnRelation { .. }
                | DependencyKind::RenameTo
                | DependencyKind::PartitionOf
                | DependencyKind::ColumnGeneratedFrom { .. }
                | DependencyKind::ForeignKey {
                    constraint_name: None,
                    ..
                } => {}
            }
        }

        if local.transactions.is_empty() {
            assert!(
                !local.transaction_aborted,
                "an aborted transaction must retain its root frame"
            );
        } else {
            assert!(matches!(
                local.transactions.first().map(|frame| &frame.kind),
                Some(TransactionFrameKind::Root)
            ));
            assert!(
                local
                    .transactions
                    .iter()
                    .skip(1)
                    .all(|frame| matches!(frame.kind, TransactionFrameKind::Savepoint { .. })),
                "only the first transaction frame may be the root"
            );
        }
    }

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
}
