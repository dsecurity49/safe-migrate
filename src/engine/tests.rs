#[cfg(test)]
mod tests {
    use crate::analysis::facts::{ColumnFact, FkFact, StatementFact};
    use crate::analysis::mutations::Mutation;
    use crate::analysis::resolver::Resolver;
    use crate::analysis::state::AnalysisState;
    use crate::ast::identifiers::{ObjectId, QualifiedName};
    use crate::db::cache::DbCache;
    use crate::model::relation::RelationOverlay;
    use crate::report::reporter::Reporter;
    use crate::rules::destructive::DestructiveDropRule;
    use crate::rules::indexes::ConcurrentIndexRule;
    use crate::rules::Rule;

    // ── Helpers ───────────────────────────────────────────────────────

    fn fresh_state() -> AnalysisState {
        AnalysisState::new(DbCache::new())
    }

    fn object_id(schema: &str, name: &str) -> ObjectId {
        ObjectId::new(schema, name)
    }

    /// Apply a single fact through resolve + apply with no rule evaluation.
    fn apply_fact(state: &mut AnalysisState, fact: &StatementFact) {
        for m in Resolver::resolve(fact, state) {
            state.apply(m);
        }
    }

    /// Build a minimal CreateTable fact with no columns or FKs.
    fn create_table_fact(schema: Option<&str>, name: &str) -> StatementFact {
        StatementFact::CreateTable {
            name: QualifiedName::new(schema.map(|s| s.to_string()), name),
            if_not_exists: false,
            columns: Vec::new(),
            foreign_keys: Vec::new(),
        }
    }

    // ── Phase 1 regression tests ──────────────────────────────────────

    #[test]
    fn test_destructive_drop_rule_tombstones() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(DestructiveDropRule)];

        let fact = StatementFact::DropTable {
            name: QualifiedName::new(None, "users"),
            if_exists: false,
        };

        let mutations = Resolver::resolve(&fact, &state);
        for m in mutations {
            for rule in &rules {
                rule.evaluate(&m, &state, &mut reporter);
            }
            state.apply(m);
        }

        let id = object_id("public", "users");

        assert!(matches!(
            state.get_relation(&id),
            Some(RelationOverlay::Dropped)
        ));

        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("public.users"));
    }

    #[test]
    fn test_begin_rollback_restores_state() {
        let mut state = fresh_state();

        apply_fact(&mut state, &create_table_fact(Some("public"), "orders"));
        apply_fact(&mut state, &StatementFact::BeginTransaction);

        let drop_fact = StatementFact::DropTable {
            name: QualifiedName::new(Some("public".to_string()), "orders"),
            if_exists: false,
        };
        apply_fact(&mut state, &drop_fact);

        let id = object_id("public", "orders");
        assert!(matches!(
            state.get_relation(&id),
            Some(RelationOverlay::Dropped)
        ));

        apply_fact(&mut state, &StatementFact::RollbackTransaction);

        assert!(matches!(
            state.get_relation(&id),
            Some(RelationOverlay::Present(_))
        ));
    }

    #[test]
    fn test_create_view_inserts_view_edge() {
        let mut state = fresh_state();

        let fact = StatementFact::CreateView {
            name: QualifiedName::new(None, "user_summary"),
            or_replace: false,
        };
        apply_fact(&mut state, &fact);

        let id = object_id("public", "user_summary");
        assert!(state.relation_is_present(&id));
        assert!(state.local.graph.views.iter().any(|v| v.view_id == id));
    }

    #[test]
    fn test_search_path_expands_unqualified_name() {
        let mut state = fresh_state();

        apply_fact(&mut state, &StatementFact::SetSearchPath {
            schemas: vec!["myschema".to_string()],
        });
        apply_fact(&mut state, &create_table_fact(None, "accounts"));

        assert!(state.relation_is_present(&object_id("myschema", "accounts")));
        assert!(!state.relation_is_present(&object_id("public", "accounts")));
    }

    // ── Phase 2 new tests ─────────────────────────────────────────────

    #[test]
    fn test_create_table_populates_columns() {
        let mut state = fresh_state();

        let fact = StatementFact::CreateTable {
            name: QualifiedName::new(None, "products"),
            if_not_exists: false,
            columns: vec![
                ColumnFact {
                    name: "id".to_string(),
                    ty: Some("integer".to_string()),
                    not_null: true,
                    is_primary_key: true,
                },
                ColumnFact {
                    name: "name".to_string(),
                    ty: Some("text".to_string()),
                    not_null: false,
                    is_primary_key: false,
                },
            ],
            foreign_keys: Vec::new(),
        };
        apply_fact(&mut state, &fact);

        let id = object_id("public", "products");
        if let Some(RelationOverlay::Present(rel)) = state.get_relation(&id) {
            assert!(rel.has_column("id"),   "id column should exist");
            assert!(rel.has_column("name"), "name column should exist");
            assert!(!rel.has_column("price"), "price column should not exist");
        } else {
            panic!("products table should be Present");
        }
    }

    #[test]
    fn test_create_table_inserts_fk_edge() {
        let mut state = fresh_state();

        // Create both tables so the graph is coherent.
        apply_fact(&mut state, &create_table_fact(None, "users"));

        let fact = StatementFact::CreateTable {
            name: QualifiedName::new(None, "orders"),
            if_not_exists: false,
            columns: Vec::new(),
            foreign_keys: vec![FkFact {
                references: QualifiedName::new(None, "users"),
            }],
        };
        apply_fact(&mut state, &fact);

        // An FkEdge from orders → users should be in the graph.
        let orders_id = object_id("public", "orders");
        let users_id  = object_id("public", "users");
        let has_edge = state.local.graph.foreign_keys.iter().any(|fk| {
            fk.from_table == orders_id && fk.to_table == users_id
        });
        assert!(has_edge, "FkEdge orders → users should be present");
    }

    #[test]
    fn test_orphaned_fk_rule_fires_on_drop() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        // Create users table, then orders with FK to users.
        apply_fact(&mut state, &create_table_fact(None, "users"));

        let orders_fact = StatementFact::CreateTable {
            name: QualifiedName::new(None, "orders"),
            if_not_exists: false,
            columns: Vec::new(),
            foreign_keys: vec![FkFact {
                references: QualifiedName::new(None, "users"),
            }],
        };
        apply_fact(&mut state, &orders_fact);

        // Now drop users — should fire OrphanedDependencyRule.
        let drop_fact = StatementFact::DropTable {
            name: QualifiedName::new(None, "users"),
            if_exists: false,
        };
        let mutations = Resolver::resolve(&drop_fact, &state);
        let all_rules = crate::rules::rules();
        for m in &mutations {
            for rule in &all_rules {
                rule.evaluate(m, &state, &mut reporter);
            }
        }

        let fk_violation = reporter.violations.iter().any(|v| {
            v.message.contains("foreign key")
        });
        assert!(fk_violation, "should report FK dependency on users");
    }

    #[test]
    fn test_concurrent_index_rule_fires_without_concurrently() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        // Table must exist for context, but the rule only inspects the mutation.
        apply_fact(&mut state, &create_table_fact(None, "events"));

        let fact = StatementFact::CreateIndex {
            name: QualifiedName::new(None, "idx_events_created_at"),
            relation: QualifiedName::new(None, "events"),
            if_not_exists: false,
            concurrently: false, // ← missing CONCURRENTLY
        };

        let mutations = Resolver::resolve(&fact, &state);
        let rule = ConcurrentIndexRule;
        for m in &mutations {
            rule.evaluate(m, &state, &mut reporter);
        }

        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("ACCESS EXCLUSIVE"));
    }

    #[test]
    fn test_concurrent_index_inside_transaction_warns() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "events"));
        apply_fact(&mut state, &StatementFact::BeginTransaction);

        let fact = StatementFact::CreateIndex {
            name: QualifiedName::new(None, "idx_events_type"),
            relation: QualifiedName::new(None, "events"),
            if_not_exists: false,
            concurrently: true, // CONCURRENTLY inside transaction — will be ignored by PG
        };

        let mutations = Resolver::resolve(&fact, &state);
        let rule = ConcurrentIndexRule;
        for m in &mutations {
            rule.evaluate(m, &state, &mut reporter);
        }

        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("transaction block"));
    }

    #[test]
    fn test_concurrent_index_correct_usage_no_violation() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();

        apply_fact(&mut state, &create_table_fact(None, "events"));

        let fact = StatementFact::CreateIndex {
            name: QualifiedName::new(None, "idx_events_user_id"),
            relation: QualifiedName::new(None, "events"),
            if_not_exists: false,
            concurrently: true, // correct — outside transaction
        };

        let mutations = Resolver::resolve(&fact, &state);
        let rule = ConcurrentIndexRule;
        for m in &mutations {
            rule.evaluate(m, &state, &mut reporter);
        }

        assert!(
            reporter.violations.is_empty(),
            "correct CONCURRENTLY usage should not produce violations"
        );
    }
}
