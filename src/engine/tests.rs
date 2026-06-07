#[cfg(test)]
mod tests {
    use crate::analysis::facts::StatementFact;
    use crate::analysis::resolver::Resolver;
    use crate::analysis::state::AnalysisState;
    use crate::ast::identifiers::{ObjectId, QualifiedName};
    use crate::db::cache::DbCache;
    use crate::model::relation::RelationOverlay; // FIX: correct import path
    use crate::report::reporter::Reporter;
    use crate::rules::destructive::DestructiveDropRule;
    use crate::rules::Rule;

    // ── Helper ────────────────────────────────────────────────────────

    fn fresh_state() -> AnalysisState {
        AnalysisState::new(DbCache::new())
    }

    fn object_id(schema: &str, name: &str) -> ObjectId {
        ObjectId::new(schema, name)
    }

    // ── Tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_destructive_drop_rule_tombstones() {
        let mut state = fresh_state();
        let mut reporter = Reporter::new();
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(DestructiveDropRule)];

        let fact = StatementFact::DropTable {
            name: QualifiedName::new(None, "users"),
            if_exists: false,
        };

        // FIX: Resolver::resolve takes &state not &mut state
        let mutations = Resolver::resolve(&fact, &state);

        for m in mutations {
            // FIX: clone before rule loop so we can apply after
            for rule in &rules {
                rule.evaluate(&m, &state, &mut reporter);
            }
            state.apply(m); // consumes m — no clone needed after loop
        }

        let id = object_id("public", "users");

        // Tombstone is active
        assert!(matches!(
            state.get_relation(&id),
            Some(RelationOverlay::Dropped)
        ));

        // Destructive drop was caught
        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("public.users"));
    }

    #[test]
    fn test_begin_rollback_restores_state() {
        let mut state = fresh_state();

        // Create a table
        let create_fact = StatementFact::CreateTable {
            name: QualifiedName::new(Some("public".to_string()), "orders"),
            if_not_exists: false,
        };
        for m in Resolver::resolve(&create_fact, &state) {
            state.apply(m);
        }

        // Begin transaction
        for m in Resolver::resolve(&StatementFact::BeginTransaction, &state) {
            state.apply(m);
        }

        // Drop the table inside the transaction
        let drop_fact = StatementFact::DropTable {
            name: QualifiedName::new(Some("public".to_string()), "orders"),
            if_exists: false,
        };
        for m in Resolver::resolve(&drop_fact, &state) {
            state.apply(m);
        }

        let id = object_id("public", "orders");

        // Table should be tombstoned inside the transaction
        assert!(matches!(
            state.get_relation(&id),
            Some(RelationOverlay::Dropped)
        ));

        // Rollback — should restore the table
        for m in Resolver::resolve(&StatementFact::RollbackTransaction, &state) {
            state.apply(m);
        }

        // Table should be Present again after rollback
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

        for m in Resolver::resolve(&fact, &state) {
            state.apply(m);
        }

        let id = object_id("public", "user_summary");

        // View should be present as a schema object
        assert!(state.relation_is_present(&id));

        // A ViewEdge should have been inserted into the graph
        assert!(state
            .local
            .graph
            .views
            .iter()
            .any(|v| v.view_id == id));
    }

    #[test]
    fn test_search_path_expands_unqualified_name() {
        let mut state = fresh_state();

        // Change search path to myschema
        let fact = StatementFact::SetSearchPath {
            schemas: vec!["myschema".to_string()],
        };
        for m in Resolver::resolve(&fact, &state) {
            state.apply(m);
        }

        // Create a table with no schema qualifier
        let create_fact = StatementFact::CreateTable {
            name: QualifiedName::new(None, "accounts"),
            if_not_exists: false,
        };
        for m in Resolver::resolve(&create_fact, &state) {
            state.apply(m);
        }

        // Should be in myschema, not public
        assert!(state.relation_is_present(&object_id("myschema", "accounts")));
        assert!(!state.relation_is_present(&object_id("public", "accounts")));
    }
}
