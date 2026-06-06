// src/engine/tests.rs
#[cfg(test)]
mod tests {
    use crate::analysis::facts::StatementFact;
    use crate::analysis::resolver::Resolver;
    use crate::analysis::state::AnalysisState;
    use crate::ast::identifiers::QualifiedName;
    use crate::db::cache::DbCache;
    use crate::model::relation::ObjectId;
    use crate::report::reporter::Reporter;
    use crate::rules::destructive::DestructiveDropRule;
    use crate::rules::Rule;

    #[test]
    fn test_core_execution_loop() {
        let cache = DbCache::new();
        let mut state = AnalysisState::new(cache);
        let mut reporter = Reporter::new();
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(DestructiveDropRule)];

        // --- STEP 1: Execute `CREATE TABLE users` (Unqualified) ---
        let fact_create = StatementFact::CreateTable {
            name: QualifiedName::new(None, "users"),
        };
        
        let mutations = Resolver::resolve(&fact_create, &state);
        for m in mutations {
            for rule in &rules { rule.evaluate(&m, &state, &mut reporter); }
            state.apply(&m);
        }

        // Assertion 1: Identity is canonicalized via default search_path
        let canonical_id = ObjectId::new("public", "users");
        assert!(state.get_relation(&canonical_id).is_some());
        assert!(!reporter.has_errors()); // No violations yet

        // --- STEP 2: Execute `DROP TABLE public.users` (Qualified) ---
        let fact_drop = StatementFact::DropTable {
            name: QualifiedName::new(Some("public"), "users"),
            if_exists: false,
        };

        let mutations = Resolver::resolve(&fact_drop, &state);
        for m in mutations {
            for rule in &rules { rule.evaluate(&m, &state, &mut reporter); }
            state.apply(&m); // Applies Tombstone
        }

        // Assertion 2: The Tombstone Rule is active
        assert!(state.get_relation(&canonical_id).is_none());

        // Assertion 3: DestructiveDropRule successfully caught the DropTableMutation
        assert_eq!(reporter.violations.len(), 1);
        assert!(reporter.violations[0].message.contains("public.users"));
    }
}
