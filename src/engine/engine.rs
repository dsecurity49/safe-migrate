// src/engine/engine.rs
use crate::ast::visitor::AstVisitor;
use squawk_syntax::ast::Stmt; 
use crate::analysis::resolver::Resolver;
use crate::analysis::state::AnalysisState;
use crate::db::cache::DbCache;
use crate::report::reporter::Reporter;
use crate::rules::Rule;
use crate::rules::destructive::DestructiveDropRule;

pub struct SafeMigrateEngine {
    rules: Vec<Box<dyn Rule>>,
}

impl SafeMigrateEngine {
    pub fn new() -> Self {
        Self {
            rules: vec![
                Box::new(DestructiveDropRule),
                // Register future rules here
            ],
        }
    }

    /// The CORE ENGINE FINAL LOOP (From Blueprint Section 4)
    pub fn run(&self, statements: Vec<Stmt>, db_cache: DbCache) -> Reporter {
        let mut state = AnalysisState::new(db_cache);
        let mut reporter = Reporter::new();

        // Sequential execution only (Rule 2.4)
        for stmt in statements {
            // 1. Extract syntax IR
            if let Some(fact) = AstVisitor::extract(&stmt) {
                
                // 2. Resolve semantics
                let mutations = Resolver::resolve(&fact, &state);

                for mutation in mutations {
                    // 3. Rule evaluation (read-only state)
                    for rule in &self.rules {
                        rule.evaluate(&mutation, &state, &mut reporter);
                    }

                    // 4. Apply state changes (mutates local state)
                    state.apply(&mutation);
                }
            }
        }

        reporter
    }
}
