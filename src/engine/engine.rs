use crate::analysis::resolver::Resolver;
use crate::analysis::state::AnalysisState;
use crate::ast::visitor::AstVisitor;
use crate::db::cache::DbCache;
use crate::engine::MigrationFile;
use crate::report::reporter::Reporter;
use crate::rules::rules;

pub fn run(file: MigrationFile, db_cache: DbCache) -> Reporter {
    let mut state = AnalysisState::new(db_cache);
    let mut reporter = Reporter::new();

    for stmt in file.statements() {
        // 1. Extract syntax IR — pure AST, no semantics
        let Some(fact) = AstVisitor::extract(&stmt) else {
            continue;
        };

        // 2. Resolve semantics — QualifiedName → ObjectId, expand search_path
        // FIX: Resolver::resolve takes &state not &mut state
        let mutations = Resolver::resolve(&fact, &state);

        // 3. Rule evaluation — read-only, emits violations only
        for mutation in &mutations {
            for rule in rules() {
                rule.evaluate(mutation, &state, &mut reporter);
            }
        }

        // 4. Apply state changes — mutates LocalState, never emits violations
        for mutation in mutations {
            state.apply(mutation);
        }
    }

    // After all statements: finalize rules that check accumulated state.
    for rule in rules() {
        rule.finalize(&state, &mut reporter);
    }

    reporter
}

