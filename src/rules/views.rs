// src/rules/views.rs
use crate::analysis::mutations::Mutation;
use crate::analysis::state::AnalysisState;
use crate::report::Reporter;
use crate::rules::Rule;

pub struct OrphanedDependencyRule;

impl Rule for OrphanedDependencyRule {
    fn evaluate(&self, mutation: &Mutation, state: &AnalysisState, reporter: &mut Reporter) {
        if let Mutation::DropTable { id, .. } = mutation {
            
            // 1. Check for dependent Views
            let dependent_views = state.local.graph.is_referenced_by_view(id);
            for view_id in dependent_views {
                reporter.report(format!(
                    "FATAL: Cannot drop table '{}.{}'. The view '{}.{}' depends on it.",
                    id.schema, id.name, view_id.schema, view_id.name
                ));
            }

            // 2. Check for Foreign Key references
            let dependent_fks = state.local.graph.is_referenced_by_fk(id);
            for from_table in dependent_fks {
                reporter.report(format!(
                    "FATAL: Cannot drop table '{}.{}'. It is referenced by a foreign key on '{}.{}'.",
                    id.schema, id.name, from_table.schema, from_table.name
                ));
            }
        }
    }
}
