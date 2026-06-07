use crate::analysis::mutations::Mutation;
use crate::analysis::state::AnalysisState;
use crate::report::reporter::Reporter;
use crate::report::violations::{Severity, Violation};
use crate::rules::Rule;

/// Fires when a DROP TABLE would orphan a view, break a foreign key,
/// or invalidate an index that depends on the dropped table.
pub struct OrphanedDependencyRule;

impl Rule for OrphanedDependencyRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        // FIX: tuple variant — Mutation::DropTable(drop), not { id, .. }
        if let Mutation::DropTable(drop) = mutation {
            for view_id in state.local.graph.is_referenced_by_view(&drop.id) {
                reporter.report(Violation::new(
                    Severity::Error,
                    format!(
                        "Cannot drop table '{}': view '{}' depends on it.",
                        drop.id, view_id
                    ),
                ));
            }

            for from_table in state.local.graph.is_referenced_by_fk(&drop.id) {
                reporter.report(Violation::new(
                    Severity::Error,
                    format!(
                        "Cannot drop table '{}': referenced by a foreign key on table '{}'.",
                        drop.id, from_table
                    ),
                ));
            }

            for index_id in state.local.graph.is_referenced_by_index(&drop.id) {
                reporter.report(Violation::new(
                    Severity::Warning,
                    format!(
                        "Dropping table '{}' will also invalidate index '{}'.",
                        drop.id, index_id
                    ),
                ));
            }
        }
    }
}
