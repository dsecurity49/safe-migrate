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
        if let Mutation::DropTable(drop) = mutation {
            // FIX Bug 2: filter tombstoned views.
            // A view that was explicitly dropped earlier in this migration
            // has RelationOverlay::Dropped. Its graph edge is stale — it
            // must not block dropping the base table.
            for view_id in state.local.graph.is_referenced_by_view(&drop.id) {
                if !state.relation_is_present(view_id) {
                    continue; // view already dropped — edge is stale
                }
                reporter.report(Violation::new(
                    Severity::Error,
                    format!(
                        "Cannot drop table '{}': view '{}' depends on it.",
                        drop.id, view_id
                    ),
                ));
            }

            // Filter edges by generation — prevents ABA phantom FK dependencies.
            // An edge is stale if from_table's current generation doesn't match
            // the generation stamped on the edge when it was created.
            for (from_table, edge_generation) in state.local.graph.is_referenced_by_fk(&drop.id) {
                if !state.relation_is_present(from_table) {
                    continue; // tombstoned — already dropped
                }
                // ABA check: if the table was recreated, its generation changed.
                let current_generation = state.local.relations.get(from_table)
                    .and_then(|o| if let crate::model::relation::RelationOverlay::Present(r) = o {
                        Some(r.generation)
                    } else { None })
                    .unwrap_or(0);
                if current_generation != edge_generation {
                    continue; // edge belongs to a previous incarnation of this table
                }
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
