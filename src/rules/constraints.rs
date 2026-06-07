use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::state::AnalysisState;
use crate::model::relation::RelationOverlay;
use crate::report::reporter::Reporter;
use crate::report::violations::{Severity, Violation};
use crate::rules::Rule;

/// Validates ADD COLUMN safety:
///
/// 1. The target table must exist and not be tombstoned.
/// 2. If the column is added without IF NOT EXISTS and the table
///    is known to already have that column, emit an error.
/// 3. If the column has no type recorded, emit a warning — this
///    may indicate an AST extraction gap.
/// 4. Remind the author to ensure the column is nullable or has
///    a default to avoid a full table rewrite on large tables.
pub struct SafeAddColumnRule;

impl Rule for SafeAddColumnRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        // FIX B1: AlterTable is a tuple variant — Mutation::AlterTable(AlterTable { .. })
        // Old code used struct-variant syntax { id, action } which does not compile.
        if let Mutation::AlterTable(alter) = mutation {
            if let AlterTableActionMutation::AddColumn { name, ty, if_not_exists } = &alter.action {

                match state.get_relation(&alter.id) {
                    // Table does not exist at all in local state or cache.
                    None => {
                        reporter.report(Violation::new(
                            Severity::Error,
                            format!(
                                "ADD COLUMN '{}': table '{}' does not exist in the simulated schema.",
                                name, alter.id
                            ),
                        ));
                    }

                    // Table was previously dropped — tombstone is active.
                    Some(RelationOverlay::Dropped) => {
                        reporter.report(Violation::new(
                            Severity::Error,
                            format!(
                                "ADD COLUMN '{}': table '{}' has been dropped earlier in this migration.",
                                name, alter.id
                            ),
                        ));
                    }

                    // Table exists — check column-level safety.
                    Some(RelationOverlay::Present(rel_state)) => {
                        // Duplicate column without IF NOT EXISTS guard.
                        if rel_state.has_column(name) && !if_not_exists {
                            reporter.report(Violation::new(
                                Severity::Error,
                                format!(
                                    "ADD COLUMN '{}' on '{}': column already exists. \
                                     Use IF NOT EXISTS to make this idempotent.",
                                    name, alter.id
                                ),
                            ));
                        }

                        // No type information extracted — likely an AST gap.
                        if ty.is_none() {
                            reporter.report(Violation::new(
                                Severity::Warning,
                                format!(
                                    "ADD COLUMN '{}' on '{}': could not extract column type from AST.",
                                    name, alter.id
                                ),
                            ));
                        }

                        // Remind author about nullable / default requirement.
                        // Only fires when the column is genuinely being added
                        // (not a duplicate caught above).
                        if !rel_state.has_column(name) {
                            reporter.report(Violation::new(
                                Severity::Warning,
                                format!(
                                    "ADD COLUMN '{}' on '{}': ensure the column is nullable \
                                     or has a non-volatile default to avoid a full table rewrite.",
                                    name, alter.id
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }
}

