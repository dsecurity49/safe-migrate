use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::state::AnalysisState;
use crate::model::relation::RelationOverlay;
use crate::report::reporter::Reporter;
use crate::report::violations::{Severity, Violation};
use crate::rules::Rule;

// ─────────────────────────────────────────────
// SafeAddColumnRule
// ─────────────────────────────────────────────

pub struct SafeAddColumnRule;

impl Rule for SafeAddColumnRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if let Mutation::AlterTable(alter) = mutation {
            if let AlterTableActionMutation::AddColumn { name, ty, if_not_exists, .. } = &alter.action {
                match state.get_relation(&alter.id) {
                    None => {
                        reporter.report(Violation::new(
                            Severity::Error,
                            format!(
                                "ADD COLUMN '{}': table '{}' does not exist in the simulated schema.",
                                name, alter.id
                            ),
                        ));
                    }
                    Some(RelationOverlay::Dropped) => {
                        reporter.report(Violation::new(
                            Severity::Error,
                            format!(
                                "ADD COLUMN '{}': table '{}' has been dropped earlier in this migration.",
                                name, alter.id
                            ),
                        ));
                    }
                    Some(RelationOverlay::Present(rel)) => {
                        if rel.has_column(name) && !if_not_exists {
                            reporter.report(Violation::new(
                                Severity::Error,
                                format!(
                                    "ADD COLUMN '{}' on '{}': column already exists. \
                                     Use IF NOT EXISTS to make this idempotent.",
                                    name, alter.id
                                ),
                            ));
                        }
                        if ty.is_none() {
                            reporter.report(Violation::new(
                                Severity::Warning,
                                format!(
                                    "ADD COLUMN '{}' on '{}': could not extract column type from AST.",
                                    name, alter.id
                                ),
                            ));
                        }
                        if !rel.has_column(name) {
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

// ─────────────────────────────────────────────
// NotValidConstraintRule
//
// Fires when ADD CONSTRAINT ... NOT VALID is
// used without a subsequent VALIDATE CONSTRAINT.
//
// NOT VALID skips the full table scan at
// constraint creation time, deferring the check
// to VALIDATE CONSTRAINT. If VALIDATE is never
// called, the constraint is unenforced for
// existing rows — new rows are checked, but old
// rows are not.
//
// This rule fires at the ADD CONSTRAINT point.
// A companion rule (future) should fire if
// VALIDATE CONSTRAINT is missing entirely.
// ─────────────────────────────────────────────

pub struct NotValidConstraintRule;

impl Rule for NotValidConstraintRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        _state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if let Mutation::AlterTable(alter) = mutation {
            if let AlterTableActionMutation::AddForeignKey { to_table, not_valid, .. } = &alter.action {
                if *not_valid {
                    reporter.report(Violation::new(
                        Severity::Warning,
                        format!(
                            "ADD CONSTRAINT ... NOT VALID on '{}' referencing '{}': \
                             constraint will not be validated for existing rows. \
                             Follow this with VALIDATE CONSTRAINT to enforce it fully.",
                            alter.id, to_table
                        ),
                    ));
                }
            }
        }
    }
}

// ─────────────────────────────────────────────
// SetNotNullRule
//
// Fires when ALTER COLUMN ... SET NOT NULL is
// used on a table that already has rows (i.e.
// was created earlier in this migration or
// exists in DbCache).
//
// SET NOT NULL requires a full table scan to
// verify no existing rows have NULL in that
// column. On large tables this causes a long
// ACCESS EXCLUSIVE lock.
//
// The safe pattern is:
//   1. ADD CONSTRAINT ... CHECK (col IS NOT NULL) NOT VALID
//   2. VALIDATE CONSTRAINT ...
//   3. ALTER COLUMN ... SET NOT NULL  (uses the validated constraint, no scan)
//   4. DROP CONSTRAINT ...
//
// We can only detect the unsafe case — we emit
// a warning to prompt the author to consider
// the safe pattern.
// ─────────────────────────────────────────────

pub struct SetNotNullRule;

impl Rule for SetNotNullRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if let Mutation::AlterTable(alter) = mutation {
            if let AlterTableActionMutation::SetNotNull { column } = &alter.action {
                // Only warn when the table is known to exist — if it was
                // just created in this migration it likely has no rows yet.
                // We still warn because the migration may run against a
                // pre-existing table in production.
                match state.get_relation(&alter.id) {
                    Some(RelationOverlay::Present(rel)) => {
                        // If the column is already NOT NULL we can skip —
                        // the constraint is already enforced.
                        if let Some(col) = rel.get_column(column) {
                            if !col.is_nullable {
                                // Already NOT NULL — no scan needed, no warning.
                                return;
                            }
                        }
                        reporter.report(Violation::new(
                            Severity::Warning,
                            format!(
                                "ALTER COLUMN '{}' SET NOT NULL on '{}': requires a full table \
                                 scan with ACCESS EXCLUSIVE lock. On large tables, consider \
                                 using ADD CONSTRAINT ... CHECK (col IS NOT NULL) NOT VALID \
                                 followed by VALIDATE CONSTRAINT instead.",
                                column, alter.id
                            ),
                        ));
                    }
                    Some(RelationOverlay::Dropped) => {
                        reporter.report(Violation::new(
                            Severity::Error,
                            format!(
                                "ALTER COLUMN '{}' SET NOT NULL: table '{}' has been dropped \
                                 earlier in this migration.",
                                column, alter.id
                            ),
                        ));
                    }
                    None => {
                        reporter.report(Violation::new(
                            Severity::Error,
                            format!(
                                "ALTER COLUMN '{}' SET NOT NULL: table '{}' does not exist \
                                 in the simulated schema.",
                                column, alter.id
                            ),
                        ));
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────
// MissingValidateConstraintRule
//
// Fires at end-of-migration (via finalize()) if
// any NOT VALID constraints were added but never
// followed by VALIDATE CONSTRAINT.
//
// Pattern being detected:
//   ALTER TABLE t ADD CONSTRAINT fk FOREIGN KEY
//     REFERENCES other NOT VALID;
//   -- missing: ALTER TABLE t VALIDATE CONSTRAINT fk;
//
// The NOT VALID flag is intentional and useful
// for zero-downtime FK addition, but only if
// VALIDATE CONSTRAINT is run afterwards.
// Without it, existing rows silently bypass the
// constraint — only new/updated rows are checked.
//
// This rule does not fire per-mutation; it uses
// the Rule::finalize() hook to inspect the
// accumulated pending_validation state after all
// statements have been processed.
// ─────────────────────────────────────────────

pub struct MissingValidateConstraintRule;

impl Rule for MissingValidateConstraintRule {
    // No per-mutation evaluation needed.
    fn evaluate(
        &self,
        _mutation: &Mutation,
        _state: &AnalysisState,
        _reporter: &mut Reporter,
    ) {}

    /// Fires after all mutations are applied.
    /// Any entry remaining in pending_validation at this point
    /// means the author added a NOT VALID constraint but never
    /// validated it within this migration file.
    fn finalize(&self, state: &AnalysisState, reporter: &mut Reporter) {
        for (table_id, constraint_name) in &state.local.pending_validation {
            // Filter out synthetic FK placeholder names — they can't be
            // referenced by VALIDATE CONSTRAINT so we format the message
            // differently.
            if constraint_name.starts_with("__fk__") {
                let to_table = constraint_name.trim_start_matches("__fk__");
                reporter.report(Violation::new(
                    Severity::Warning,
                    format!(
                        "Table '{}' has an unnamed NOT VALID foreign key referencing '{}' \
                         that was never followed by VALIDATE CONSTRAINT in this migration. \
                         Existing rows will not be checked against this constraint.",
                        table_id, to_table
                    ),
                ));
            } else {
                reporter.report(Violation::new(
                    Severity::Warning,
                    format!(
                        "Constraint '{}' on table '{}' was added with NOT VALID but \
                         VALIDATE CONSTRAINT was never called in this migration. \
                         Existing rows will not be checked against this constraint.",
                        constraint_name, table_id
                    ),
                ));
            }
        }
    }
}
