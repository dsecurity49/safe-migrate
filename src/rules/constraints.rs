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
            if let AlterTableActionMutation::AddColumn { name, ty, if_not_exists } = &alter.action {
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
