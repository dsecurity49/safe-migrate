use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::state::AnalysisState;
use crate::model::relation::RelationOverlay;
use crate::report::reporter::Reporter;
use crate::report::violations::{Severity, Violation};
use crate::rules::Rule;

// ─────────────────────────────────────────────
// SafeAddColumnRule
//
// Bug 15 fix: the previous implementation fired a blanket
//   "ensure the column is nullable or has a non-volatile default"
// warning for every ADD COLUMN on a known table. This made the
// rule fire on every valid migration, creating noise that would
// cause authors to ignore all warnings.
//
// Responsibility split after fix:
//   - SafeAddColumnRule: structural errors only
//       * table unknown / tombstoned
//       * column already exists without IF NOT EXISTS
//       * column type unextractable from AST
//   - VolatileDefaultRule: volatile default detection
//   - (future) NotNullWithoutDefaultRule: NOT NULL add without default
//
// The removed catch-all warning was: "ensure the column is nullable
// or has a non-volatile default to avoid a full table rewrite."
// This is now covered more precisely by VolatileDefaultRule.
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
                        // Error: column already exists and author omitted IF NOT EXISTS.
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

                        // Warning: type could not be extracted — likely an AST gap.
                        // This fires regardless of whether the column is new or existing,
                        // since a missing type is always a sign something went wrong.
                        if ty.is_none() {
                            reporter.report(Violation::new(
                                Severity::Warning,
                                format!(
                                    "ADD COLUMN '{}' on '{}': could not extract column type from AST.",
                                    name, alter.id
                                ),
                            ));
                        }

                        // Volatile-default safety is intentionally NOT checked here.
                        // VolatileDefaultRule owns that concern — it evaluates the
                        // extracted ExprIr and fires only when the default is actually
                        // volatile. The old catch-all warning fired for every valid
                        // ADD COLUMN regardless of whether there was any default at all.
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────
// NotValidConstraintRule
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
                match state.get_relation(&alter.id) {
                    Some(RelationOverlay::Present(rel)) => {
                        if let Some(col) = rel.get_column(column) {
                            if !col.is_nullable {
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
// ─────────────────────────────────────────────

pub struct MissingValidateConstraintRule;

impl Rule for MissingValidateConstraintRule {
    fn evaluate(
        &self,
        _mutation: &Mutation,
        _state: &AnalysisState,
        _reporter: &mut Reporter,
    ) {}

    fn finalize(&self, state: &AnalysisState, reporter: &mut Reporter) {
        for (table_id, constraint_name) in &state.local.pending_validation {
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

// ─────────────────────────────────────────────
// AddCheckConstraintRule
// ─────────────────────────────────────────────

pub struct AddCheckConstraintRule;

impl Rule for AddCheckConstraintRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        _state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if let Mutation::AlterTable(alter) = mutation {
            if let AlterTableActionMutation::AddCheckConstraint { not_valid } = &alter.action {
                if !not_valid {
                    reporter.report(Violation::new(
                        Severity::Warning,
                        format!(
                            "ADD CONSTRAINT CHECK on '{}' without NOT VALID will scan the \
                             entire table holding a ShareLock, blocking writes for the duration. \
                             Use ADD CONSTRAINT ... CHECK (...) NOT VALID followed by \
                             VALIDATE CONSTRAINT for a shorter lock window.",
                            alter.id
                        ),
                    ));
                }
            }
        }
    }
}

// ─────────────────────────────────────────────
// AddUniqueConstraintRule
// ─────────────────────────────────────────────

pub struct AddUniqueConstraintRule;

impl Rule for AddUniqueConstraintRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        _state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if let Mutation::AlterTable(alter) = mutation {
            match &alter.action {
                AlterTableActionMutation::AddUniqueConstraint => {
                    reporter.report(Violation::new(
                        Severity::Warning,
                        format!(
                            "ADD CONSTRAINT UNIQUE on '{}' takes ACCESS EXCLUSIVE lock and \
                             builds an index, blocking all reads and writes. Safe pattern: \
                             CREATE UNIQUE INDEX CONCURRENTLY first, then \
                             ADD CONSTRAINT ... UNIQUE USING INDEX.",
                            alter.id
                        ),
                    ));
                }
                AlterTableActionMutation::AddPrimaryKeyConstraint => {
                    reporter.report(Violation::new(
                        Severity::Warning,
                        format!(
                            "ADD CONSTRAINT PRIMARY KEY on '{}' takes ACCESS EXCLUSIVE lock \
                             and builds an index, blocking all reads and writes. If a unique \
                             index already exists on the PK columns, use \
                             ADD CONSTRAINT ... PRIMARY KEY USING INDEX to avoid the rebuild.",
                            alter.id
                        ),
                    ));
                }
                _ => {}
            }
        }
    }
}
