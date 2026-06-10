use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::state::AnalysisState;
use crate::report::reporter::Reporter;
use crate::report::violations::{Severity, Violation};
use crate::rules::Rule;

// ─────────────────────────────────────────────
// Idempotency rules
//
// Migrations should be safely re-runnable.
// Missing IF NOT EXISTS / IF EXISTS guards cause
// runtime errors when a migration is re-applied
// (e.g. after a partial failure and retry, or in
// a CI environment that applies migrations from
// scratch repeatedly).
//
// These rules fire when the guard flag is absent.
// They are Warnings not Errors because omitting
// the guard is sometimes intentional — the author
// may want an error if the object already exists.
// ─────────────────────────────────────────────

// ── CREATE TABLE without IF NOT EXISTS ───────

pub struct CreateTableIdempotencyRule;

impl Rule for CreateTableIdempotencyRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        _state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if let Mutation::CreateTable(create) = mutation {
            if !create.if_not_exists {
                reporter.report(Violation::new(
                    Severity::Warning,
                    format!(
                        "CREATE TABLE '{}' without IF NOT EXISTS. \
                         Re-running this migration will fail if the table already exists.",
                        create.id
                    ),
                ));
            }
        }
    }
}

// ── CREATE INDEX without IF NOT EXISTS ───────

pub struct CreateIndexIdempotencyRule;

impl Rule for CreateIndexIdempotencyRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        _state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if let Mutation::CreateIndex(create) = mutation {
            if !create.if_not_exists {
                reporter.report(Violation::new(
                    Severity::Warning,
                    format!(
                        "CREATE INDEX '{}' without IF NOT EXISTS. \
                         Re-running this migration will fail if the index already exists.",
                        create.id
                    ),
                ));
            }
        }
    }
}

// ── DROP TABLE without IF EXISTS ─────────────

pub struct DropTableIdempotencyRule;

impl Rule for DropTableIdempotencyRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        _state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if let Mutation::DropTable(drop) = mutation {
            if !drop.if_exists {
                reporter.report(Violation::new(
                    Severity::Warning,
                    format!(
                        "DROP TABLE '{}' without IF EXISTS. \
                         Re-running this migration will fail if the table was already dropped.",
                        drop.id
                    ),
                ));
            }
        }
    }
}

// ── DROP INDEX without IF EXISTS ─────────────

pub struct DropIndexIdempotencyRule;

impl Rule for DropIndexIdempotencyRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        _state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if let Mutation::DropIndex(drop) = mutation {
            if !drop.if_exists {
                reporter.report(Violation::new(
                    Severity::Warning,
                    format!(
                        "DROP INDEX '{}' without IF EXISTS. \
                         Re-running this migration will fail if the index was already dropped.",
                        drop.id
                    ),
                ));
            }
        }
    }
}

// ── DROP COLUMN without IF EXISTS ────────────
//
// Bug 16 fix: this rule was missing. DropColumn facts carry
// if_exists: bool (extracted in visitor.rs) but no rule
// consumed it. A migration that drops a column without IF EXISTS
// will fail on re-run if the column was already removed.

pub struct DropColumnIdempotencyRule;

impl Rule for DropColumnIdempotencyRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        _state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if let Mutation::AlterTable(alter) = mutation {
            if let AlterTableActionMutation::DropColumn { name, if_exists } = &alter.action {
                if !if_exists {
                    reporter.report(Violation::new(
                        Severity::Warning,
                        format!(
                            "DROP COLUMN '{}' on '{}' without IF EXISTS. \
                             Re-running this migration will fail if the column was already dropped.",
                            name, alter.id
                        ),
                    ));
                }
            }
        }
    }
}
