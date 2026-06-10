use crate::analysis::mutations::Mutation;
use crate::analysis::state::AnalysisState;
use crate::report::reporter::Reporter;
use crate::report::violations::{Severity, Violation};
use crate::rules::Rule;

// ─────────────────────────────────────────────
// ConcurrentIndexRule — CREATE INDEX
// ─────────────────────────────────────────────

pub struct ConcurrentIndexRule;

impl Rule for ConcurrentIndexRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if let Mutation::CreateIndex(create) = mutation {
            let inside_transaction = !state.local.transactions.is_empty();

            if inside_transaction && create.concurrently {
                reporter.report(Violation::new(
                    Severity::Warning,
                    format!(
                        "CREATE INDEX CONCURRENTLY on '{}' is inside a transaction block. \
                         PostgreSQL will silently downgrade this to a blocking index build. \
                         Move it outside the transaction.",
                        create.id
                    ),
                ));
            } else if !inside_transaction && !create.concurrently {
                reporter.report(Violation::new(
                    Severity::Warning,
                    format!(
                        "CREATE INDEX on '{}' without CONCURRENTLY will take an \
                         ACCESS EXCLUSIVE lock on table '{}', blocking all reads \
                         and writes for the duration of the index build. \
                         Use CREATE INDEX CONCURRENTLY instead.",
                        create.id, create.table
                    ),
                ));
            }
        }
    }
}

// ─────────────────────────────────────────────
// DropConcurrentIndexRule — DROP INDEX
//
// DROP INDEX without CONCURRENTLY takes an
// ACCESS EXCLUSIVE lock on the parent table
// for the duration of the drop — blocking all
// reads and writes exactly like CREATE INDEX.
//
// DROP INDEX CONCURRENTLY releases the lock
// progressively, allowing concurrent access.
//
// Same transaction caveat as CREATE INDEX:
// DROP INDEX CONCURRENTLY cannot run inside
// a transaction block — PostgreSQL will error.
// ─────────────────────────────────────────────

pub struct DropConcurrentIndexRule;

impl Rule for DropConcurrentIndexRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if let Mutation::DropIndex(drop) = mutation {
            let inside_transaction = !state.local.transactions.is_empty();

            if inside_transaction && drop.concurrently {
                // DROP INDEX CONCURRENTLY inside a transaction is a hard error
                // in PostgreSQL — it won't downgrade, it will fail.
                reporter.report(Violation::new(
                    Severity::Error,
                    format!(
                        "DROP INDEX CONCURRENTLY on '{}' is inside a transaction block. \
                         PostgreSQL does not allow CONCURRENTLY inside a transaction — \
                         this will produce an error. Move it outside the transaction.",
                        drop.id
                    ),
                ));
            } else if !inside_transaction && !drop.concurrently {
                reporter.report(Violation::new(
                    Severity::Warning,
                    format!(
                        "DROP INDEX '{}' without CONCURRENTLY will take an ACCESS EXCLUSIVE \
                         lock on the parent table, blocking all reads and writes. \
                         Use DROP INDEX CONCURRENTLY instead.",
                        drop.id
                    ),
                ));
            }
            // inside_transaction && !concurrently: intentional blocking drop inside
            // a transaction. No violation.
            //
            // !inside_transaction && concurrently: correct usage. No violation.
        }
    }
}
