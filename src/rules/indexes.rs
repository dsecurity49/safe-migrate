use crate::analysis::mutations::Mutation;
use crate::analysis::state::AnalysisState;
use crate::report::reporter::Reporter;
use crate::report::violations::{Severity, Violation};
use crate::rules::Rule;

// ConcurrentIndexRule
//
// Fires when CREATE INDEX is used without the
// CONCURRENTLY flag in a migration.
//
// Without CONCURRENTLY, PostgreSQL takes an
// ACCESS EXCLUSIVE lock on the table for the
// duration of the index build — blocking all
// reads and writes. On any table with live
// traffic this will cause downtime.
//
// CONCURRENTLY builds the index in the
// background with weaker locks, allowing normal
// table access throughout.
//
// Exceptions:
//   - Inside an explicit transaction block
//     (CREATE INDEX CONCURRENTLY cannot run
//     inside a transaction in PostgreSQL).
//     In that case we flip the violation:
//     warn that CONCURRENTLY was used inside
//     a transaction and will be silently
//     downgraded by PostgreSQL to a blocking build.

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
                // CONCURRENTLY inside a transaction block is silently ignored
                // by PostgreSQL — the index build becomes blocking anyway.
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
                // Non-concurrent build outside a transaction — will take
                // ACCESS EXCLUSIVE lock and block all table access.
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
            // inside_transaction && !concurrently: blocking build inside a
            // transaction is intentional (e.g. migration tooling that wraps
            // everything in a transaction). No violation — the author made
            // an explicit choice.
            //
            // !inside_transaction && concurrently: correct usage. No violation.
        }
    }
}
