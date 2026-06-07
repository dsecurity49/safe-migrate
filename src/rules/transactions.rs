// src/rules/transactions.rs
use crate::analysis::mutations::Mutation;
use crate::analysis::state::AnalysisState;
use crate::report::reporter::Reporter;
use crate::report::violations::{Severity, Violation};
use crate::rules::Rule;

pub struct TransactionSanityRule;

impl Rule for TransactionSanityRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        match mutation {
            Mutation::BeginTransaction => {
                if !state.local.transactions.is_empty() {
                    reporter.report(Violation::new(
                        Severity::Warning,
                        "PostgreSQL warns when BEGIN is called inside an existing transaction block.",
                    ));
                }
            }
            Mutation::CommitTransaction | Mutation::RollbackTransaction => {
                if state.local.transactions.is_empty() {
                    reporter.report(Violation::new(
                        Severity::Warning,
                        "COMMIT or ROLLBACK outside a transaction block has no effect.",
                    ));
                }
            }
            _ => {}
        }
    }
}
