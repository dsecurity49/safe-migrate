// src/rules/transactions.rs
use crate::analysis::mutations::Mutation;
use crate::analysis::state::AnalysisState;
use crate::report::Reporter;
use crate::rules::Rule;

pub struct TransactionSanityRule;

impl Rule for TransactionSanityRule {
    fn evaluate(&self, mutation: &Mutation, state: &AnalysisState, reporter: &mut Reporter) {
        match mutation {
            Mutation::BeginTransaction => {
                if !state.local.transactions.is_empty() {
                    reporter.report("WARNING: PostgreSQL issues a warning when calling BEGIN inside an existing transaction block.".to_string());
                }
            }
            Mutation::CommitTransaction | Mutation::RollbackTransaction => {
                if state.local.transactions.is_empty() {
                    reporter.report("WARNING: Calling COMMIT or ROLLBACK outside of a transaction block has no effect.".to_string());
                }
            }
            _ => {}
        }
    }
}
