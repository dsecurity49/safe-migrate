// Implementation tests are compiled inside the crate so they can exercise
// invariants without promoting the mutable engine model to public API.
pub(crate) use crate::_internal::test_support::LiveDatabaseGuard;

/// Live tests share disposable PostgreSQL fixtures and the `DATABASE_URL`
/// environment variable, so they must exclude each other and every
/// environment-mutating test. Both needs are served by one lock.
pub(crate) fn live_database_test_lock() -> LiveDatabaseGuard {
    LiveDatabaseGuard::acquire()
}

#[path = "../tests/alter_schema_visitor.rs"]
mod alter_schema_visitor;
#[path = "../tests/architectural_gaps.rs"]
mod architectural_gaps;
#[path = "../tests/bug_fixes.rs"]
mod bug_fixes;
#[path = "../tests/chain_execution.rs"]
mod chain_execution;
#[path = "../tests/cli_tests.rs"]
mod cli_tests;
#[path = "../tests/destructive_rules.rs"]
mod destructive_rules;
#[path = "../tests/evidence_outcome.rs"]
mod evidence_outcome;
#[path = "../tests/exhaustive_fuzz.rs"]
mod exhaustive_fuzz;
#[path = "../tests/expression_parsing.rs"]
mod expression_parsing;
#[path = "../tests/identifier_casing.rs"]
mod identifier_casing;
#[path = "../tests/invariant_sequences.rs"]
mod invariant_sequences_file;
#[path = "../tests/live_auto_sync.rs"]
mod live_auto_sync;
#[path = "../tests/live_cache_encryption.rs"]
mod live_cache_encryption;
#[path = "../tests/live_catalog_sync.rs"]
mod live_catalog_sync;
#[path = "../tests/live_differential_harness.rs"]
mod live_differential_harness;
#[path = "../tests/live_parity_oracle_file.rs"]
mod live_parity_oracle;
#[path = "../tests/performance_scenarios.rs"]
mod performance_scenarios_file;
#[path = "../tests/resolver_namespaces.rs"]
mod resolver_namespaces;
#[path = "../tests/reversibility.rs"]
mod reversibility;
#[path = "../tests/rule_evaluation.rs"]
mod rule_evaluation;
#[path = "../tests/state_machine_guards.rs"]
mod state_machine_guards;
#[path = "../tests/state_mutation.rs"]
mod state_mutation;
#[path = "../tests/test_isolation.rs"]
mod test_isolation;
#[path = "../tests/transaction_lifecycle.rs"]
mod transaction_lifecycle;
#[path = "../tests/v045_state.rs"]
mod v045_state;
#[path = "../tests/v060_timeouts.rs"]
mod v060_timeouts;
#[path = "../tests/v070_stub_removal.rs"]
mod v070_stub_removal;
