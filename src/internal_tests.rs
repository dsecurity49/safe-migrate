// Implementation tests are compiled inside the crate so they can exercise
// invariants without promoting the mutable engine model to public API.
use std::sync::{Mutex, MutexGuard, OnceLock};

/// Live tests share disposable PostgreSQL fixtures, so Rust's default parallel
/// test scheduler must not let their setup and teardown overlap.
pub(crate) fn live_database_test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
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
#[path = "../tests/transaction_lifecycle.rs"]
mod transaction_lifecycle;
#[path = "../tests/v045_state.rs"]
mod v045_state;
#[path = "../tests/v060_timeouts.rs"]
mod v060_timeouts;
