use crate::analysis::mutations::Mutation;
use crate::analysis::state::AnalysisState;
use crate::report::reporter::Reporter;

pub mod constraints;
pub mod destructive;
pub mod expressions;
pub mod indexes;
pub mod opaque;
pub mod partitions;
pub mod transactions;
pub mod views;

pub trait Rule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        state: &AnalysisState,
        reporter: &mut Reporter,
    );

    /// Called once after all mutations in the migration file have been
    /// applied. Used for rules that check accumulated state rather than
    /// individual mutations — e.g. detecting NOT VALID constraints that
    /// were never followed by VALIDATE CONSTRAINT.
    ///
    /// Default implementation is a no-op so existing rules need no changes.
    fn finalize(&self, _state: &AnalysisState, _reporter: &mut Reporter) {}
}

/// Returns the active rule set for the engine loop.
///
/// Rules are evaluated in order for each mutation. Order matters
/// when a later rule depends on a violation already reported by
/// an earlier one — put more fundamental checks first.
pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        // Transaction sanity first — if we're outside a valid
        // transaction context the rest of the analysis is moot.
        Box::new(transactions::TransactionSanityRule),

        // Opaque execution downgrades confidence — report it early
        // so downstream rules know the state may be unreliable.
        Box::new(opaque::OpaqueExecutionRule),

        // Destructive operations.
        Box::new(destructive::DestructiveDropRule),

        // Index safety — CONCURRENTLY flag, locking behaviour.
        Box::new(indexes::ConcurrentIndexRule),

        // Dependency safety — views, FK, indexes referencing dropped tables.
        Box::new(views::OrphanedDependencyRule),

        // Column-level mutation safety.
        Box::new(constraints::SafeAddColumnRule),
        Box::new(constraints::NotValidConstraintRule),
        Box::new(constraints::SetNotNullRule),
        Box::new(constraints::MissingValidateConstraintRule),

        // Volatile default heuristic.
        Box::new(expressions::VolatileDefaultRule),
        Box::new(expressions::SetTypeRule),
    ]
}
