use crate::analysis::mutations::Mutation;
use crate::analysis::state::AnalysisState;
use crate::report::reporter::Reporter;

pub mod constraints;
pub mod destructive;
pub mod expressions;
pub mod idempotency;
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

    /// Called once after all mutations have been applied.
    /// Used for rules that inspect accumulated state rather than
    /// individual mutations. Default is a no-op.
    fn finalize(&self, _state: &AnalysisState, _reporter: &mut Reporter) {}
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    vec![
        // Transaction sanity first.
        Box::new(transactions::TransactionSanityRule),

        // Opaque execution — downgrades confidence early.
        Box::new(opaque::OpaqueExecutionRule),

        // Destructive operations.
        Box::new(destructive::DestructiveDropRule),

        // Index lock safety.
        Box::new(indexes::ConcurrentIndexRule),
        Box::new(indexes::DropConcurrentIndexRule),

        // Dependency safety.
        Box::new(views::OrphanedDependencyRule),

        // Constraint lock safety.
        Box::new(constraints::SafeAddColumnRule),
        Box::new(constraints::NotValidConstraintRule),
        Box::new(constraints::SetNotNullRule),
        Box::new(constraints::AddCheckConstraintRule),
        Box::new(constraints::AddUniqueConstraintRule),
        Box::new(constraints::MissingValidateConstraintRule),

        // Expression / type safety.
        Box::new(expressions::VolatileDefaultRule),
        Box::new(expressions::SetTypeRule),

        // Idempotency.
        Box::new(idempotency::CreateTableIdempotencyRule),
        Box::new(idempotency::CreateIndexIdempotencyRule),
        Box::new(idempotency::DropTableIdempotencyRule),
        Box::new(idempotency::DropIndexIdempotencyRule),
        // Bug 16 fix: register the new DropColumn idempotency rule.
        Box::new(idempotency::DropColumnIdempotencyRule),
    ]
}
