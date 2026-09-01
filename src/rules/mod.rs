pub mod conflict;
pub mod constraints;
pub mod destructive;
pub mod drift;
pub mod expressions;
pub mod functions;
pub mod idempotency;
pub mod indexes;
pub mod opaque;
pub mod partitions;
pub mod policies;
pub mod registry;
pub mod security;
pub mod timeouts;
pub mod transactions;
pub mod triggers;
pub mod views;

use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier};

/// Read-only inputs supplied to a rule for one analyzed mutation.
///
/// Keeping this bundle immutable prevents the engine from accidentally
/// evaluating a rule against state from a different statement and provides a
/// single extension point for evidence/capability metadata.
pub struct RuleContext<'a> {
    pub(crate) mutation: &'a Mutation,
    pub(crate) result: &'a MutationResult,
    pub(crate) pre_state: &'a crate::analysis::state::PreState,
    pub(crate) state: &'a AnalysisState,
    pub(crate) config: &'a Config,
    pub(crate) cascade_closure: Option<&'a CascadeResult>,
}

impl<'a> RuleContext<'a> {
    pub(crate) fn new(
        mutation: &'a Mutation,
        result: &'a MutationResult,
        pre_state: &'a crate::analysis::state::PreState,
        state: &'a AnalysisState,
        config: &'a Config,
        cascade_closure: Option<&'a CascadeResult>,
    ) -> Self {
        Self {
            mutation,
            result,
            pre_state,
            state,
            config,
            cascade_closure,
        }
    }
}

pub trait Rule {
    fn id(&self) -> &'static str;
    fn default_tier(&self) -> ViolationTier;
    fn recipe(&self) -> &'static str;

    fn evaluate(
        &self,
        mutation: &Mutation,
        result: &MutationResult,
        pre_state: &crate::analysis::state::PreState,
        state: &AnalysisState,
        config: &Config,
        cascade_closure: Option<&CascadeResult>,
    ) -> Vec<Violation>;

    /// Evaluate through the immutable context boundary.
    ///
    /// The compatibility adapter is temporary: individual rules can migrate
    /// to `RuleContext` without forcing a repository-wide behavior change.
    fn evaluate_context(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        self.evaluate(
            context.mutation,
            context.result,
            context.pre_state,
            context.state,
            context.config,
            context.cascade_closure,
        )
    }
}
