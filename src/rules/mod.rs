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

use crate::analysis::evidence::EvidenceRecord;
use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, CascadeResult, Confidence, MutationResult};
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
    pub(crate) evidence: &'a [EvidenceRecord],
    pub(crate) confidence: &'a Confidence,
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
            evidence: state.evidence(),
            confidence: state.confidence(),
        }
    }

    pub fn evidence(&self) -> &[EvidenceRecord] {
        self.evidence
    }

    pub fn confidence(&self) -> &Confidence {
        self.confidence
    }

    pub fn mutation(&self) -> &Mutation {
        self.mutation
    }

    pub fn result(&self) -> &MutationResult {
        self.result
    }

    pub fn pre_state(&self) -> &crate::analysis::state::PreState {
        self.pre_state
    }

    pub fn state(&self) -> &AnalysisState {
        self.state
    }

    pub fn config(&self) -> &Config {
        self.config
    }

    pub fn cascade_closure(&self) -> Option<&CascadeResult> {
        self.cascade_closure
    }
}

/// Supported rule interface. Implementations receive one immutable context
/// object, so future inputs can be added without another argument explosion.
pub trait Rule {
    fn id(&self) -> &'static str;
    fn default_tier(&self) -> ViolationTier;
    fn recipe(&self) -> &'static str;

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation>;
}

/// Transitional implementation interface for rules that have not yet been
/// mechanically migrated to `RuleContext`. This trait is crate-private in
/// practice: it is only used by the blanket bridge below.
trait LegacyRule {
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
}

impl<T: LegacyRule> Rule for T {
    fn id(&self) -> &'static str {
        LegacyRule::id(self)
    }

    fn default_tier(&self) -> ViolationTier {
        LegacyRule::default_tier(self)
    }

    fn recipe(&self) -> &'static str {
        LegacyRule::recipe(self)
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        LegacyRule::evaluate(
            self,
            context.mutation,
            context.result,
            context.pre_state,
            context.state,
            context.config,
            context.cascade_closure,
        )
    }
}
