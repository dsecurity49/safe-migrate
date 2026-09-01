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

/// Semantic state surfaces a rule must account for before claiming an exact
/// result. Declarations are checked centrally so new rules cannot silently
/// depend on an untracked part of the transition state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleCapability {
    BaselineRelations,
    CatalogDependencies,
    RowStatistics,
    TransactionState,
    FunctionCatalog,
}

impl RuleCapability {
    pub(crate) fn available(self, state: &AnalysisState) -> bool {
        if self == Self::TransactionState {
            return state.evidence().iter().all(|record| {
                record.code != crate::analysis::evidence::EvidenceCode::TransactionStateUnknown
            });
        }
        if !state.baseline_available {
            return false;
        }
        let family = match self {
            Self::BaselineRelations | Self::RowStatistics => {
                crate::db::cache::CatalogFamily::Relations
            }
            Self::CatalogDependencies => crate::db::cache::CatalogFamily::Dependencies,
            Self::FunctionCatalog => crate::db::cache::CatalogFamily::Routines,
            Self::TransactionState => unreachable!(),
        };
        state.baseline_coverage.has(family)
    }

    pub(crate) const fn evidence_code(self) -> crate::analysis::evidence::EvidenceCode {
        match self {
            Self::BaselineRelations
            | Self::CatalogDependencies
            | Self::RowStatistics
            | Self::FunctionCatalog => {
                crate::analysis::evidence::EvidenceCode::CatalogCoverageIncomplete
            }
            Self::TransactionState => {
                crate::analysis::evidence::EvidenceCode::TransactionStateUnknown
            }
        }
    }
}

pub(crate) const BASELINE_STATS_CAPABILITIES: &[RuleCapability] = &[
    RuleCapability::BaselineRelations,
    RuleCapability::RowStatistics,
];
pub(crate) const BASELINE_RELATION_CAPABILITIES: &[RuleCapability] =
    &[RuleCapability::BaselineRelations];
pub(crate) const FUNCTION_CAPABILITIES: &[RuleCapability] = &[RuleCapability::FunctionCatalog];
pub(crate) const TRANSACTION_CAPABILITIES: &[RuleCapability] = &[RuleCapability::TransactionState];

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

    fn required_capabilities(&self) -> &'static [RuleCapability] {
        &[]
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation>;
}
