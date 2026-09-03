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

use crate::_internal::analysis::evidence::EvidenceRecord;
use crate::_internal::analysis::mutations::Mutation;
use crate::_internal::analysis::state::{AnalysisState, CascadeResult, Confidence, MutationResult};
use crate::_internal::engine::config::Config;
use crate::_internal::report::violations::{Violation, ViolationTier};

/// Read-only inputs supplied to a rule for one analyzed mutation.
///
/// Keeping this bundle immutable prevents the engine from accidentally
/// evaluating a rule against state from a different statement and provides a
/// single extension point for evidence/capability metadata.
pub(crate) struct TransitionRecord<'a> {
    mutation: &'a Mutation,
    result: &'a MutationResult,
    pre_state: &'a crate::_internal::analysis::state::PreState,
    cascade_closure: Option<&'a CascadeResult>,
    evidence: &'a [EvidenceRecord],
    confidence: &'a Confidence,
}

impl<'a> TransitionRecord<'a> {
    fn new(
        mutation: &'a Mutation,
        result: &'a MutationResult,
        pre_state: &'a crate::_internal::analysis::state::PreState,
        cascade_closure: Option<&'a CascadeResult>,
        evidence: &'a [EvidenceRecord],
        confidence: &'a Confidence,
    ) -> Self {
        Self {
            mutation,
            result,
            pre_state,
            cascade_closure,
            evidence,
            confidence,
        }
    }
}

pub struct RuleContext<'a> {
    pub(crate) transition: TransitionRecord<'a>,
    pub(crate) state: &'a AnalysisState,
    pub(crate) config: &'a Config,
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
                record.code != crate::_internal::analysis::evidence::EvidenceCode::TransactionStateUnknown
            });
        }
        if !state.baseline_is_available() {
            return false;
        }
        let family = match self {
            Self::BaselineRelations | Self::RowStatistics => {
                crate::_internal::db::cache::CatalogFamily::Relations
            }
            Self::CatalogDependencies => crate::_internal::db::cache::CatalogFamily::Dependencies,
            Self::FunctionCatalog => crate::_internal::db::cache::CatalogFamily::Routines,
            Self::TransactionState => unreachable!(),
        };
        state.baseline_has_coverage(family)
    }

    /// Check capability availability for the concrete transition being
    /// evaluated. Catalog-family coverage alone cannot prove row statistics:
    /// PostgreSQL legitimately reports an unknown estimate for an individual
    /// relation that has never been analyzed. Keep that uncertainty scoped to
    /// rules whose finding actually depends on the affected relation.
    pub(crate) fn available_for(
        self,
        state: &AnalysisState,
        mutation: &crate::_internal::analysis::mutations::Mutation,
        pre_state: &crate::_internal::analysis::state::PreState,
    ) -> bool {
        if self != Self::RowStatistics {
            return self.available(state);
        }
        if !self.available(state) {
            return false;
        }

        let mut targets = Vec::new();
        match mutation {
            crate::_internal::analysis::mutations::Mutation::AlterTable(alter) => {
                targets.push(&alter.id);
                if let crate::_internal::analysis::mutations::AlterTableActionMutation::AddForeignKey {
                    to_table,
                    ..
                } = &alter.action
                {
                    targets.push(to_table);
                }
            }
            crate::_internal::analysis::mutations::Mutation::CreateIndex(create) => {
                targets.push(&create.table);
            }
            crate::_internal::analysis::mutations::Mutation::RefreshMaterializedView(refresh) => {
                targets.push(&refresh.id);
            }
            crate::_internal::analysis::mutations::Mutation::DropIndex(drop) => {
                for index_id in &drop.ids {
                    targets.extend(pre_state.indexes.iter().filter_map(|edge| {
                        if edge.dependent == *index_id {
                            if let crate::_internal::analysis::graph::DependencyKind::IndexOnRelation {
                                ..
                            } = edge.kind
                            {
                                Some(&edge.referenced)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }));
                }
            }
            _ => {}
        }

        // A capability can be declared by a rule that has findings for a
        // different mutation family. In that case there is no relation-local
        // statistic to require.
        targets.into_iter().all(|id| {
            pre_state
                .relations
                .get(id)
                .is_some_and(|relation| relation.estimated_rows.is_some())
        })
    }

    pub(crate) const fn evidence_code(self) -> crate::_internal::analysis::evidence::EvidenceCode {
        match self {
            Self::BaselineRelations
            | Self::CatalogDependencies
            | Self::RowStatistics
            | Self::FunctionCatalog => {
                crate::_internal::analysis::evidence::EvidenceCode::CatalogCoverageIncomplete
            }
            Self::TransactionState => {
                crate::_internal::analysis::evidence::EvidenceCode::TransactionStateUnknown
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
pub(crate) const FUNCTION_DEPENDENCY_CAPABILITIES: &[RuleCapability] = &[
    RuleCapability::FunctionCatalog,
    RuleCapability::CatalogDependencies,
];
pub(crate) const BASELINE_STATS_DEPENDENCY_CAPABILITIES: &[RuleCapability] = &[
    RuleCapability::BaselineRelations,
    RuleCapability::CatalogDependencies,
    RuleCapability::RowStatistics,
];
pub(crate) const TRANSACTION_CAPABILITIES: &[RuleCapability] = &[RuleCapability::TransactionState];

impl<'a> RuleContext<'a> {
    pub(crate) fn new(
        mutation: &'a Mutation,
        result: &'a MutationResult,
        pre_state: &'a crate::_internal::analysis::state::PreState,
        state: &'a AnalysisState,
        config: &'a Config,
        cascade_closure: Option<&'a CascadeResult>,
    ) -> Self {
        Self {
            transition: TransitionRecord::new(
                mutation,
                result,
                pre_state,
                cascade_closure,
                state.evidence(),
                state.confidence(),
            ),
            state,
            config,
        }
    }

    pub fn evidence(&self) -> &[EvidenceRecord] {
        self.transition.evidence
    }

    pub fn confidence(&self) -> &Confidence {
        self.transition.confidence
    }

    pub fn mutation(&self) -> &Mutation {
        self.transition.mutation
    }

    pub fn result(&self) -> &MutationResult {
        self.transition.result
    }

    pub fn pre_state(&self) -> &crate::_internal::analysis::state::PreState {
        self.transition.pre_state
    }

    pub fn state(&self) -> &AnalysisState {
        self.state
    }

    pub fn config(&self) -> &Config {
        self.config
    }

    pub fn cascade_closure(&self) -> Option<&CascadeResult> {
        self.transition.cascade_closure
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
