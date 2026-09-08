pub(crate) mod conflict;
pub(crate) mod constraints;
pub(crate) mod destructive;
pub(crate) mod drift;
pub(crate) mod expressions;
pub(crate) mod functions;
pub(crate) mod idempotency;
pub(crate) mod indexes;
pub(crate) mod opaque;
pub(crate) mod partitions;
pub(crate) mod policies;
pub(crate) mod registry;
pub(crate) mod security;
pub(crate) mod timeouts;
pub(crate) mod transactions;
pub(crate) mod triggers;
pub(crate) mod views;

use crate::_internal::analysis::mutations::Mutation;
use crate::_internal::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::_internal::report::violations::{Violation, ViolationTier};
use crate::api::config::Config;

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
}

impl<'a> TransitionRecord<'a> {
    fn new(
        mutation: &'a Mutation,
        result: &'a MutationResult,
        pre_state: &'a crate::_internal::analysis::state::PreState,
        cascade_closure: Option<&'a CascadeResult>,
    ) -> Self {
        Self {
            mutation,
            result,
            pre_state,
            cascade_closure,
        }
    }
}

pub(crate) struct RuleContext<'a> {
    pub(crate) transition: TransitionRecord<'a>,
    pub(crate) state: &'a AnalysisState,
    pub(crate) config: &'a Config,
}

/// Semantic state surfaces a rule must account for before claiming an exact
/// result. Declarations are checked centrally so new rules cannot silently
/// depend on an untracked part of the transition state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuleCapability {
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
            transition: TransitionRecord::new(mutation, result, pre_state, cascade_closure),
            state,
            config,
        }
    }

    pub(crate) fn mutation(&self) -> &Mutation {
        self.transition.mutation
    }

    pub(crate) fn result(&self) -> &MutationResult {
        self.transition.result
    }

    pub(crate) fn pre_state(&self) -> &crate::_internal::analysis::state::PreState {
        self.transition.pre_state
    }

    pub(crate) fn state(&self) -> &AnalysisState {
        self.state
    }

    pub(crate) fn config(&self) -> &Config {
        self.config
    }

    pub(crate) fn cascade_closure(&self) -> Option<&CascadeResult> {
        self.transition.cascade_closure
    }
}

/// Supported rule interface. Implementations receive one immutable context
/// object, so future inputs can be added without another argument explosion.
pub(crate) trait Rule {
    fn id(&self) -> &'static str;
    fn default_tier(&self) -> ViolationTier;
    fn recipe(&self) -> &'static str;

    fn required_capabilities(&self) -> &'static [RuleCapability] {
        &[]
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation>;
}
