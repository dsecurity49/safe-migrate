use super::Resolver;
use crate::_internal::analysis::facts::{
    RelationTargetFact, SearchPathTarget, TimeoutSetting, TimeoutSettingValue,
};
use crate::_internal::analysis::mutations::{
    LockTableMutation, Mutation, RelationTargetMutation, ReleaseSavepointMutation,
    RollbackToSavepointMutation, SavepointMutation, SearchPathChange, TimeoutSettingChange,
    TruncateMutation,
};
use crate::_internal::analysis::state::AnalysisState;
use crate::_internal::ast::identifiers::QualifiedName;

impl Resolver {
    pub(super) fn resolve_search_path(target: &SearchPathTarget, local: bool) -> Mutation {
        Mutation::SearchPath(SearchPathChange {
            target: target.clone(),
            local,
        })
    }

    pub(super) fn resolve_timeout(
        setting: TimeoutSetting,
        value: &TimeoutSettingValue,
        local: bool,
    ) -> Mutation {
        Mutation::TimeoutSetting(TimeoutSettingChange {
            setting,
            value: value.clone(),
            local,
        })
    }

    pub(super) fn resolve_rollback_to_savepoint(name: &str) -> Mutation {
        Mutation::RollbackToSavepoint(RollbackToSavepointMutation {
            name: name.to_string(),
        })
    }

    pub(super) fn resolve_savepoint(name: &str) -> Mutation {
        Mutation::Savepoint(SavepointMutation {
            name: name.to_string(),
        })
    }

    pub(super) fn resolve_release_savepoint(name: &str) -> Mutation {
        Mutation::ReleaseSavepoint(ReleaseSavepointMutation {
            name: name.to_string(),
        })
    }

    pub(super) fn resolve_vacuum(
        relation: Option<&QualifiedName>,
        is_full: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::Vacuum {
            table_id: relation.map(|relation| Self::resolve_relation_lookup_name(relation, state)),
            is_full,
        }
    }

    pub(super) fn resolve_lock(
        targets: &[RelationTargetFact],
        mode: crate::_internal::analysis::facts::LockModeFact,
        nowait: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::LockTable(LockTableMutation {
            targets: targets
                .iter()
                .map(|target| RelationTargetMutation {
                    id: Self::resolve_relation_lookup_name(&target.name, state),
                    only: target.only,
                })
                .collect(),
            mode,
            nowait,
        })
    }

    pub(super) fn resolve_truncate(
        targets: &[RelationTargetFact],
        cascade: bool,
        restart_identity: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::Truncate(TruncateMutation {
            targets: targets
                .iter()
                .map(|target| RelationTargetMutation {
                    id: Self::resolve_relation_lookup_name(&target.name, state),
                    only: target.only,
                })
                .collect(),
            cascade,
            restart_identity,
        })
    }
}
