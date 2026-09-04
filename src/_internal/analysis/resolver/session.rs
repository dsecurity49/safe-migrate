use super::Resolver;
use crate::_internal::analysis::facts::{SearchPathTarget, TimeoutSetting, TimeoutSettingValue};
use crate::_internal::analysis::mutations::{
    Mutation, ReleaseSavepointMutation, RollbackToSavepointMutation, SavepointMutation,
    SearchPathChange, TimeoutSettingChange,
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
}
