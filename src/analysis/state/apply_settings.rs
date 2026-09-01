use super::{AnalysisState, MutationResult};
use crate::analysis::evidence::{EvidenceCode, EvidenceScope};
use crate::analysis::facts::{
    ResetSettingTarget, RoleFact, SearchPathTarget, TimeoutSetting, TimeoutSettingValue,
};
use crate::analysis::mutations::{OpaqueMutation, SearchPathChange, TimeoutSettingChange};

impl AnalysisState {
    pub(super) fn apply_search_path(&mut self, change: &SearchPathChange) -> MutationResult {
        if change.local && self.local.transactions.is_empty() {
            return MutationResult::Skipped;
        }
        self.snapshot_search_path();
        self.snapshot_confidence();
        let template = match &change.target {
            SearchPathTarget::Default => self.local.default_search_path_template.clone(),
            SearchPathTarget::Schemas(schemas) => schemas.clone(),
        };
        self.local.search_path_template = template.clone();
        if !change.local {
            self.local.session_search_path_template = template;
        }
        self.refresh_role_sensitive_search_path();
        MutationResult::Applied
    }

    pub(super) fn apply_timeout_setting(
        &mut self,
        change: &TimeoutSettingChange,
    ) -> MutationResult {
        if change.local && self.local.transactions.is_empty() {
            return MutationResult::Skipped;
        }
        let next = match &change.value {
            TimeoutSettingValue::Default => match change.setting {
                TimeoutSetting::Lock => self.local.lock_timeout.default,
                TimeoutSetting::Statement => self.local.statement_timeout.default,
            },
            TimeoutSettingValue::Milliseconds(milliseconds) => Some(*milliseconds),
            TimeoutSettingValue::Current => match change.setting {
                TimeoutSetting::Lock => self.local.lock_timeout.effective,
                TimeoutSetting::Statement => self.local.statement_timeout.effective,
            },
            TimeoutSettingValue::Invalid(reason) => {
                return MutationResult::Conflict {
                    reason: reason.clone(),
                };
            }
        };
        self.snapshot_timeout_settings();
        let setting = match change.setting {
            TimeoutSetting::Lock => &mut self.local.lock_timeout,
            TimeoutSetting::Statement => &mut self.local.statement_timeout,
        };
        setting.effective = next;
        if !change.local {
            setting.session = next;
        }
        MutationResult::Applied
    }

    pub(super) fn apply_reset_settings(&mut self, target: &ResetSettingTarget) -> MutationResult {
        if matches!(
            target,
            ResetSettingTarget::All | ResetSettingTarget::SearchPath
        ) {
            self.snapshot_search_path();
            self.snapshot_confidence();
            let template = self.local.default_search_path_template.clone();
            self.local.session_search_path_template = template.clone();
            self.local.search_path_template = template;
            self.refresh_role_sensitive_search_path();
        }
        if matches!(
            target,
            ResetSettingTarget::All
                | ResetSettingTarget::LockTimeout
                | ResetSettingTarget::StatementTimeout
        ) {
            self.snapshot_timeout_settings();
            if matches!(
                target,
                ResetSettingTarget::All | ResetSettingTarget::LockTimeout
            ) {
                self.local.lock_timeout.session = self.local.lock_timeout.default;
                self.local.lock_timeout.effective = self.local.lock_timeout.default;
            }
            if matches!(
                target,
                ResetSettingTarget::All | ResetSettingTarget::StatementTimeout
            ) {
                self.local.statement_timeout.session = self.local.statement_timeout.default;
                self.local.statement_timeout.effective = self.local.statement_timeout.default;
            }
        }
        MutationResult::Applied
    }

    pub(super) fn apply_switch_role(
        &mut self,
        role: &Option<RoleFact>,
        local: bool,
        is_session_auth: bool,
    ) -> MutationResult {
        if local && self.local.transactions.is_empty() {
            return MutationResult::Skipped;
        }

        let (target_name, target_known) = if let Some(role) = role {
            let Some(identity) = self.role_fact_identity(role) else {
                self.taint(EvidenceCode::UnresolvedReference, EvidenceScope::Chain);
                return MutationResult::Skipped;
            };
            identity
        } else if is_session_auth {
            (
                self.local.authenticated_role.clone(),
                self.local.authenticated_role_known,
            )
        } else {
            (
                self.local.session_role.clone(),
                self.local.session_role_known,
            )
        };
        let persistent_role_reset_target = if role.is_none() && !is_session_auth {
            Some((
                self.local.persistent_session_role.clone(),
                self.local.persistent_session_role_known,
            ))
        } else {
            None
        };

        let authorized = if role.is_none() {
            Some(true)
        } else if is_session_auth {
            self.can_set_session_authorization_to(&target_name)
        } else {
            self.can_set_role_to(&target_name)
        };
        match authorized {
            Some(false) => {
                return MutationResult::Conflict {
                    reason: if self.present_role(&target_name).is_none() {
                        format!("role '{}' does not exist", target_name)
                    } else {
                        format!("permission denied to set role '{}'", target_name)
                    },
                };
            }
            None => {
                self.taint(
                    EvidenceCode::CatalogCoverageIncomplete,
                    EvidenceScope::Chain,
                );
            }
            Some(true) => {}
        }

        self.snapshot_role_context();
        self.snapshot_search_path();
        self.snapshot_confidence();
        if is_session_auth {
            self.local.session_role = target_name.clone();
            self.local.session_role_known = target_known;
            self.local.current_role = target_name.clone();
            self.local.current_role_known = target_known;
            if !local {
                self.local.persistent_session_role = target_name.clone();
                self.local.persistent_session_role_known = target_known;
                self.local.persistent_current_role = target_name;
                self.local.persistent_current_role_known = target_known;
            }
        } else {
            self.local.current_role = target_name.clone();
            self.local.current_role_known = target_known;
            if !local {
                let (persistent_name, persistent_known) =
                    persistent_role_reset_target.unwrap_or((target_name, target_known));
                self.local.persistent_current_role = persistent_name;
                self.local.persistent_current_role_known = persistent_known;
            }
        }
        self.refresh_role_sensitive_search_path();
        MutationResult::Applied
    }

    pub(super) fn apply_opaque(&mut self, opaque: &OpaqueMutation) -> MutationResult {
        let code = match opaque {
            OpaqueMutation::UnsupportedStatement => EvidenceCode::UnsupportedStatement,
            OpaqueMutation::UnresolvedReference { .. } => EvidenceCode::UnresolvedReference,
            _ => EvidenceCode::UnsupportedSemantics,
        };
        self.taint(code, EvidenceScope::Chain);
        MutationResult::Applied
    }
}
