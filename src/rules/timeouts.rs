use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::rules::LegacyRule as Rule;

pub struct RequireLockTimeoutRule;

impl Rule for RequireLockTimeoutRule {
    fn id(&self) -> &'static str {
        "require-lock-timeout"
    }

    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier2
    }

    fn recipe(&self) -> &'static str {
        "Set a positive lock_timeout before this operation, or configure it for the intended migration role and run safe-migrate sync again."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        result: &MutationResult,
        _pre_state: &crate::analysis::state::PreState,
        state: &AnalysisState,
        _config: &Config,
        _cascade: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        if !matches!(mutation, Mutation::CheckTimeouts) || result != &MutationResult::Applied {
            return Vec::new();
        }

        let reason = match state.local.lock_timeout.effective {
            None => "No lock_timeout is known from SQL or a synchronized cache.".to_string(),
            Some(0) => "lock_timeout is disabled (0).".to_string(),
            Some(lock_timeout) => match state.local.statement_timeout.effective {
                Some(statement_timeout)
                    if statement_timeout > 0 && lock_timeout >= statement_timeout =>
                {
                    format!(
                        "lock_timeout ({lock_timeout} ms) is not shorter than statement_timeout ({statement_timeout} ms), so PostgreSQL reaches statement_timeout first."
                    )
                }
                _ => return Vec::new(),
            },
        };

        vec![Violation {
            source_range: None,
            rule_id: self.id(),
            operation_kind: OperationKind::Other("timeout_check".to_string()),
            object_kind: ObjectKind::Unknown,
            object_name: "<statement>".to_string(),
            tier: self.default_tier(),
            reason,
            recipe: self.recipe(),
            dedup_key: Some(self.id().to_string()),
            sql: None,
            fk_dependency_related: false,
        }]
    }
}

pub struct RequireStatementTimeoutRule;

impl Rule for RequireStatementTimeoutRule {
    fn id(&self) -> &'static str {
        "require-statement-timeout"
    }

    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier2
    }

    fn recipe(&self) -> &'static str {
        "Set a positive statement_timeout before this operation, or configure it for the intended migration role and run safe-migrate sync again."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        result: &MutationResult,
        _pre_state: &crate::analysis::state::PreState,
        state: &AnalysisState,
        _config: &Config,
        _cascade: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        if !matches!(mutation, Mutation::CheckTimeouts) || result != &MutationResult::Applied {
            return Vec::new();
        }

        let reason = match state.local.statement_timeout.effective {
            None => "No statement_timeout is known from SQL or a synchronized cache.".to_string(),
            Some(0) => "statement_timeout is disabled (0).".to_string(),
            Some(_) => return Vec::new(),
        };

        vec![Violation {
            source_range: None,
            rule_id: self.id(),
            operation_kind: OperationKind::Other("timeout_check".to_string()),
            object_kind: ObjectKind::Unknown,
            object_name: "<statement>".to_string(),
            tier: self.default_tier(),
            reason,
            recipe: self.recipe(),
            dedup_key: Some(self.id().to_string()),
            sql: None,
            fk_dependency_related: false,
        }]
    }
}
