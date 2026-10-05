use crate::_internal::analysis::mutations::Mutation;
use crate::_internal::analysis::state::MutationResult;
use crate::_internal::report::violations::{ObjectKind, Violation, ViolationTier};
use crate::_internal::rules::{Rule, RuleContext};

pub(crate) struct RequireLockTimeoutRule;

impl RequireLockTimeoutRule {
    /// The object the timed statement acts on, or an honest unknown.
    fn subject(context: &RuleContext<'_>) -> (ObjectKind, String) {
        match context.mutation() {
            Mutation::CheckTimeouts {
                subject: Some(subject),
            } => subject.clone(),
            _ => (ObjectKind::Unknown, "unknown statement".to_string()),
        }
    }
}

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

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        if !matches!(context.mutation(), Mutation::CheckTimeouts { .. })
            || context.result() != &MutationResult::Applied
        {
            return Vec::new();
        }
        let subject = Self::subject(context);

        let reason = match context.state().effective_lock_timeout() {
            None => "No lock_timeout is known from SQL or a synchronized cache.".to_string(),
            Some(0) => "lock_timeout is disabled (0).".to_string(),
            Some(lock_timeout) => match context.state().effective_statement_timeout() {
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

            object_kind: subject.0,
            object_name: subject.1,
            tier: self.default_tier(),
            reason,
            recipe: self.recipe(),
            dedup_key: Some(self.id().to_string()),
            sql: None,
        }]
    }
}

pub(crate) struct RequireStatementTimeoutRule;

impl RequireStatementTimeoutRule {
    fn subject(context: &RuleContext<'_>) -> (ObjectKind, String) {
        match context.mutation() {
            Mutation::CheckTimeouts {
                subject: Some(subject),
            } => subject.clone(),
            _ => (ObjectKind::Unknown, "unknown statement".to_string()),
        }
    }
}

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

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        if !matches!(context.mutation(), Mutation::CheckTimeouts { .. })
            || context.result() != &MutationResult::Applied
        {
            return Vec::new();
        }
        let subject = Self::subject(context);

        let reason = match context.state().effective_statement_timeout() {
            None => "No statement_timeout is known from SQL or a synchronized cache.".to_string(),
            Some(0) => "statement_timeout is disabled (0).".to_string(),
            Some(_) => return Vec::new(),
        };

        vec![Violation {
            source_range: None,
            rule_id: self.id(),

            object_kind: subject.0,
            object_name: subject.1,
            tier: self.default_tier(),
            reason,
            recipe: self.recipe(),
            dedup_key: Some(self.id().to_string()),
            sql: None,
        }]
    }
}
