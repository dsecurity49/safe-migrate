use crate::analysis::mutations::Mutation;
use crate::analysis::state::MutationResult;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::rules::{Rule, RuleContext};

pub struct RestrictivePolicyRule;

impl Rule for RestrictivePolicyRule {
    fn id(&self) -> &'static str {
        "restrictive-policy"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier2
    }
    fn recipe(&self) -> &'static str {
        "Adding a RESTRICTIVE policy narrows access for all users. This can silently make rows invisible that were previously accessible."
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        if *context.result() == MutationResult::Skipped {
            return vec![];
        }
        let mut violations = Vec::new();

        if let Mutation::CreatePolicy(policy) = context.mutation()
            && !policy.permissive
        {
            violations.push(Violation {
                source_range: None,
                rule_id: self.id(),
                operation_kind: OperationKind::CreatePolicy,
                object_kind: ObjectKind::Policy,
                object_name: format!("{} on {}", policy.name, policy.table),
                tier: self.default_tier(),
                reason: format!(
                    "Adding RESTRICTIVE policy {} on {}",
                    policy.name, policy.table
                ),
                recipe: self.recipe(),
                dedup_key: None,
                sql: None,
                fk_dependency_related: false,
            });
        }

        violations
    }
}
