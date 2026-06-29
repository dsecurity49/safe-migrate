use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier};
use crate::rules::Rule;

pub struct DisableTriggerRule;

impl Rule for DisableTriggerRule {
    fn id(&self) -> &'static str {
        "disable-trigger"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "Disabling triggers can lead to data inconsistency and bypasses critical business logic. Use with extreme caution and ensure triggers are re-enabled."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        _result: &MutationResult,
        _pre_state: &crate::analysis::state::PreState,
        _state: &AnalysisState,
        _config: &Config,
        _cascade: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        if let Mutation::AlterTable(alter) = mutation {
            match &alter.action {
                AlterTableActionMutation::DisableTrigger { trigger_name } => {
                    let name = trigger_name.as_deref().unwrap_or("ALL");
                    violations.push(Violation {
                        rule_id: self.id(),
                        title: format!("Disabling trigger {} on {}", name, alter.id),
                        tier: self.default_tier(),
                        recipe: self.recipe(),
                        dedup_key: None,
                    });
                }
                AlterTableActionMutation::EnableTrigger { trigger_name } => {
                    let name = trigger_name.as_deref().unwrap_or("ALL");
                    violations.push(Violation {
                        rule_id: self.id(),
                        title: format!("Enabling trigger {} on {}", name, alter.id),
                        tier: ViolationTier::Tier3, // Tier 3 because it is restorative
                        recipe: "Re-enabling triggers restores business logic. Ensure state consistency was maintained during the disabled window.",
                        dedup_key: None,
                    });
                }
                _ => {}
            }
        }

        violations
    }
}
