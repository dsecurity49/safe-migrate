use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::rules::LegacyRule as Rule;

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
        result: &MutationResult,
        _pre_state: &crate::analysis::state::PreState,
        _state: &AnalysisState,
        _config: &Config,
        _cascade: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        if *result == MutationResult::Skipped {
            return vec![];
        }
        let mut violations = Vec::new();

        if let Mutation::AlterTable(alter) = mutation {
            match &alter.action {
                AlterTableActionMutation::DisableTrigger { trigger_name } => {
                    let name = trigger_name.as_deref().unwrap_or("ALL");
                    violations.push(Violation {
                        source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::DisableTrigger,
                        object_kind: ObjectKind::Trigger,
                        object_name: format!("{} on {}", name, alter.id),
                        tier: self.default_tier(),
                        reason: format!("Disabling trigger {} on {}", name, alter.id),
                        recipe: self.recipe(),
                        dedup_key: None,
                        sql: None,
                        fk_dependency_related: false,
                    });
                }
                AlterTableActionMutation::EnableTrigger { trigger_name } => {
                    let name = trigger_name.as_deref().unwrap_or("ALL");
                    violations.push(Violation { source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::EnableTrigger,
                        object_kind: ObjectKind::Trigger,
                        object_name: format!("{} on {}", name, alter.id),
                        tier: ViolationTier::Tier3, // Tier 3 because it is restorative
                        reason: format!("Enabling trigger {} on {}", name, alter.id),
                        recipe: "Re-enabling triggers restores business logic. Ensure state consistency was maintained during the disabled window.",
                        dedup_key: None,
                                    sql: None,
                                    fk_dependency_related: false,
                    });
                }
                _ => {}
            }
        }

        violations
    }
}
