// FILE: src/rules/partitions.rs
use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::engine::config::Config;
use crate::model::relation::Persistence;
use crate::report::violations::{Violation, ViolationTier};
use crate::rules::Rule;

pub struct PartitionLockRule;

impl Rule for PartitionLockRule {
    fn id(&self) -> &'static str {
        "blocking-partition-mutation"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "Attaching or detaching partitions takes an ACCESS EXCLUSIVE lock on the parent table. Run ATTACH PARTITION concurrently (or manage locks explicitly during low traffic)."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        result: &MutationResult,
        pre_state: &crate::analysis::state::PreState,
        state: &AnalysisState,
        config: &Config,
        _cascade: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        if *result == MutationResult::Skipped {
            return vec![];
        }

        let mut violations = Vec::new();

        if let Mutation::AlterTable(alter) = mutation {
            match &alter.action {
                AlterTableActionMutation::AttachPartition { .. }
                | AlterTableActionMutation::DetachPartition { .. } => {
                    let (is_temp, is_stale, rows) = match pre_state.relations.get(&alter.id) {
                        Some(rel) => {
                            let stale =
                                rel.is_stale() && state.baseline_relations.contains(&alter.id);
                            (
                                rel.persistence == Persistence::Temporary,
                                stale,
                                rel.estimated_rows.unwrap_or(config.default_rows),
                            )
                        }
                        None => (false, true, config.default_rows),
                    };

                    if is_temp {
                        return violations;
                    }

                    if is_stale {
                        let key = format!("{}_stale_{}", self.id(), alter.id);
                        violations.push(Violation {
                            rule_id: self.id(),
                            title: format!("Table {} statistics are stale. Lock evaluations may be inaccurate.", alter.id),
                            tier: ViolationTier::Tier2,
                            recipe: "Run ANALYZE to ensure accurate row estimates before structural changes.",
                            dedup_key: Some(key),
                        });
                    }

                    let tier1_threshold = config.rule_tier1_threshold(self.id());
                    let tier2_threshold = config.rule_tier2_threshold(self.id());

                    let tier = if rows >= tier1_threshold {
                        ViolationTier::Tier1
                    } else if rows >= tier2_threshold {
                        ViolationTier::Tier2
                    } else {
                        ViolationTier::Tier3
                    };

                    if tier != ViolationTier::Tier3 {
                        let op_name = if matches!(
                            alter.action,
                            AlterTableActionMutation::AttachPartition { .. }
                        ) {
                            "Attaching"
                        } else {
                            "Detaching"
                        };
                        let mut title = format!(
                            "{} a partition on heavily utilized parent table {}",
                            op_name, alter.id
                        );
                        if is_stale {
                            title.push_str(" [WARNING: Based on offline/stale statistics]");
                        }

                        violations.push(Violation {
                            rule_id: self.id(),
                            title,
                            tier,
                            recipe: self.recipe(),
                            dedup_key: None,
                        });
                    }
                }
                _ => {}
            }
        }
        violations
    }
}
