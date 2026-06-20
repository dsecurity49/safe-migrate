// FILE: ./src/rules/partitions.rs

use std::collections::HashMap;
use crate::ast::identifiers::ObjectId;
use crate::rules::Rule;
use crate::analysis::mutations::{Mutation, AlterTableActionMutation};
use crate::analysis::state::{AnalysisState, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier};
use crate::model::relation::{RelationState, Persistence};

pub struct PartitionLockRule;

impl Rule for PartitionLockRule {
    fn id(&self) -> &'static str { "blocking-partition-mutation" }
    fn default_tier(&self) -> ViolationTier { ViolationTier::Tier1 }
    fn recipe(&self) -> &'static str { "Attaching or detaching partitions takes an ACCESS EXCLUSIVE lock on the parent table. Run ATTACH PARTITION concurrently (or manage locks explicitly during low traffic)." }

    fn evaluate(
        &self, 
        mutation: &Mutation, 
        result: &MutationResult,
        pre_relations: &HashMap<ObjectId, RelationState>,
        _state: &AnalysisState, 
        config: &Config
    ) -> Vec<Violation> {
        if *result == MutationResult::Skipped { return vec![]; }

        let mut violations = Vec::new();

        if let Mutation::AlterTable(alter) = mutation {
            match &alter.action {
                AlterTableActionMutation::AttachPartition { .. } |
                AlterTableActionMutation::DetachPartition { .. } => {
                    if let Some(rel) = pre_relations.get(&alter.id) {
                        if rel.persistence == Persistence::Temporary { return violations; }

                        if rel.is_stale() {
                            let key = format!("{}_stale_{}", self.id(), alter.id);
                            violations.push(Violation {
                                rule_id: self.id(),
                                title: format!("Table {} statistics are stale. Lock evaluations may be inaccurate.", alter.id),
                                tier: ViolationTier::Tier2,
                                recipe: "Run ANALYZE to ensure accurate row estimates before structural changes.",
                                dedup_key: Some(key),
                            });
                        }

                        let tier = match rel.estimated_rows {
                            None => ViolationTier::Tier1,
                            Some(r) if r >= config.tier1_threshold_rows => ViolationTier::Tier1,
                            Some(r) if r >= config.tier2_threshold_rows => ViolationTier::Tier2,
                            _ => ViolationTier::Tier3,
                        };

                        if tier != ViolationTier::Tier3 {
                            let op_name = if matches!(alter.action, AlterTableActionMutation::AttachPartition{..}) { "Attaching" } else { "Detaching" };
                            let mut title = format!("{} a partition on heavily utilized parent table {}", op_name, alter.id);
                            if rel.is_stale() { title.push_str(" [WARNING: Based on stale statistics]"); }

                            violations.push(Violation {
                                rule_id: self.id(),
                                title,
                                tier,
                                recipe: self.recipe(),
                                dedup_key: None,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        violations
    }
}
