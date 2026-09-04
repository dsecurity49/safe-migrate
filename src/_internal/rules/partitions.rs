use crate::_internal::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::_internal::analysis::state::MutationResult;
use crate::_internal::model::relation::Persistence;
use crate::_internal::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::_internal::rules::{BASELINE_STATS_CAPABILITIES, Rule, RuleCapability, RuleContext};

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

    fn required_capabilities(&self) -> &'static [RuleCapability] {
        BASELINE_STATS_CAPABILITIES
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        if *context.result() == MutationResult::Skipped {
            return vec![];
        }

        let mut violations = Vec::new();

        if let Mutation::AlterTable(alter) = context.mutation() {
            match &alter.action {
                AlterTableActionMutation::AttachPartition { .. }
                | AlterTableActionMutation::DetachPartition { .. } => {
                    let (is_temp, is_stale, rows, is_hash_partitioned) =
                        match context.pre_state().relations.get(&alter.id) {
                            Some(rel) => {
                                let stale = rel.is_stale()
                                    && context.state().baseline_relation_is_known(&alter.id);
                                let is_hash = rel
                                    .partition_type
                                    .as_ref()
                                    .is_some_and(|pt| pt.to_uppercase().contains("HASH"));
                                (
                                    rel.persistence == Persistence::Temporary,
                                    stale,
                                    rel.estimated_rows.unwrap_or(context.config().default_rows),
                                    is_hash,
                                )
                            }
                            None => (false, true, context.config().default_rows, false),
                        };

                    if is_temp {
                        return violations;
                    }

                    let op_kind = if matches!(
                        alter.action,
                        AlterTableActionMutation::AttachPartition { .. }
                    ) {
                        OperationKind::AttachPartition
                    } else {
                        OperationKind::DetachPartition
                    };

                    if is_stale {
                        let key = format!("{}_stale_{}", self.id(), alter.id);
                        violations.push(Violation { source_range: None,
                            rule_id: self.id(),
                            operation_kind: op_kind.clone(),
                            object_kind: ObjectKind::Table,
                            object_name: alter.id.to_string(),
                            tier: ViolationTier::Tier2,
                            reason: format!("Table {} statistics are stale. Lock evaluations may be inaccurate.", alter.id),
                            recipe: "Run ANALYZE to ensure accurate row estimates before structural changes.",
                            dedup_key: Some(key),
                                            sql: None,
                                            fk_dependency_related: false,
                        });
                    }

                    let tier1_threshold = context.config().rule_tier1_threshold(self.id());
                    let tier2_threshold = context.config().rule_tier2_threshold(self.id());

                    let (adjusted_tier1, adjusted_tier2) = if is_hash_partitioned {
                        (tier1_threshold / 2, tier2_threshold / 2)
                    } else {
                        (tier1_threshold, tier2_threshold)
                    };

                    let tier = if rows >= adjusted_tier1 {
                        ViolationTier::Tier1
                    } else if rows >= adjusted_tier2 {
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
                        let mut reason = format!(
                            "{} a partition on heavily utilized parent table {}",
                            op_name, alter.id
                        );
                        if is_hash_partitioned {
                            reason.push_str(" [HASH partitioning escalates lock severity]");
                        }
                        if is_stale {
                            reason.push_str(" [WARNING: Based on offline/stale statistics]");
                        }

                        violations.push(Violation {
                            source_range: None,
                            rule_id: self.id(),
                            operation_kind: op_kind,
                            object_kind: ObjectKind::Table,
                            object_name: alter.id.to_string(),
                            tier,
                            reason,
                            recipe: self.recipe(),
                            dedup_key: None,
                            sql: None,
                            fk_dependency_related: false,
                        });
                    }
                }
                _ => {}
            }
        }
        violations
    }
}

pub struct PartitionStrategyMismatchRule;

impl Rule for PartitionStrategyMismatchRule {
    fn id(&self) -> &'static str {
        "partition-strategy-mismatch"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "Ensure the partition being attached matches the parent table's partition strategy (RANGE/LIST/HASH). Mismatched strategies will cause ATTACH PARTITION to fail."
    }

    fn required_capabilities(&self) -> &'static [RuleCapability] {
        crate::_internal::rules::BASELINE_RELATION_CAPABILITIES
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        if *context.result() == MutationResult::Skipped {
            return vec![];
        }

        let mut violations = Vec::new();

        if let Mutation::AlterTable(alter) = context.mutation()
            && let AlterTableActionMutation::AttachPartition { child, strategy } = &alter.action
        {
            let parent_partition_type = context
                .pre_state()
                .relations
                .get(&alter.id)
                .and_then(|rel| rel.partition_type.clone());

            if let Some(parent_type) = parent_partition_type {
                let normalized = |value: &str| {
                    value
                        .to_uppercase()
                        .split('(')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_string()
                };
                let parent_kind = normalized(&parent_type);
                let child_kind = context
                    .pre_state()
                    .relations
                    .get(child)
                    .and_then(|rel| rel.partition_type.as_deref())
                    .map(normalized);
                let bound_kind = strategy.as_deref().map(normalized);
                let mismatch_kind = child_kind
                    .filter(|kind| kind != &parent_kind)
                    .or_else(|| bound_kind.filter(|kind| kind != &parent_kind));

                if let Some(part_type) = mismatch_kind {
                    violations.push(Violation {
                        source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::AttachPartition,
                        object_kind: ObjectKind::Table,
                        object_name: format!("{} -> {}", child, alter.id),
                        tier: self.default_tier(),
                        reason: format!(
                            "ATTACH PARTITION: partition {} is {} but parent {} is {} (mismatch)",
                            child, part_type, alter.id, parent_type
                        ),
                        recipe: self.recipe(),
                        dedup_key: None,
                        sql: None,
                        fk_dependency_related: false,
                    });
                }
            }
        }
        violations
    }
}
