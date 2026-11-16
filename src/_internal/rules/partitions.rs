use crate::_internal::analysis::mutations::{AlterTableActionMutation, Mutation};

use crate::_internal::model::relation::Persistence;
use crate::_internal::report::violations::{ObjectKind, Violation, ViolationTier};
use crate::_internal::rules::{BASELINE_STATS_CAPABILITIES, Rule, RuleCapability, RuleContext};

pub(crate) struct PartitionLockRule;

impl Rule for PartitionLockRule {
    fn id(&self) -> &'static str {
        "blocking-partition-mutation"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "Attaching a partition scans the partition and detaching can lock the parent. Use DETACH PARTITION CONCURRENTLY where supported and manage locks during low traffic."
    }

    fn required_capabilities(&self) -> &'static [RuleCapability] {
        BASELINE_STATS_CAPABILITIES
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        let Mutation::AlterTable(alter) = context.mutation() else {
            return Vec::new();
        };
        match &alter.action {
            AlterTableActionMutation::AttachPartition { child, .. } => {
                self.evaluate_attach(context, alter, child)
            }
            AlterTableActionMutation::DetachPartition { .. } => {
                self.evaluate_detach(context, alter)
            }
            _ => Vec::new(),
        }
    }
}

impl PartitionLockRule {
    /// Size an attach by the new partition plus every default partition it
    /// must scan; HASH parents use half the normal thresholds.
    fn evaluate_attach(
        &self,
        context: &RuleContext<'_>,
        alter: &crate::_internal::analysis::mutations::AlterTable,
        child: &crate::_internal::ast::identifiers::ObjectId,
    ) -> Vec<Violation> {
        let parent = &alter.id;
        let (is_temp, is_hash_partitioned) = match context.pre_state().relations.get(parent) {
            Some(relation) => (
                relation.persistence == Persistence::Temporary,
                relation
                    .partition_type
                    .as_ref()
                    .is_some_and(|kind| kind.to_uppercase().contains("HASH")),
            ),
            None => (false, false),
        };
        if is_temp {
            return Vec::new();
        }

        let mut total = 0u64;
        let mut sources = Vec::new();
        let mut stale_leaves = Vec::new();
        if accumulate_scan_rows(context, child, &mut total, &mut stale_leaves) {
            sources.push(format!("partition {child}"));
        }
        for default in context.state().default_partitions_of(parent) {
            if &default == child {
                continue;
            }
            if accumulate_scan_rows(context, &default, &mut total, &mut stale_leaves) {
                sources.push(format!("default partition {default}"));
            }
        }
        if sources.is_empty() {
            return Vec::new();
        }

        let mut violations = Vec::new();
        if !stale_leaves.is_empty() {
            violations.push(self.stale_violation(
                parent,
                format!(
                    "Statistics for {} are stale or missing. Lock evaluations may be inaccurate.",
                    join_names(&stale_leaves)
                ),
            ));
        }

        let tier = self.tier_for(context, total, is_hash_partitioned);
        if tier == ViolationTier::Tier3 {
            return violations;
        }

        let mut reason = format!(
            "Attaching {} to {} scans {} rows",
            sources.join(" and "),
            parent,
            total
        );
        if is_hash_partitioned {
            reason.push_str(" [HASH partitioning escalates lock severity]");
        }
        if !stale_leaves.is_empty() {
            reason.push_str(" [WARNING: Based on offline/stale statistics]");
        }
        violations.push(Violation {
            source_range: None,
            rule_id: self.id(),
            object_kind: ObjectKind::Table,
            object_name: parent.to_string(),
            tier,
            reason,
            recipe: self.recipe(),
            dedup_key: None,
            sql: None,
        });
        violations
    }

    /// Tiers a partition detach by parent size and hash partitioning;
    /// temporary parents are skipped.
    fn evaluate_detach(
        &self,
        context: &RuleContext<'_>,
        alter: &crate::_internal::analysis::mutations::AlterTable,
    ) -> Vec<Violation> {
        let parent = &alter.id;
        let (is_temp, is_stale, rows, is_hash_partitioned) =
            match context.pre_state().relations.get(parent) {
                Some(relation) => {
                    let stale =
                        relation.is_stale() && context.state().baseline_relation_is_known(parent);
                    let is_hash = relation
                        .partition_type
                        .as_ref()
                        .is_some_and(|kind| kind.to_uppercase().contains("HASH"));
                    (
                        relation.persistence == Persistence::Temporary,
                        stale,
                        relation
                            .estimated_rows
                            .unwrap_or(context.config().default_rows),
                        is_hash,
                    )
                }
                None => (false, true, context.config().default_rows, false),
            };
        if is_temp {
            return Vec::new();
        }

        let mut violations = Vec::new();
        if is_stale {
            violations.push(self.stale_violation(
                parent,
                format!("Table {parent} statistics are stale. Lock evaluations may be inaccurate."),
            ));
        }

        let tier = self.tier_for(context, rows, is_hash_partitioned);
        if tier == ViolationTier::Tier3 {
            return violations;
        }

        let mut reason = format!("Detaching a partition on heavily utilized parent table {parent}");
        if is_hash_partitioned {
            reason.push_str(" [HASH partitioning escalates lock severity]");
        }
        if is_stale {
            reason.push_str(" [WARNING: Based on offline/stale statistics]");
        }
        violations.push(Violation {
            source_range: None,
            rule_id: self.id(),
            object_kind: ObjectKind::Table,
            object_name: parent.to_string(),
            tier,
            reason,
            recipe: self.recipe(),
            dedup_key: None,
            sql: None,
        });
        violations
    }

    fn stale_violation(
        &self,
        parent: &crate::_internal::ast::identifiers::ObjectId,
        reason: String,
    ) -> Violation {
        Violation {
            source_range: None,
            rule_id: self.id(),
            object_kind: ObjectKind::Table,
            object_name: parent.to_string(),
            tier: ViolationTier::Tier2,
            reason,
            recipe: "Run ANALYZE to ensure accurate row estimates before structural changes.",
            dedup_key: Some(format!("{}_stale_{}", self.id(), parent)),
            sql: None,
        }
    }

    fn tier_for(
        &self,
        context: &RuleContext<'_>,
        rows: u64,
        is_hash_partitioned: bool,
    ) -> ViolationTier {
        let tier1_threshold = context.config().rule_tier1_threshold(self.id());
        let tier2_threshold = context.config().rule_tier2_threshold(self.id());
        let (tier1_threshold, tier2_threshold) = if is_hash_partitioned {
            (tier1_threshold / 2, tier2_threshold / 2)
        } else {
            (tier1_threshold, tier2_threshold)
        };
        if rows >= tier1_threshold {
            ViolationTier::Tier1
        } else if rows >= tier2_threshold {
            ViolationTier::Tier2
        } else {
            ViolationTier::Tier3
        }
    }
}

/// Accumulate the rows a partition scan touches, using default estimates for
/// leaves absent from the baseline and recording stale or missing statistics.
fn accumulate_scan_rows(
    context: &RuleContext<'_>,
    root: &crate::_internal::ast::identifiers::ObjectId,
    total: &mut u64,
    stale_leaves: &mut Vec<crate::_internal::ast::identifiers::ObjectId>,
) -> bool {
    let leaves = context.state().partition_scan_relations(root);
    if leaves.is_empty() {
        return false;
    }
    for leaf in leaves {
        match context.pre_state().relations.get(&leaf) {
            Some(relation) => {
                *total = total.saturating_add(
                    relation
                        .estimated_rows
                        .unwrap_or(context.config().default_rows),
                );
                if context.state().baseline_relation_is_known(&leaf)
                    && (relation.is_stale() || relation.estimated_rows.is_none())
                {
                    stale_leaves.push(leaf);
                }
            }
            None => {
                *total = total.saturating_add(context.config().default_rows);
                stale_leaves.push(leaf);
            }
        }
    }
    true
}

fn join_names(ids: &[crate::_internal::ast::identifiers::ObjectId]) -> String {
    const MAX_NAMES: usize = 3;
    let mut names = ids
        .iter()
        .take(MAX_NAMES)
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if ids.len() > MAX_NAMES {
        names.push(format!("and {} more", ids.len() - MAX_NAMES));
    }
    names.join(", ")
}

pub(crate) struct PartitionStrategyMismatchRule;

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
        let mut violations = Vec::new();

        if let Mutation::AlterTable(alter) = context.mutation()
            && let AlterTableActionMutation::AttachPartition {
                child, strategy, ..
            } = &alter.action
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
                    });
                }
            }
        }
        violations
    }
}
