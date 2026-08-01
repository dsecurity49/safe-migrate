// FILE: src/rules/constraints.rs
use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::engine::config::Config;
use crate::model::relation::Persistence;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::rules::Rule;

pub struct BlockingConstraintRule;

impl Rule for BlockingConstraintRule {
    fn id(&self) -> &'static str {
        "blocking-constraint"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "Adding a valid CHECK or FOREIGN KEY constraint takes an ACCESS EXCLUSIVE lock and scans the table. Add it as NOT VALID first, then VALIDATE it in a separate transaction."
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
            // Get child table properties
            let (is_temp, mut is_stale, child_rows) = match pre_state.relations.get(&alter.id) {
                Some(rel) => {
                    // BUG FIX: Only mark as stale if it actually existed in the baseline database!
                    let stale = rel.is_stale() && state.baseline_relations.contains(&alter.id);
                    (
                        rel.persistence == Persistence::Temporary,
                        stale,
                        rel.estimated_rows.unwrap_or(config.default_rows),
                    )
                }
                None => (false, true, config.default_rows),
            };

            // If the table being altered is a temp table, schema locks don't block other sessions.
            if is_temp {
                return violations;
            }

            let action_is_relevant = matches!(
                &alter.action,
                AlterTableActionMutation::AddCheckConstraint {
                    not_valid: false,
                    ..
                } | AlterTableActionMutation::AddForeignKey {
                    not_valid: false,
                    ..
                } | AlterTableActionMutation::SetNotNull { .. }
                    | AlterTableActionMutation::AddUniqueConstraint {
                        using_index: None,
                        ..
                    }
                    | AlterTableActionMutation::AddPrimaryKeyConstraint {
                        using_index: None,
                        ..
                    }
                    | AlterTableActionMutation::AddExcludeConstraint { .. }
                    | AlterTableActionMutation::SetStorage { .. }
                    | AlterTableActionMutation::SetAccessMethod
            );
            if !action_is_relevant {
                return violations;
            }

            // Evaluate max locked rows based on the specific action
            let max_locked_rows = match &alter.action {
                AlterTableActionMutation::AddForeignKey { to_table, .. } => {
                    // BUG FIX: Foreign keys lock BOTH the child and the parent table.
                    // We must escalate the lock tier if the parent table is massive, even if the child is empty.
                    let parent_rows = match pre_state.relations.get(to_table) {
                        Some(parent_rel) => {
                            if parent_rel.is_stale() && state.baseline_relations.contains(to_table)
                            {
                                is_stale = true;
                            }
                            parent_rel.estimated_rows.unwrap_or(config.default_rows)
                        }
                        None => {
                            is_stale = true;
                            config.default_rows
                        }
                    };
                    std::cmp::max(child_rows, parent_rows)
                }
                _ => child_rows,
            };

            // FIX: Evaluate the violation tier using granular RuleConfig overrides
            let tier1_threshold = config.rule_tier1_threshold(self.id());
            let tier2_threshold = config.rule_tier2_threshold(self.id());

            // Check if either table is partitioned (partitioned tables have higher lock costs)
            let is_partitioned =
                if let AlterTableActionMutation::AddForeignKey { to_table, .. } = &alter.action {
                    let child_partitioned = pre_state
                        .relations
                        .get(&alter.id)
                        .is_some_and(|rel| rel.partition_type.is_some());
                    let parent_partitioned = pre_state
                        .relations
                        .get(to_table)
                        .is_some_and(|rel| rel.partition_type.is_some());
                    child_partitioned || parent_partitioned
                } else {
                    false
                };

            // Partitioned tables escalate lock severity: use 50% of threshold (floor at 1)
            let (adjusted_tier1, adjusted_tier2) = if is_partitioned {
                (
                    std::cmp::max(1, tier1_threshold / 2),
                    std::cmp::max(1, tier2_threshold / 2),
                )
            } else {
                (tier1_threshold, tier2_threshold)
            };

            let tier = if max_locked_rows >= adjusted_tier1 {
                ViolationTier::Tier1
            } else if max_locked_rows >= adjusted_tier2 {
                ViolationTier::Tier2
            } else {
                ViolationTier::Tier3
            };

            // Emit staleness warning if required (and if it's not going to be completely silent)
            if is_stale && tier != ViolationTier::Tier3 {
                let key = format!("{}_stale_{}", self.id(), alter.id);
                violations.push(Violation { source_range: None,
                    rule_id: self.id(),
                    operation_kind: OperationKind::AddConstraint,
                    object_kind: ObjectKind::Table,
                    object_name: alter.id.to_string(),
                    tier: ViolationTier::Tier2,
                    reason: "Table statistics are offline/stale. Lock evaluations may be inaccurate.".to_string(),
                    recipe: "Run ANALYZE to ensure accurate row estimates before structural changes.",
                    dedup_key: Some(key),
                            sql: None,
                            fk_dependency_related: false,
                });
            }

            // Short-circuit if the locked tables are small enough to be safe
            if tier == ViolationTier::Tier3 {
                return violations;
            }

            match &alter.action {
                AlterTableActionMutation::AddCheckConstraint {
                    constraint_name,
                    not_valid: false,
                } => {
                    let name_str = constraint_name.as_deref().unwrap_or("<unnamed>");
                    let mut reason = format!(
                        "Synchronous CHECK constraint '{}' addition on {}",
                        name_str, alter.id
                    );
                    if is_stale {
                        reason.push_str(" [WARNING: Based on offline/stale statistics]");
                    }

                    violations.push(Violation {
                        source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::AddConstraint,
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
                AlterTableActionMutation::AddForeignKey {
                    constraint_name,
                    not_valid: false,
                    to_table,
                    ..
                } => {
                    let name_str = constraint_name.as_deref().unwrap_or("<unnamed>");

                    let mut reason = format!(
                        "Synchronous FOREIGN KEY constraint '{}' addition locks {} and {}",
                        name_str, alter.id, to_table
                    );
                    if is_partitioned {
                        reason.push_str(" [partitioned tables escalate lock severity]");
                    }
                    if is_stale {
                        reason.push_str(" [WARNING: Based on offline/stale statistics]");
                    }

                    violations.push(Violation {
                        source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::AddConstraint,
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
                AlterTableActionMutation::SetNotNull { column } => {
                    let has_fast_path = pre_state
                        .relations
                        .get(&alter.id)
                        .map(|r| {
                            r.get_column(column)
                                .map(|c| !c.is_nullable)
                                .unwrap_or(false)
                        })
                        .unwrap_or(false);

                    if !has_fast_path {
                        violations.push(Violation {
                            source_range: None,
                            rule_id: self.id(),
                            operation_kind: OperationKind::AddConstraint,
                            object_kind: ObjectKind::Table,
                            object_name: format!("{}.{}", alter.id, column),
                            tier,
                            reason: format!("Synchronous SET NOT NULL on {}.{}", alter.id, column),
                            recipe: "Add CHECK constraint NOT VALID, then VALIDATE separately.",
                            dedup_key: None,
                            sql: None,
                            fk_dependency_related: false,
                        });
                    }
                }
                AlterTableActionMutation::AddUniqueConstraint {
                    using_index: None, ..
                }
                | AlterTableActionMutation::AddPrimaryKeyConstraint {
                    using_index: None, ..
                }
                | AlterTableActionMutation::AddExcludeConstraint { .. } => {
                    let mut reason = format!(
                        "Building an index for a UNIQUE, PRIMARY KEY, or EXCLUDE constraint on {}",
                        alter.id
                    );
                    if is_stale {
                        reason.push_str(" [WARNING: Based on offline/stale statistics]");
                    }

                    violations.push(Violation { source_range: None,
                        rule_id: "blocking-index-constraint",
                        operation_kind: OperationKind::AddConstraint,
                        object_kind: ObjectKind::Table,
                        object_name: alter.id.to_string(),
                        tier,
                        reason,
                        recipe: "Build a UNIQUE index CONCURRENTLY first, then add the constraint USING INDEX.",
                        dedup_key: None,
                                    sql: None,
                                    fk_dependency_related: false,
                    });
                }
                AlterTableActionMutation::SetStorage { column } => {
                    let mut reason = format!(
                        "Changing storage parameter for {}.{} causes a table rewrite",
                        alter.id, column
                    );
                    if is_stale {
                        reason.push_str(" [WARNING: Based on offline/stale statistics]");
                    }

                    violations.push(Violation { source_range: None,
                        rule_id: "table-rewrite-storage",
                        operation_kind: OperationKind::AlterColumnType,
                        object_kind: ObjectKind::Table,
                        object_name: format!("{}.{}", alter.id, column),
                        tier,
                        reason,
                        recipe: "Changing column storage requires an ACCESS EXCLUSIVE lock. Execute during a planned maintenance window.",
                        dedup_key: None,
                                    sql: None,
                                    fk_dependency_related: false,
                    });
                }
                AlterTableActionMutation::SetAccessMethod => {
                    let mut reason = format!(
                        "Changing access method for {} causes a table rewrite",
                        alter.id
                    );
                    if is_stale {
                        reason.push_str(" [WARNING: Based on offline/stale statistics]");
                    }

                    violations.push(Violation { source_range: None,
                        rule_id: "table-rewrite-access-method",
                        operation_kind: OperationKind::AlterColumnType,
                        object_kind: ObjectKind::Table,
                        object_name: alter.id.to_string(),
                        tier,
                        reason,
                        recipe: "Changing table access method requires an ACCESS EXCLUSIVE lock. Execute during a planned maintenance window.",
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
