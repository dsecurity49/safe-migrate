use crate::analysis::mutations::Mutation;
use crate::analysis::state::MutationResult;
use crate::model::relation::Persistence;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::rules::{Rule, RuleContext};

pub struct ConcurrentIndexRule;

impl Rule for ConcurrentIndexRule {
    fn id(&self) -> &'static str {
        "require-concurrent-index"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "Index operations block writes (or both reads and writes) when executed synchronously. Add the CONCURRENTLY keyword."
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        if *context.result() == MutationResult::Skipped {
            // An index that is present in the pre-state still incurs the
            // synchronous DROP INDEX risk even when V6 metadata is too
            // incomplete to mutate it exactly (for example, eligibility for
            // a backing constraint is not serialized).  A truly absent,
            // guarded drop remains a no-op and is correctly suppressed.
            let known_drop_target = matches!(context.mutation(), Mutation::DropIndex(drop)
                if drop.ids.iter().any(|id| context.pre_state().indexes.iter().any(|edge| edge.dependent == *id)));
            if !known_drop_target {
                return vec![];
            }
        }

        let mut violations = Vec::new();

        match context.mutation() {
            Mutation::CreateIndex(create) if !create.concurrently => {
                let (is_temp, is_stale, rows, tx_depth) =
                    match context.pre_state().relations.get(&create.table) {
                        Some(rel) => {
                            let stale = rel.is_stale()
                                && context.state().baseline_relations.contains(&create.table);
                            (
                                rel.persistence == Persistence::Temporary,
                                stale,
                                rel.estimated_rows.unwrap_or(context.config().default_rows),
                                rel.created_at_tx_depth,
                            )
                        }
                        None => (false, true, context.config().default_rows, 0),
                    };

                if is_temp || (tx_depth > 0 && tx_depth <= context.state().local.transactions.len())
                {
                    return violations;
                }

                if is_stale {
                    let key = format!("{}_stale_{}", self.id(), create.table);
                    violations.push(Violation { source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::CreateIndex,
                        object_kind: ObjectKind::Index,
                        object_name: create.id.to_string(),
                        tier: ViolationTier::Tier2,
                        reason: format!("Table {} statistics are stale. Lock evaluations may be inaccurate.", create.table),
                        recipe: "Run ANALYZE to ensure accurate row estimates before structural changes.",
                        dedup_key: Some(key),
                                    sql: None,
                                    fk_dependency_related: false,
                    });
                }

                let tier1_threshold = context.config().rule_tier1_threshold(self.id());
                let tier2_threshold = context.config().rule_tier2_threshold(self.id());

                let tier = if rows >= tier1_threshold {
                    ViolationTier::Tier1
                } else if rows >= tier2_threshold {
                    ViolationTier::Tier2
                } else {
                    ViolationTier::Tier3
                };

                let mut reason = format!("Synchronous index creation on {}", create.table);
                if is_stale {
                    reason.push_str(" [WARNING: Based on offline/stale statistics]");
                }

                violations.push(Violation {
                    source_range: None,
                    rule_id: self.id(),
                    operation_kind: OperationKind::CreateIndex,
                    object_kind: ObjectKind::Index,
                    object_name: create.id.to_string(),
                    tier,
                    reason,
                    recipe: self.recipe(),
                    dedup_key: None,
                    sql: None,
                    fk_dependency_related: false,
                });
            }
            Mutation::DropIndex(drop) if !drop.concurrently => {
                let rule_id = "require-concurrent-drop-index";
                let tier1_threshold = context.config().rule_tier1_threshold(self.id());
                let tier2_threshold = context.config().rule_tier2_threshold(self.id());

                // DROP INDEX classification does not emit a stale-statistics finding.

                for id in &drop.ids {
                    if context.pre_state().relations.is_empty() {
                        let rows = context.config().default_rows;
                        let tier = if rows >= tier1_threshold {
                            ViolationTier::Tier1
                        } else if rows >= tier2_threshold {
                            ViolationTier::Tier2
                        } else {
                            ViolationTier::Tier3
                        };

                        violations.push(Violation {
                            source_range: None,
                            rule_id,
                            operation_kind: OperationKind::DropIndex,
                            object_kind: ObjectKind::Index,
                            object_name: id.to_string(),
                            tier,
                            reason: format!("Synchronous index drop for {}", id),
                            recipe: self.recipe(),
                            dedup_key: None,
                            sql: None,
                            fk_dependency_related: false,
                        });
                    } else {
                        let target_relations = context
                            .pre_state()
                            .indexes
                            .iter()
                            .filter_map(|idx| {
                                (idx.dependent == *id)
                                    .then(|| context.pre_state().relations.get(&idx.referenced))
                                    .flatten()
                            })
                            .collect::<Vec<_>>();
                        if target_relations.is_empty() {
                            let rows = context.config().default_rows;
                            let tier = if rows >= tier1_threshold {
                                ViolationTier::Tier1
                            } else if rows >= tier2_threshold {
                                ViolationTier::Tier2
                            } else {
                                ViolationTier::Tier3
                            };
                            violations.push(Violation {
                                source_range: None,
                                rule_id,
                                operation_kind: OperationKind::DropIndex,
                                object_kind: ObjectKind::Index,
                                object_name: id.to_string(),
                                tier,
                                reason: format!("Synchronous index drop for {}", id),
                                recipe: self.recipe(),
                                dedup_key: None,
                                sql: None,
                                fk_dependency_related: false,
                            });
                        }
                        for rel in target_relations {
                            if rel.persistence == Persistence::Temporary {
                                continue;
                            }

                            let rows = rel.estimated_rows.unwrap_or(context.config().default_rows);
                            let tier = if rows >= tier1_threshold {
                                ViolationTier::Tier1
                            } else if rows >= tier2_threshold {
                                ViolationTier::Tier2
                            } else {
                                ViolationTier::Tier3
                            };

                            let reason = format!("Synchronous index drop for {} on {}", id, rel.id);

                            violations.push(Violation {
                                source_range: None,
                                rule_id,
                                operation_kind: OperationKind::DropIndex,
                                object_kind: ObjectKind::Index,
                                object_name: id.to_string(),
                                tier,
                                reason,
                                recipe: self.recipe(),
                                dedup_key: None,
                                sql: None,
                                fk_dependency_related: false,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
        violations
    }
}
