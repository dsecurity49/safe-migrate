use crate::_internal::analysis::mutations::{Mutation, ReindexTargetMutation};

use crate::_internal::model::relation::Persistence;
use crate::_internal::report::violations::{ObjectKind, Violation, ViolationTier};
use crate::_internal::rules::{
    BASELINE_STATS_DEPENDENCY_CAPABILITIES, Rule, RuleCapability, RuleContext,
};

pub(crate) struct ConcurrentIndexRule;

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

    fn required_capabilities(&self) -> &'static [RuleCapability] {
        BASELINE_STATS_DEPENDENCY_CAPABILITIES
    }

    fn evaluates_when_unresolved(&self) -> bool {
        // A DROP INDEX on a known target is synchronous regardless of catalog
        // completeness, so the risk stands even when the post-state is unknown.
        true
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        if context.result().is_unresolved() {
            // An index that is present in the pre-state still incurs the
            // synchronous DROP INDEX risk even when catalog metadata is too
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
                                && context.state().baseline_relation_is_known(&create.table);
                            (
                                rel.persistence == Persistence::Temporary,
                                stale,
                                rel.estimated_rows.unwrap_or(context.config().default_rows),
                                rel.created_at_tx_depth,
                            )
                        }
                        None => (false, true, context.config().default_rows, 0),
                    };

                if is_temp || (tx_depth > 0 && tx_depth <= context.state().transaction_depth()) {
                    return violations;
                }

                if is_stale {
                    let key = format!("{}_stale_{}", self.id(), create.table);
                    violations.push(Violation { source_range: None,
                        rule_id: self.id(),

                        object_kind: ObjectKind::Index,
                        object_name: create.id.to_string(),
                        tier: ViolationTier::Tier2,
                        reason: format!("Table {} statistics are stale. Lock evaluations may be inaccurate.", create.table),
                        recipe: "Run ANALYZE to ensure accurate row estimates before structural changes.",
                        dedup_key: Some(key),
                                    sql: None,

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

                    object_kind: ObjectKind::Index,
                    object_name: create.id.to_string(),
                    tier,
                    reason,
                    recipe: self.recipe(),
                    dedup_key: None,
                    sql: None,
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

                            object_kind: ObjectKind::Index,
                            object_name: id.to_string(),
                            tier,
                            reason: format!("Synchronous index drop for {}", id),
                            recipe: self.recipe(),
                            dedup_key: None,
                            sql: None,
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

                                object_kind: ObjectKind::Index,
                                object_name: id.to_string(),
                                tier,
                                reason: format!("Synchronous index drop for {}", id),
                                recipe: self.recipe(),
                                dedup_key: None,
                                sql: None,
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

                                object_kind: ObjectKind::Index,
                                object_name: id.to_string(),
                                tier,
                                reason,
                                recipe: self.recipe(),
                                dedup_key: None,
                                sql: None,
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

pub(crate) struct RequireConcurrentReindexRule;

impl Rule for RequireConcurrentReindexRule {
    fn id(&self) -> &'static str {
        "require-concurrent-reindex"
    }

    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }

    fn recipe(&self) -> &'static str {
        "Reindexing a table or index without `concurrently` holds a lock that blocks writes (and reads, for some targets) for the duration. Use `CONCURRENTLY` where PostgreSQL allows it."
    }

    fn required_capabilities(&self) -> &'static [RuleCapability] {
        &[]
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        let mut violations = Vec::new();

        if let Mutation::Reindex {
            target,
            concurrently,
        } = context.mutation()
            && !*concurrently
        {
            violations.extend(Self::evaluate_target(context, target.as_ref()));
        }

        violations
    }
}

impl RequireConcurrentReindexRule {
    /// Flag a non-concurrent REINDEX. Targets where PostgreSQL rejects
    /// `CONCURRENTLY` are exempt, since there is no correct alternative.
    fn evaluate_target(
        context: &RuleContext<'_>,
        target: Option<&ReindexTargetMutation>,
    ) -> Vec<Violation> {
        let Some(target) = target else {
            return vec![Violation {
                source_range: None,
                rule_id: RequireConcurrentReindexRule.id(),

                object_kind: ObjectKind::Unknown,
                object_name: "unknown".to_string(),
                tier: ViolationTier::Tier1,
                reason: "Synchronous REINDEX with no resolvable target".to_string(),
                recipe: RequireConcurrentReindexRule.recipe(),
                dedup_key: None,
                sql: None,
            }];
        };

        // REINDEX SYSTEM does not accept CONCURRENTLY, so demanding it is a false positive.
        if matches!(target, ReindexTargetMutation::System(_)) {
            return vec![];
        }

        // A temporary relation cannot be reindexed concurrently; the synchronous
        // form is the only legal statement, so there is nothing to report.
        if let ReindexTargetMutation::Table(id) | ReindexTargetMutation::Index(id) = target
            && let Some(rel) = context.pre_state().relations.get(id)
            && rel.persistence == Persistence::Temporary
        {
            return vec![];
        }

        if let ReindexTargetMutation::Index(id) = target
            && context.state().index_backs_exclusion_constraint(id)
        {
            return vec![];
        }

        let object_kind = match target {
            ReindexTargetMutation::Database(_) | ReindexTargetMutation::System(_) => {
                ObjectKind::Database
            }
            ReindexTargetMutation::Schema(_) => ObjectKind::Schema,
            ReindexTargetMutation::Table(_) => ObjectKind::Table,
            ReindexTargetMutation::Index(_) => ObjectKind::Index,
        };
        let target_name = target.object_name();

        vec![Violation {
            source_range: None,
            rule_id: RequireConcurrentReindexRule.id(),

            object_kind,
            object_name: target_name.clone(),
            tier: ViolationTier::Tier1,
            reason: format!("Synchronous REINDEX on {target_name}"),
            recipe: RequireConcurrentReindexRule.recipe(),
            dedup_key: Some(format!(
                "{}_{}",
                RequireConcurrentReindexRule.id(),
                target_name
            )),
            sql: None,
        }]
    }
}
