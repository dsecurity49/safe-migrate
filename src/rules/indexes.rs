// FILE: src/rules/indexes.rs
use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::engine::config::Config;
use crate::model::relation::Persistence;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::rules::Rule;

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

        match mutation {
            Mutation::CreateIndex(create) if !create.concurrently => {
                let (is_temp, is_stale, rows, tx_depth) =
                    match pre_state.relations.get(&create.table) {
                        Some(rel) => {
                            let stale =
                                rel.is_stale() && state.baseline_relations.contains(&create.table);
                            (
                                rel.persistence == Persistence::Temporary,
                                stale,
                                rel.estimated_rows.unwrap_or(config.default_rows),
                                rel.created_at_tx_depth,
                            )
                        }
                        None => (false, true, config.default_rows, 0),
                    };

                if is_temp || (tx_depth > 0 && tx_depth <= state.local.transactions.len()) {
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
                });
            }
            Mutation::DropIndex(drop) if !drop.concurrently => {
                let rule_id = "require-concurrent-drop-index";
                let tier1_threshold = config.rule_tier1_threshold(rule_id);
                let tier2_threshold = config.rule_tier2_threshold(rule_id);

                // BUG-010: Do not check or push stale statistics warning for DROP INDEX.
                // We only perform size evaluation for the drop index violation tier.

                if pre_state.relations.is_empty() {
                    let rows = config.default_rows;
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
                        object_name: drop.id.to_string(),
                        tier,
                        reason: format!("Synchronous index drop for {}", drop.id),
                        recipe: self.recipe(),
                        dedup_key: None,
                        sql: None,
                    });
                } else {
                    let mut target_relations = Vec::new();
                    for idx in &pre_state.indexes {
                        if idx.index_id == drop.id
                            && let Some(rel) = pre_state.relations.get(&idx.relation_id)
                        {
                            target_relations.push(rel);
                        }
                    }

                    if target_relations.is_empty() {
                        let rows = config.default_rows;
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
                            object_name: drop.id.to_string(),
                            tier,
                            reason: format!("Synchronous index drop for {}", drop.id),
                            recipe: self.recipe(),
                            dedup_key: None,
                            sql: None,
                        });
                    } else {
                        for rel in target_relations {
                            if rel.persistence == Persistence::Temporary {
                                continue;
                            }

                            let rows = rel.estimated_rows.unwrap_or(config.default_rows);
                            let tier = if rows >= tier1_threshold {
                                ViolationTier::Tier1
                            } else if rows >= tier2_threshold {
                                ViolationTier::Tier2
                            } else {
                                ViolationTier::Tier3
                            };

                            let reason =
                                format!("Synchronous index drop for {} on {}", drop.id, rel.id);

                            violations.push(Violation {
                                source_range: None,
                                rule_id,
                                operation_kind: OperationKind::DropIndex,
                                object_kind: ObjectKind::Index,
                                object_name: drop.id.to_string(),
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
