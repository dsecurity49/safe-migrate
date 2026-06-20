// FILE: src/rules/indexes.rs
use std::collections::HashMap;
use crate::ast::identifiers::ObjectId;
use crate::rules::Rule;
use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, MutationResult, CascadeResult};
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier};
use crate::model::relation::{RelationState, Persistence};

pub struct ConcurrentIndexRule;

impl Rule for ConcurrentIndexRule {
    fn id(&self) -> &'static str { "require-concurrent-index" }
    fn default_tier(&self) -> ViolationTier { ViolationTier::Tier1 }
    fn recipe(&self) -> &'static str { "Index operations block writes (or both reads and writes) when executed synchronously. Add the CONCURRENTLY keyword." }

    fn evaluate(
        &self,
        mutation: &Mutation,
        result: &MutationResult,
        pre_relations: &HashMap<ObjectId, RelationState>,
        _state: &AnalysisState,
        config: &Config,
        _cascade: Option<&CascadeResult>
    ) -> Vec<Violation> {
        if *result == MutationResult::Skipped { return vec![]; }

        let mut violations = Vec::new();

        match mutation {
            Mutation::CreateIndex(create) => {
                if !create.concurrently {
                    let (is_temp, is_stale, rows) = match pre_relations.get(&create.table) {
                        Some(rel) => {
                            (rel.persistence == Persistence::Temporary, rel.is_stale(), rel.estimated_rows.unwrap_or(config.default_rows))
                        }
                        None => {
                            (false, false, config.default_rows)
                        }
                    };

                    if is_temp { return violations; }

                    if is_stale {
                        let key = format!("{}_stale_{}", self.id(), create.table);
                        violations.push(Violation {
                            rule_id: self.id(),
                            title: format!("Table {} statistics are stale. Lock evaluations may be inaccurate.", create.table),
                            tier: ViolationTier::Tier2,
                            recipe: "Run ANALYZE to ensure accurate row estimates before structural changes.",
                            dedup_key: Some(key),
                        });
                    }

                    let tier = if rows >= config.tier1_threshold_rows { ViolationTier::Tier1 }
                               else if rows >= config.tier2_threshold_rows { ViolationTier::Tier2 }
                               else { ViolationTier::Tier3 };

                    if tier != ViolationTier::Tier3 {
                        let mut title = format!("Synchronous index creation on {}", create.table);
                        if is_stale { title.push_str(" [WARNING: Based on stale statistics]"); }

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
            Mutation::DropIndex(drop) => {
                if !drop.concurrently {
                    // Engine loop already resolved the N-to-many parent tables and pushed them into pre_relations
                    if pre_relations.is_empty() {
                        let rows = config.default_rows;
                        let tier = if rows >= config.tier1_threshold_rows { ViolationTier::Tier1 }
                                   else if rows >= config.tier2_threshold_rows { ViolationTier::Tier2 }
                                   else { ViolationTier::Tier3 };
                                   
                        if tier != ViolationTier::Tier3 {
                            violations.push(Violation {
                                rule_id: "require-concurrent-drop-index",
                                title: format!("Synchronous index drop for {}", drop.id),
                                tier,
                                recipe: self.recipe(),
                                dedup_key: None,
                            });
                        }
                    } else {
                        for rel in pre_relations.values() {
                            if rel.persistence == Persistence::Temporary { continue; }

                            if rel.is_stale() {
                                let key = format!("{}_stale_{}", self.id(), rel.id);
                                violations.push(Violation {
                                    rule_id: self.id(),
                                    title: format!("Table {} statistics are stale. Lock evaluations may be inaccurate.", rel.id),
                                    tier: ViolationTier::Tier2,
                                    recipe: "Run ANALYZE to ensure accurate row estimates before structural changes.",
                                    dedup_key: Some(key),
                                });
                            }

                            let rows = rel.estimated_rows.unwrap_or(config.default_rows);
                            let tier = if rows >= config.tier1_threshold_rows { ViolationTier::Tier1 }
                                       else if rows >= config.tier2_threshold_rows { ViolationTier::Tier2 }
                                       else { ViolationTier::Tier3 };

                            if tier != ViolationTier::Tier3 {
                                let mut title = format!("Synchronous index drop for {} on {}", drop.id, rel.id);
                                if rel.is_stale() { title.push_str(" [WARNING: Based on stale statistics]"); }

                                violations.push(Violation {
                                    rule_id: "require-concurrent-drop-index",
                                    title,
                                    tier,
                                    recipe: self.recipe(),
                                    dedup_key: None,
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        violations
    }
}
