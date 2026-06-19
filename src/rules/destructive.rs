// FILE: ./src/rules/destructive.rs                  
use std::collections::HashMap;
use crate::ast::identifiers::ObjectId;
use crate::model::relation::RelationState;
use crate::rules::Rule;
use crate::analysis::mutations::{Mutation, AlterTableActionMutation};
use crate::analysis::state::{LocalState, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier};

pub struct CascadingDropRule;

impl Rule for CascadingDropRule {
    fn id(&self) -> &'static str { "destructive-cascade" }
    fn default_tier(&self) -> ViolationTier { ViolationTier::Tier1 }
    fn recipe(&self) -> &'static str { "Avoid CASCADE on DROP TABLE in production. Handle dependencies explicitly." }

    fn evaluate(
        &self, 
        mutation: &Mutation, 
        result: &MutationResult,
        _pre_relations: &HashMap<ObjectId, RelationState>,
        state: &LocalState, 
        _config: &Config
    ) -> Vec<Violation> {
        // Safe to skip: If the drop was a no-op, no cascade happened.
        if *result == MutationResult::Skipped {
            return vec![];
        }

        let mut violations = Vec::new();

        if let Mutation::DropTable(drop) = mutation {
            if drop.cascade {
                let fks = state.graph.is_referenced_by_fk(&drop.id);
                let views = state.graph.is_referenced_by_view(&drop.id);

                if !fks.is_empty() || !views.is_empty() {
                    violations.push(Violation {
                        rule_id: self.id(),
                        title: format!("DROP TABLE {} CASCADE affects active dependent objects", drop.id),
                        tier: self.default_tier(),
                        recipe: self.recipe(),
                        dedup_key: None,
                    });
                }
            }
        }
        violations
    }
}

pub struct SizeAwareAddColumnRule;

impl Rule for SizeAwareAddColumnRule {
    fn id(&self) -> &'static str { "size-aware-add-column" }
    fn default_tier(&self) -> ViolationTier { ViolationTier::Tier1 }
    fn recipe(&self) -> &'static str { "Adding a column with a volatile DEFAULT to a large table forces an ACCESS EXCLUSIVE rewrite. Use a multi-step migration." }

    fn evaluate(
        &self, 
        mutation: &Mutation, 
        result: &MutationResult,
        pre_relations: &HashMap<ObjectId, RelationState>,
        _state: &LocalState, 
        config: &Config
    ) -> Vec<Violation> {
        // Safe to skip: if the column already existed (IF NOT EXISTS), no table rewrite happens.
        if *result == MutationResult::Skipped {
            return vec![];
        }

        let mut violations = Vec::new();
        
        if let Mutation::AlterTable(alter) = mutation {
            if let AlterTableActionMutation::AddColumn { default: Some(def), .. } = &alter.action {
                if def.is_volatile() {
                    // Extract PRE-mutation state (O(1) clone provided by engine loop)
                    if let Some(rel) = pre_relations.get(&alter.id) {
                        
                        // 1. Independent Staleness Check (Deduplicated)
                        if rel.is_stale() {
                            let key = format!("{}_stale_{}", self.id(), alter.id);
                            violations.push(Violation {
                                rule_id: self.id(),
                                title: format!("Table {} statistics are stale. Lock evaluations may be inaccurate.", alter.id),
                                tier: ViolationTier::Tier2,
                                recipe: "Run ANALYZE to ensure accurate TOAST width and row estimates before structural changes.",
                                dedup_key: Some(key),
                            });
                        }

                        // 2. Size and TOAST Evaluation
                        let has_wide_columns = rel.columns.iter()
                            .any(|c| c.avg_width.unwrap_or(0) >= config.toast_width_threshold_bytes);

                        let mut tier = match rel.estimated_rows {
                            None => ViolationTier::Tier1, // Unknown -> Fail closed
                            Some(r) if r >= config.tier1_threshold_rows => ViolationTier::Tier1,
                            Some(r) if r >= config.tier2_threshold_rows => ViolationTier::Tier2,
                            _ => ViolationTier::Tier3,
                        };

                        // Escalate severity if TOAST reconstruction is likely
                        if has_wide_columns && tier == ViolationTier::Tier2 {
                            tier = ViolationTier::Tier1;
                        }

                        if tier != ViolationTier::Tier3 {
                            let mut title = format!("Adding volatile default to {} triggers a table rewrite", alter.id);
                            
                            // Contextualize the output based on heuristics
                            if has_wide_columns && tier == ViolationTier::Tier1 {
                                title.push_str(" (Escalated due to wide TOAST columns)");
                            }
                            if rel.is_stale() {
                                title.push_str(" [WARNING: Based on stale statistics]");
                            }

                            violations.push(Violation {
                                rule_id: self.id(),
                                title,
                                tier,
                                recipe: self.recipe(),
                                dedup_key: None, // Main violation is evaluated per statement, not deduped
                            });
                        }
                    }
                }
            }
        }
        violations
    }
}
