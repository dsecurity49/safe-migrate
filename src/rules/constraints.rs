// FILE: ./src/rules/constraints.rs                  
use std::collections::HashMap;
use crate::ast::identifiers::ObjectId;
use crate::rules::Rule;                              
use crate::analysis::mutations::{Mutation, AlterTableActionMutation};                                     
use crate::analysis::state::{LocalState, MutationResult};           
use crate::engine::config::Config;                   
use crate::report::violations::{Violation, ViolationTier};                                                
use crate::model::relation::{RelationState, Persistence};

pub struct BlockingConstraintRule;
                                                     
impl Rule for BlockingConstraintRule {                   
    fn id(&self) -> &'static str { "blocking-constraint" }
    fn default_tier(&self) -> ViolationTier { ViolationTier::Tier1 }
    fn recipe(&self) -> &'static str { "Adding a valid CHECK or FOREIGN KEY constraint takes an ACCESS EXCLUSIVE lock and scans the table. Add it as NOT VALID first, then VALIDATE it in a separate transaction." }

    fn evaluate(
        &self, 
        mutation: &Mutation, 
        result: &MutationResult,
        pre_relations: &HashMap<ObjectId, RelationState>,
        _state: &LocalState, 
        config: &Config
    ) -> Vec<Violation> {
        if *result == MutationResult::Skipped { return vec![]; }

        let mut violations = Vec::new();

        if let Mutation::AlterTable(alter) = mutation {
            // O(1) Pre-State lookup guarantees we don't see the constraint we just added
            if let Some(rel) = pre_relations.get(&alter.id) {
                if rel.persistence == Persistence::Temporary { return violations; }

                // Staleness check
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
                    None => ViolationTier::Tier1, // Fail-closed
                    Some(r) if r >= config.tier1_threshold_rows => ViolationTier::Tier1,
                    Some(r) if r >= config.tier2_threshold_rows => ViolationTier::Tier2,
                    _ => ViolationTier::Tier3,
                };

                if tier == ViolationTier::Tier3 { return violations; }

                match &alter.action {
                    AlterTableActionMutation::AddCheckConstraint { not_valid: false } |
                    AlterTableActionMutation::AddForeignKey { not_valid: false, .. } => {
                        let mut title = format!("Synchronous constraint addition on {}", alter.id);
                        if rel.is_stale() { title.push_str(" [WARNING: Based on stale statistics]"); }

                        violations.push(Violation {
                            rule_id: self.id(),
                            title,
                            tier,
                            recipe: self.recipe(),
                            dedup_key: None, // Statements are evaluated linearly; no dedup needed
                        });
                    }
                    AlterTableActionMutation::AddUniqueConstraint |
                    AlterTableActionMutation::AddPrimaryKeyConstraint => {
                        let mut title = format!("Adding a UNIQUE or PRIMARY KEY constraint to {}", alter.id);
                        if rel.is_stale() { title.push_str(" [WARNING: Based on stale statistics]"); }

                        violations.push(Violation {
                            rule_id: "blocking-index-constraint",
                            title,
                            tier,
                            recipe: "Build a UNIQUE index CONCURRENTLY first, then add the constraint USING INDEX.",
                            dedup_key: None,
                        });
                    }
                    _ => {}
                }
            }
        }
        violations
    }
}
