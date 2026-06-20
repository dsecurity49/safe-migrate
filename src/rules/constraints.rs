// FILE: src/rules/constraints.rs
use std::collections::HashMap;
use crate::ast::identifiers::ObjectId;
use crate::rules::Rule;
use crate::analysis::mutations::{Mutation, AlterTableActionMutation};
use crate::analysis::state::{AnalysisState, MutationResult, CascadeResult};
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
        _state: &AnalysisState,
        config: &Config,
        _cascade: Option<&CascadeResult>
    ) -> Vec<Violation> {
        if *result == MutationResult::Skipped { return vec![]; }

        let mut violations = Vec::new();

        if let Mutation::AlterTable(alter) = mutation {
            let (is_temp, is_stale, rows) = match pre_relations.get(&alter.id) {
                Some(rel) => {
                    (rel.persistence == Persistence::Temporary, rel.is_stale(), rel.estimated_rows.unwrap_or(config.default_rows))
                }
                None => {
                    (false, false, config.default_rows)
                }
            };

            if is_temp { return violations; }

            if is_stale {
                let key = format!("{}_stale_{}", self.id(), alter.id);
                violations.push(Violation {
                    rule_id: self.id(),
                    title: format!("Table {} statistics are stale. Lock evaluations may be inaccurate.", alter.id),
                    tier: ViolationTier::Tier2,
                    recipe: "Run ANALYZE to ensure accurate row estimates before structural changes.",
                    dedup_key: Some(key),
                });
            }

            let tier = if rows >= config.tier1_threshold_rows { ViolationTier::Tier1 }
                       else if rows >= config.tier2_threshold_rows { ViolationTier::Tier2 }
                       else { ViolationTier::Tier3 };

            if tier == ViolationTier::Tier3 { return violations; }

            match &alter.action {
                AlterTableActionMutation::AddCheckConstraint { constraint_name, not_valid: false } => {
                    let name_str = constraint_name.as_deref().unwrap_or("<unnamed>");
                    let mut title = format!("Synchronous CHECK constraint '{}' addition on {}", name_str, alter.id);
                    if is_stale { title.push_str(" [WARNING: Based on stale statistics]"); }

                    violations.push(Violation {
                        rule_id: self.id(),
                        title,
                        tier,
                        recipe: self.recipe(),
                        dedup_key: None, 
                    });
                }
                AlterTableActionMutation::AddForeignKey { constraint_name, not_valid: false, .. } => {
                    let name_str = constraint_name.as_deref().unwrap_or("<unnamed>");
                    let mut title = format!("Synchronous FOREIGN KEY constraint '{}' addition on {}", name_str, alter.id);
                    if is_stale { title.push_str(" [WARNING: Based on stale statistics]"); }

                    violations.push(Violation {
                        rule_id: self.id(),
                        title,
                        tier,
                        recipe: self.recipe(),
                        dedup_key: None,
                    });
                }
                AlterTableActionMutation::AddUniqueConstraint |
                AlterTableActionMutation::AddPrimaryKeyConstraint => {
                    let mut title = format!("Adding a UNIQUE or PRIMARY KEY constraint to {}", alter.id);
                    if is_stale { title.push_str(" [WARNING: Based on stale statistics]"); }

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
        violations
    }
}
