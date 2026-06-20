// FILE: ./src/rules/views.rs                                                                             
use std::collections::HashMap;
use crate::ast::identifiers::ObjectId;
use crate::rules::Rule;
use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier};
use crate::model::relation::{RelationState, Persistence};

pub struct MaterializedViewRefreshRule;
              
impl Rule for MaterializedViewRefreshRule {
    fn id(&self) -> &'static str { "blocking-mat-view-refresh" }
    fn default_tier(&self) -> ViolationTier { ViolationTier::Tier1 }
    fn recipe(&self) -> &'static str { "Refreshing a materialized view without CONCURRENTLY prevents reading from it during the refresh." }

    fn evaluate(
        &self, 
        mutation: &Mutation, 
        result: &MutationResult,
        pre_relations: &HashMap<ObjectId, RelationState>,
        _state: &AnalysisState, 
        config: &Config
    ) -> Vec<Violation> {
        if *result == MutationResult::Skipped { return vec![]; }

        let mut violations = Vec::new();

        if let Mutation::RefreshMaterializedView(refresh) = mutation {
            if !refresh.concurrently {
                if let Some(rel) = pre_relations.get(&refresh.id) {
                    if rel.persistence == Persistence::Temporary { return violations; }

                    if rel.is_stale() {
                        let key = format!("{}_stale_{}", self.id(), refresh.id);
                        violations.push(Violation {
                            rule_id: self.id(),
                            title: format!("Materialized view {} statistics are stale. Lock evaluations may be inaccurate.", refresh.id),
                            tier: ViolationTier::Tier2,
                            recipe: "Run ANALYZE to ensure accurate row estimates.",
                            dedup_key: Some(key),
                        });
                    }

                    let tier = match rel.estimated_rows {
                        None => ViolationTier::Tier1,
                        Some(r) if r >= config.tier1_threshold_rows => ViolationTier::Tier1,
                        Some(r) if r >= config.tier2_threshold_rows => ViolationTier::Tier2,
                        _ => ViolationTier::Tier3,
                    };

                    if tier != ViolationTier::Tier3 {
                        let mut title = format!("Blocking materialized view refresh on {}", refresh.id);
                        if rel.is_stale() { title.push_str(" [WARNING: Based on stale statistics]"); }

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
        }
        violations
    }
}
