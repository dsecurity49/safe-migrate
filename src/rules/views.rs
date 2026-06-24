// FILE: src/rules/views.rs
use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::ast::identifiers::ObjectId;
use crate::engine::config::Config;
use crate::model::relation::{Persistence, RelationState};
use crate::report::violations::{Violation, ViolationTier};
use crate::rules::Rule;
use std::collections::HashMap;

pub struct MaterializedViewRefreshRule;

impl Rule for MaterializedViewRefreshRule {
    fn id(&self) -> &'static str {
        "blocking-mat-view-refresh"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "Refreshing a materialized view without CONCURRENTLY prevents reading from it during the refresh."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        result: &MutationResult,
        pre_relations: &HashMap<ObjectId, RelationState>,
        state: &AnalysisState,
        config: &Config,
        _cascade: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        if *result == MutationResult::Skipped {
            return vec![];
        }

        let mut violations = Vec::new();

        if let Mutation::RefreshMaterializedView(refresh) = mutation
            && !refresh.concurrently
        {
            let (is_temp, is_stale, rows) = match pre_relations.get(&refresh.id) {
                Some(rel) => {
                    let stale = rel.is_stale() && state.baseline_relations.contains(&refresh.id);
                    (
                        rel.persistence == Persistence::Temporary,
                        stale,
                        rel.estimated_rows.unwrap_or(config.default_rows),
                    )
                }
                None => (false, true, config.default_rows),
            };

            if is_temp {
                return violations;
            }

            if is_stale {
                let key = format!("{}_stale_{}", self.id(), refresh.id);
                violations.push(Violation {
                    rule_id: self.id(),
                    title: format!("Materialized view {} statistics are stale. Lock evaluations may be inaccurate.", refresh.id),
                    tier: ViolationTier::Tier2,
                    recipe: "Run ANALYZE to ensure accurate row estimates.",
                    dedup_key: Some(key),
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

            if tier != ViolationTier::Tier3 {
                let mut title = format!("Blocking materialized view refresh on {}", refresh.id);
                if is_stale {
                    title.push_str(" [WARNING: Based on offline/stale statistics]");
                }

                violations.push(Violation {
                    rule_id: self.id(),
                    title,
                    tier,
                    recipe: self.recipe(),
                    dedup_key: None,
                });
            }
        }
        violations
    }
}
