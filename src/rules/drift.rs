use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier};
use crate::rules::Rule;

pub struct DriftDetectionRule;

impl Rule for DriftDetectionRule {
    fn id(&self) -> &'static str {
        "schema-drift"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "This migration references a table that does not exist in the production baseline. If this table exists in production, sync the cache with `safe-migrate sync`. If it does not, this migration may fail."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        _result: &MutationResult,
        _pre_state: &crate::analysis::state::PreState,
        state: &AnalysisState,
        _config: &Config,
        _cascade_closure: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        match mutation {
            Mutation::DropTable(d) => {
                if !state.relation_is_present(&d.id) {
                    return vec![Violation {
                        rule_id: self.id(),
                        title: format!(
                            "Migration DROPs table \"{}\" which does not exist in the production baseline",
                            d.id
                        ),
                        tier: self.default_tier(),
                        recipe: self.recipe(),
                        dedup_key: None,
                    }];
                }
            }
            Mutation::AlterTable(a) if !state.relation_is_present(&a.id) => {
                return vec![Violation {
                    rule_id: self.id(),
                    title: format!(
                        "Migration ALTERs table \"{}\" which does not exist in the production baseline",
                        a.id
                    ),
                    tier: self.default_tier(),
                    recipe: self.recipe(),
                    dedup_key: None,
                }];
            }
            _ => {}
        }
        vec![]
    }
}