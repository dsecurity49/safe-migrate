// FILE: src/rules/expressions.rs

use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::ast::identifiers::ObjectId;
use crate::engine::config::Config;
use crate::model::relation::RelationState;
use crate::report::violations::{Violation, ViolationTier};
use crate::rules::Rule;
use std::collections::HashMap;

pub struct VolatileDefaultRule;

impl Rule for VolatileDefaultRule {
    fn id(&self) -> &'static str {
        "volatile-default"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier3
    }
    fn recipe(&self) -> &'static str {
        "Using volatile functions (like random() or now()) as defaults can cause unexpected behavior in logical replication or caching."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        result: &MutationResult,
        _pre_relations: &HashMap<ObjectId, RelationState>,
        _state: &AnalysisState,
        _config: &Config,
        _cascade: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        if *result == MutationResult::Skipped {
            return vec![];
        }

        let mut violations = Vec::new();

        if let Mutation::CreateTable(c) = mutation {
            for col in &c.columns {
                if let Some(def) = &col.default
                    && def.is_volatile()
                {
                    violations.push(Violation {
                        rule_id: self.id(),
                        title: format!("Volatile default expression on {}.{}", c.id, col.name),
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
