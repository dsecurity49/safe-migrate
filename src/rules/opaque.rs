// FILE: ./src/rules/opaque.rs

use std::collections::HashMap;
use crate::ast::identifiers::ObjectId;
use crate::model::relation::RelationState;
use crate::rules::Rule;
use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier};

pub struct OpaqueDynamicSqlRule;

impl Rule for OpaqueDynamicSqlRule {
    fn id(&self) -> &'static str { "opaque-dynamic-sql" }
    fn default_tier(&self) -> ViolationTier { ViolationTier::Tier2 }
    fn recipe(&self) -> &'static str { "Procedural or dynamic SQL (DO blocks, EXECUTE) obscures schema mutations. Lock analysis confidence is heavily degraded." }

    fn evaluate(
        &self, 
        mutation: &Mutation, 
        _result: &MutationResult,
        _pre_relations: &HashMap<ObjectId, RelationState>,
        _state: &AnalysisState, 
        _config: &Config
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        if let Mutation::Opaque(op) = mutation {
            let block_type = match op {
                crate::analysis::mutations::OpaqueMutation::DoBlock => "DO block",
                crate::analysis::mutations::OpaqueMutation::Execute => "EXECUTE statement",
                crate::analysis::mutations::OpaqueMutation::DynamicSql => "Dynamic SQL",
            };

            violations.push(Violation {
                rule_id: self.id(),
                title: format!("Encountered opaque {}", block_type),
                tier: self.default_tier(),
                recipe: self.recipe(),
                dedup_key: None,
            });
        }

        violations
    }
}
