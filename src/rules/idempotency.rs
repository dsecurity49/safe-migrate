// FILE: ./src/rules/idempotency.rs

use std::collections::HashMap;
use crate::ast::identifiers::ObjectId;
use crate::rules::Rule;
use crate::analysis::mutations::Mutation;
use crate::analysis::state::{LocalState, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier};
use crate::model::relation::RelationState;

pub struct IdempotencyRule;

impl Rule for IdempotencyRule {
    fn id(&self) -> &'static str { "missing-idempotency" }
    fn default_tier(&self) -> ViolationTier { ViolationTier::Tier3 }
    fn recipe(&self) -> &'static str { "Use IF EXISTS or IF NOT EXISTS to prevent migration failures on partial re-runs." }

    fn evaluate(
        &self, 
        mutation: &Mutation, 
        _result: &MutationResult,
        _pre_relations: &HashMap<ObjectId, RelationState>,
        _state: &LocalState, 
        _config: &Config
    ) -> Vec<Violation> {
        // ARCHITECTURAL NOTE:
        // We INTENTIONALLY ignore `MutationResult::Skipped` here.
        // This rule is a syntactic policy enforcer. It flags missing IF EXISTS / IF NOT EXISTS
        // clauses regardless of whether the object actually existed during this specific simulator run.
        // E.g., `DROP TABLE foo` should warn about missing IF EXISTS even if `foo` doesn't exist
        // in the current simulated state, because it will crash the real migration runner on retry.

        let mut violations = Vec::new();

        match mutation {
            Mutation::CreateTable(c) if !c.if_not_exists => {
                violations.push(Violation {
                    rule_id: self.id(),
                    title: format!("CREATE TABLE {} without IF NOT EXISTS", c.id),
                    tier: self.default_tier(),
                    recipe: self.recipe(),
                    dedup_key: None,
                });
            }
            Mutation::DropTable(d) if !d.if_exists => {
                violations.push(Violation {
                    rule_id: self.id(),
                    title: format!("DROP TABLE {} without IF EXISTS", d.id),
                    tier: self.default_tier(),
                    recipe: self.recipe(),
                    dedup_key: None,
                });
            }
            Mutation::CreateIndex(c) if !c.if_not_exists => {
                violations.push(Violation {
                    rule_id: self.id(),
                    title: format!("CREATE INDEX {} without IF NOT EXISTS", c.id),
                    tier: self.default_tier(),
                    recipe: self.recipe(),
                    dedup_key: None,
                });
            }
            _ => {}
        }

        violations
    }
}
