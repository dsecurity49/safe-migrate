// FILE: src/rules/transactions.rs
use std::collections::HashMap;
use crate::ast::identifiers::ObjectId;
use crate::model::relation::RelationState;
use crate::rules::Rule;
use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier};

pub struct ConcurrentInsideTransactionRule;

impl Rule for ConcurrentInsideTransactionRule {
    fn id(&self) -> &'static str { "concurrent-in-transaction" }
    fn default_tier(&self) -> ViolationTier { ViolationTier::Tier1 }
    fn recipe(&self) -> &'static str { "PostgreSQL does not allow CREATE/DROP INDEX CONCURRENTLY inside a transaction block (BEGIN/COMMIT)." }

    fn evaluate(
        &self,
        mutation: &Mutation,
        _result: &MutationResult,
        _pre_relations: &HashMap<ObjectId, RelationState>,
        state: &AnalysisState,
        _config: &Config
    ) -> Vec<Violation> {
        // We INTENTIONALLY ignore `MutationResult::Skipped` here.
        // PostgreSQL blocks CONCURRENTLY execution inside transaction boundaries
        // regardless of whether an IF EXISTS / IF NOT EXISTS clause is present.

        let mut violations = Vec::new();

        if !state.local.transactions.is_empty() {
            match mutation {
                Mutation::CreateIndex(c) if c.concurrently => {
                    violations.push(Violation {
                        rule_id: self.id(),
                        title: format!("CREATE INDEX CONCURRENTLY on {} inside a transaction block", c.table),
                        tier: self.default_tier(),
                        recipe: self.recipe(),
                        dedup_key: None,
                    });
                }
                Mutation::DropIndex(d) if d.concurrently => {
                    violations.push(Violation {
                        rule_id: self.id(),
                        title: format!("DROP INDEX CONCURRENTLY on {} inside a transaction block", d.id),
                        tier: self.default_tier(),
                        recipe: self.recipe(),
                        dedup_key: None,
                    });
                }
                _ => {}
            }
        }

        violations
    }
}

pub struct VacuumFullRule;

impl Rule for VacuumFullRule {
    fn id(&self) -> &'static str { "vacuum-full" }
    fn default_tier(&self) -> ViolationTier { ViolationTier::Tier1 }
    fn recipe(&self) -> &'static str { "VACUUM FULL rewrites the entire table and requires an ACCESS EXCLUSIVE lock. Run this manually outside of migration pipelines." }

    fn evaluate(
        &self,
        mutation: &Mutation,
        _result: &MutationResult,
        _pre_relations: &HashMap<ObjectId, RelationState>,
        _state: &AnalysisState,
        _config: &Config
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        if let Mutation::Vacuum { is_full: true } = mutation {
            violations.push(Violation {
                rule_id: self.id(),
                title: "VACUUM FULL requires an ACCESS EXCLUSIVE lock".to_string(),
                tier: self.default_tier(),
                recipe: self.recipe(),
                dedup_key: None,
            });
        }

        violations
    }
}

