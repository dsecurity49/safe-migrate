// FILE: src/rules/idempotency.rs

use std::collections::HashMap;
use crate::ast::identifiers::ObjectId;
use crate::rules::Rule;
use crate::analysis::mutations::{Mutation, AlterTableActionMutation};
use crate::analysis::state::{AnalysisState, MutationResult};
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
        _state: &AnalysisState,
        _config: &Config
    ) -> Vec<Violation> {
        // ARCHITECTURAL NOTE:
        // We INTENTIONALLY ignore `MutationResult::Skipped` here.
        // This rule is a syntactic policy enforcer. It flags missing IF EXISTS / IF NOT EXISTS
        // clauses regardless of whether the object actually existed during this specific simulator run.
        
        let mut violations = Vec::new();

        let mut add_violation = |title: String| {
            violations.push(Violation {
                rule_id: self.id(),
                title,
                tier: self.default_tier(),
                recipe: self.recipe(),
                dedup_key: None,
            });
        };

        match mutation {
            // Creation Guards
            Mutation::CreateTable(c) if !c.if_not_exists => {
                add_violation(format!("CREATE TABLE {} without IF NOT EXISTS", c.id));
            }
            Mutation::CreateIndex(c) if !c.if_not_exists => {
                add_violation(format!("CREATE INDEX {} without IF NOT EXISTS", c.id));
            }
            Mutation::CreateSequence(c) if !c.if_not_exists => {
                add_violation(format!("CREATE SEQUENCE {} without IF NOT EXISTS", c.id));
            }

            // Drop Guards (Singular targets)
            Mutation::DropTable(d) if !d.if_exists => {
                add_violation(format!("DROP TABLE {} without IF EXISTS", d.id));
            }
            Mutation::DropIndex(d) if !d.if_exists => {
                add_violation(format!("DROP INDEX {} without IF EXISTS", d.id));
            }
            Mutation::DropPolicy(d) if !d.if_exists => {
                add_violation(format!("DROP POLICY {} on {} without IF EXISTS", d.name, d.table));
            }
            Mutation::DropTrigger(d) if !d.if_exists => {
                add_violation(format!("DROP TRIGGER {} on {} without IF EXISTS", d.name, d.table));
            }

            // Drop Guards (Vector targets)
            Mutation::DropSequence(d) if !d.if_exists => {
                for id in &d.ids {
                    add_violation(format!("DROP SEQUENCE {} without IF EXISTS", id));
                }
            }
            Mutation::DropView(d) if !d.if_exists => {
                for id in &d.ids {
                    add_violation(format!("DROP VIEW {} without IF EXISTS", id));
                }
            }
            Mutation::DropMaterializedView(d) if !d.if_exists => {
                for id in &d.ids {
                    add_violation(format!("DROP MATERIALIZED VIEW {} without IF EXISTS", id));
                }
            }
            Mutation::DropDomain(d) if !d.if_exists => {
                for id in &d.ids {
                    add_violation(format!("DROP DOMAIN {} without IF EXISTS", id));
                }
            }

            // Alter Table Action Guards
            Mutation::AlterTable(a) => {
                match &a.action {
                    AlterTableActionMutation::AddColumn { name, if_not_exists, .. } if !*if_not_exists => {
                        add_violation(format!("ALTER TABLE {} ADD COLUMN {} without IF NOT EXISTS", a.id, name));
                    }
                    AlterTableActionMutation::DropColumn { name, if_exists, .. } if !*if_exists => {
                        add_violation(format!("ALTER TABLE {} DROP COLUMN {} without IF EXISTS", a.id, name));
                    }
                    _ => {}
                }
            }
            _ => {}
        }

        violations
    }
}
