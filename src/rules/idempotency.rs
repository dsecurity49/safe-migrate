// FILE: src/rules/idempotency.rs

use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::rules::Rule;

pub struct IdempotencyRule;

impl Rule for IdempotencyRule {
    fn id(&self) -> &'static str {
        "missing-idempotency"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier3
    }
    fn recipe(&self) -> &'static str {
        "Use IF EXISTS or IF NOT EXISTS to prevent migration failures on partial re-runs."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        _result: &MutationResult,
        _pre_state: &crate::analysis::state::PreState,
        _state: &AnalysisState,
        _config: &Config,
        _cascade: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        // ARCHITECTURAL NOTE:
        // We INTENTIONALLY ignore `MutationResult::Skipped` here.
        // This rule is a syntactic policy enforcer. It flags missing IF EXISTS / IF NOT EXISTS
        // clauses regardless of whether the object actually existed during this specific simulator run.

        let mut violations = Vec::new();

        let mut add_violation =
            |op: OperationKind, obj: ObjectKind, name: String, reason: String| {
                violations.push(Violation {
                    rule_id: self.id(),
                    operation_kind: op,
                    object_kind: obj,
                    object_name: name,
                    tier: self.default_tier(),
                    reason,
                    recipe: self.recipe(),
                    dedup_key: None,
                            sql: None,
                });
            };

        match mutation {
            // Creation Guards
            Mutation::CreateTable(c) if !c.if_not_exists => {
                add_violation(
                    OperationKind::CreateTable,
                    ObjectKind::Table,
                    c.id.to_string(),
                    format!("CREATE TABLE {} without IF NOT EXISTS", c.id),
                );
            }
            Mutation::CreateIndex(c) if !c.if_not_exists => {
                add_violation(
                    OperationKind::CreateIndex,
                    ObjectKind::Index,
                    c.id.to_string(),
                    format!("CREATE INDEX {} without IF NOT EXISTS", c.id),
                );
            }
            Mutation::CreateSequence(c) if !c.if_not_exists => {
                add_violation(
                    OperationKind::Other("create_sequence".to_string()),
                    ObjectKind::Sequence,
                    c.id.to_string(),
                    format!("CREATE SEQUENCE {} without IF NOT EXISTS", c.id),
                );
            }

            // Drop Guards (Singular targets)
            Mutation::DropTable(d) if !d.if_exists => {
                add_violation(
                    OperationKind::DropTable,
                    ObjectKind::Table,
                    d.id.to_string(),
                    format!("DROP TABLE {} without IF EXISTS", d.id),
                );
            }
            Mutation::DropIndex(d) if !d.if_exists => {
                add_violation(
                    OperationKind::DropIndex,
                    ObjectKind::Index,
                    d.id.to_string(),
                    format!("DROP INDEX {} without IF EXISTS", d.id),
                );
            }
            Mutation::DropPolicy(d) if !d.if_exists => {
                add_violation(
                    OperationKind::DropPolicy,
                    ObjectKind::Policy,
                    format!("{} on {}", d.name, d.table),
                    format!("DROP POLICY {} on {} without IF EXISTS", d.name, d.table),
                );
            }
            Mutation::DropTrigger(d) if !d.if_exists => {
                add_violation(
                    OperationKind::DropTrigger,
                    ObjectKind::Trigger,
                    format!("{} on {}", d.name, d.table),
                    format!("DROP TRIGGER {} on {} without IF EXISTS", d.name, d.table),
                );
            }

            // Drop Guards (Vector targets)
            Mutation::DropSequence(d) if !d.if_exists => {
                for id in &d.ids {
                    add_violation(
                        OperationKind::DropSequence,
                        ObjectKind::Sequence,
                        id.to_string(),
                        format!("DROP SEQUENCE {} without IF EXISTS", id),
                    );
                }
            }
            Mutation::DropView(d) if !d.if_exists => {
                for id in &d.ids {
                    add_violation(
                        OperationKind::DropView,
                        ObjectKind::View,
                        id.to_string(),
                        format!("DROP VIEW {} without IF EXISTS", id),
                    );
                }
            }
            Mutation::DropMaterializedView(d) if !d.if_exists => {
                for id in &d.ids {
                    add_violation(
                        OperationKind::DropMaterializedView,
                        ObjectKind::MaterializedView,
                        id.to_string(),
                        format!("DROP MATERIALIZED VIEW {} without IF EXISTS", id),
                    );
                }
            }
            Mutation::DropDomain(d) if !d.if_exists => {
                for id in &d.ids {
                    add_violation(
                        OperationKind::DropDomain,
                        ObjectKind::Domain,
                        id.to_string(),
                        format!("DROP DOMAIN {} without IF EXISTS", id),
                    );
                }
            }

            // Alter Table Action Guards
            Mutation::AlterTable(a) => match &a.action {
                AlterTableActionMutation::AddColumn {
                    name,
                    if_not_exists,
                    ..
                } if !*if_not_exists => {
                    add_violation(
                        OperationKind::AddColumn,
                        ObjectKind::Table,
                        format!("{}.{}", a.id, name),
                        format!("ALTER TABLE {} ADD COLUMN {} without IF NOT EXISTS", a.id, name),
                    );
                }
                AlterTableActionMutation::DropColumn {
                    name, if_exists, ..
                } if !*if_exists => {
                    add_violation(
                        OperationKind::DropColumn,
                        ObjectKind::Table,
                        format!("{}.{}", a.id, name),
                        format!("ALTER TABLE {} DROP COLUMN {} without IF EXISTS", a.id, name),
                    );
                }
                _ => {}
            },
            _ => {}
        }

        violations
    }
}
