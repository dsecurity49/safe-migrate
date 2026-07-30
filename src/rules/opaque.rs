// FILE: src/rules/opaque.rs
use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::rules::Rule;

pub struct OpaqueDynamicSqlRule;

impl Rule for OpaqueDynamicSqlRule {
    fn id(&self) -> &'static str {
        "opaque-dynamic-sql"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier2
    }
    fn recipe(&self) -> &'static str {
        "Procedural or dynamic SQL (DO blocks, EXECUTE) obscures schema mutations. Lock analysis confidence is heavily degraded."
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
        let mut violations = Vec::new();

        if let Mutation::Opaque(op) = mutation {
            if matches!(
                op,
                crate::analysis::mutations::OpaqueMutation::UnresolvedReference { .. }
            ) {
                return vec![];
            }
            let (block_type, is_collision) = match &op {
                crate::analysis::mutations::OpaqueMutation::UnsupportedStatement => {
                    ("unsupported SQL statement", false)
                }
                crate::analysis::mutations::OpaqueMutation::DoBlock => ("DO block", false),
                crate::analysis::mutations::OpaqueMutation::Execute => ("EXECUTE statement", false),
                crate::analysis::mutations::OpaqueMutation::DynamicSql => ("Dynamic SQL", false),
                crate::analysis::mutations::OpaqueMutation::PrepareTransaction => {
                    ("PREPARE TRANSACTION", false)
                }
                crate::analysis::mutations::OpaqueMutation::SetTransaction => {
                    ("SET TRANSACTION", false)
                }
                crate::analysis::mutations::OpaqueMutation::SetConstraints => {
                    ("SET CONSTRAINTS", false)
                }
                crate::analysis::mutations::OpaqueMutation::StateCollision(msg) => {
                    (msg.as_str(), true)
                }
                crate::analysis::mutations::OpaqueMutation::UnresolvedReference { .. } => {
                    unreachable!()
                }
            };

            if is_collision {
                violations.push(Violation {
                    source_range: None,
                    rule_id: "schema-drift",
                    operation_kind: OperationKind::Conflict,
                    object_kind: ObjectKind::Opaque,
                    object_name: "<dynamic>".to_string(),
                    tier: ViolationTier::Tier1,
                    reason: format!("Migration state conflict: {}", block_type),
                    recipe: "This migration attempts to create an object that already exists, or alter an object that does not. The simulated state has derailed.",
                    dedup_key: None,
                    sql: None,
                    fk_dependency_related: false,
                });
            } else {
                violations.push(Violation {
                    source_range: None,
                    rule_id: self.id(),
                    operation_kind: OperationKind::OpaqueSql,
                    object_kind: ObjectKind::Opaque,
                    object_name: "<dynamic>".to_string(),
                    tier: self.default_tier(),
                    reason: format!("Encountered opaque {}", block_type),
                    recipe: self.recipe(),
                    dedup_key: None,
                    sql: None,
                    fk_dependency_related: false,
                });
            }
        }

        violations
    }
}
