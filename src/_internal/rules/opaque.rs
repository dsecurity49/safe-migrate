use crate::_internal::analysis::mutations::Mutation;
use crate::_internal::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::_internal::rules::{Rule, RuleContext};

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

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        let mut violations = Vec::new();

        if let Mutation::Opaque(op) = context.mutation() {
            if matches!(
                op,
                crate::_internal::analysis::mutations::OpaqueMutation::UnresolvedReference { .. }
            ) {
                return vec![];
            }
            let (block_type, is_collision, recipe) = match &op {
                crate::_internal::analysis::mutations::OpaqueMutation::UnsupportedStatement => (
                    "unsupported SQL statement",
                    false,
                    "This SQL statement is not modeled. Review its PostgreSQL behavior before deploying.",
                ),
                crate::_internal::analysis::mutations::OpaqueMutation::DoBlock => {
                    ("DO block", false, self.recipe())
                }
                crate::_internal::analysis::mutations::OpaqueMutation::Execute => {
                    ("EXECUTE statement", false, self.recipe())
                }
                crate::_internal::analysis::mutations::OpaqueMutation::DynamicSql => {
                    ("Dynamic SQL", false, self.recipe())
                }
                crate::_internal::analysis::mutations::OpaqueMutation::PrepareTransaction => {
                    ("PREPARE TRANSACTION", false, self.recipe())
                }
                crate::_internal::analysis::mutations::OpaqueMutation::SetTransaction => {
                    ("SET TRANSACTION", false, self.recipe())
                }
                crate::_internal::analysis::mutations::OpaqueMutation::SetConstraints => {
                    ("SET CONSTRAINTS", false, self.recipe())
                }
                crate::_internal::analysis::mutations::OpaqueMutation::StateCollision(msg) => {
                    (msg.as_str(), true, self.recipe())
                }
                crate::_internal::analysis::mutations::OpaqueMutation::UnresolvedReference { .. } => {
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
                    recipe,
                    dedup_key: None,
                    sql: None,
                    fk_dependency_related: false,
                });
            }
        }

        violations
    }
}
