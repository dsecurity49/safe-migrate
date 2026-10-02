use crate::_internal::analysis::mutations::{Mutation, OpaqueMutation};
use crate::_internal::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::_internal::rules::{Rule, RuleContext};

pub(crate) struct OpaqueDynamicSqlRule;

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
        // A missing baseline object is `schema-drift`'s concern, not opaque SQL.
        if matches!(
            context.mutation(),
            Mutation::Opaque(OpaqueMutation::UnresolvedReference { .. })
        ) {
            return Vec::new();
        }

        let Mutation::Opaque(op) = context.mutation() else {
            return Vec::new();
        };

        let (block_type, recipe) = match op {
            OpaqueMutation::UnsupportedStatement => (
                "unsupported SQL statement",
                "This SQL statement is not modeled. Review its PostgreSQL behavior before deploying.",
            ),
            OpaqueMutation::DoBlock => ("DO block", self.recipe()),
            OpaqueMutation::Execute => ("EXECUTE statement", self.recipe()),
            OpaqueMutation::PrepareTransaction => ("PREPARE TRANSACTION", self.recipe()),
            OpaqueMutation::SetTransaction => ("SET TRANSACTION", self.recipe()),
            OpaqueMutation::SetConstraints => ("SET CONSTRAINTS", self.recipe()),
            OpaqueMutation::UnresolvedReference { .. } => return Vec::new(),
        };

        // The statement is deliberately unmodeled, so it has no catalog object
        // to name; `object_name` reports that honestly instead of inventing one.
        vec![Violation {
            source_range: None,
            rule_id: self.id(),
            operation_kind: OperationKind::OpaqueSql,
            object_kind: ObjectKind::Opaque,
            object_name: "opaque statement".to_string(),
            tier: self.default_tier(),
            reason: format!("Encountered opaque {}", block_type),
            recipe,
            dedup_key: None,
            sql: None,
            fk_dependency_related: false,
        }]
    }
}
