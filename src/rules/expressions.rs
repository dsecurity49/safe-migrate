use crate::analysis::mutations::Mutation;
use crate::analysis::state::MutationResult;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::rules::{Rule, RuleContext};

pub struct VolatileDefaultRule;

impl Rule for VolatileDefaultRule {
    fn id(&self) -> &'static str {
        "volatile-default"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier3
    }
    fn recipe(&self) -> &'static str {
        "Using volatile functions such as random() or gen_random_uuid() as defaults can cause unexpected behavior in logical replication or caching."
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        if *context.result() == MutationResult::Skipped {
            return vec![];
        }

        let mut violations = Vec::new();

        if let Mutation::CreateTable(c) = context.mutation() {
            for col in &c.columns {
                if let Some(def) = &col.default
                    && def.is_volatile()
                {
                    violations.push(Violation {
                        source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::CreateTable,
                        object_kind: ObjectKind::Table,
                        object_name: c.id.to_string(),
                        tier: self.default_tier(),
                        reason: format!("Volatile default expression on {}.{}", c.id, col.name),
                        recipe: self.recipe(),
                        dedup_key: None,
                        sql: None,
                        fk_dependency_related: false,
                    });
                }
            }
        }

        if let Mutation::AlterTable(a) = context.mutation() {
            match &a.action {
                crate::analysis::mutations::AlterTableActionMutation::AddColumn {
                    name,
                    default: Some(def),
                    ..
                } if def.is_volatile() => {
                    violations.push(Violation {
                        source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::AddColumn,
                        object_kind: ObjectKind::Table,
                        object_name: a.id.to_string(),
                        tier: self.default_tier(),
                        reason: format!("Volatile default expression on {}.{}", a.id, name),
                        recipe: self.recipe(),
                        dedup_key: None,
                        sql: None,
                        fk_dependency_related: false,
                    });
                }
                crate::analysis::mutations::AlterTableActionMutation::SetDefault {
                    column,
                    default: Some(def),
                } if def.is_volatile() => {
                    violations.push(Violation {
                        source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::SetDefault,
                        object_kind: ObjectKind::Table,
                        object_name: a.id.to_string(),
                        tier: self.default_tier(),
                        reason: format!("Volatile default expression on {}.{}", a.id, column),
                        recipe: self.recipe(),
                        dedup_key: None,
                        sql: None,
                        fk_dependency_related: false,
                    });
                }
                _ => {}
            }
        }

        violations
    }
}
