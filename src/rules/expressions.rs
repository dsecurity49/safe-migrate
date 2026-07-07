// FILE: src/rules/expressions.rs

use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::rules::Rule;

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
        _pre_state: &crate::analysis::state::PreState,
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
                    });
                }
            }
        }

        if let Mutation::AlterTable(a) = mutation {
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
                    });
                }
                crate::analysis::mutations::AlterTableActionMutation::SetDefault {
                    column,
                    default: Some(def),
                } if def.is_volatile() => {
                    violations.push(Violation {
                        source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::Other("set_default".to_string()),
                        object_kind: ObjectKind::Table,
                        object_name: a.id.to_string(),
                        tier: self.default_tier(),
                        reason: format!("Volatile default expression on {}.{}", a.id, column),
                        recipe: self.recipe(),
                        dedup_key: None,
                        sql: None,
                    });
                }
                _ => {}
            }
        }

        violations
    }
}
