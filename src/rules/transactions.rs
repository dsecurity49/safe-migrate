use crate::analysis::mutations::{AlterTypeActionMutation, Mutation};
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::rules::LegacyRule as Rule;

pub struct ConcurrentInsideTransactionRule;

impl Rule for ConcurrentInsideTransactionRule {
    fn id(&self) -> &'static str {
        "concurrent-in-transaction"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "PostgreSQL does not allow CREATE/DROP INDEX CONCURRENTLY inside a transaction block (BEGIN/COMMIT)."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        _result: &MutationResult,
        _pre_state: &crate::analysis::state::PreState,
        state: &AnalysisState,
        _config: &Config,
        _cascade: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        if !state.local.transactions.is_empty() {
            match mutation {
                Mutation::CreateIndex(c) if c.concurrently => {
                    violations.push(Violation { source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::CreateIndex,
                        object_kind: ObjectKind::Index,
                        object_name: c.id.to_string(),
                        tier: self.default_tier(),
                        reason: format!("CREATE INDEX CONCURRENTLY on {} inside a transaction block", c.table),
                        recipe: "Move CONCURRENTLY index creation outside of explicit transaction blocks.",
                        dedup_key: Some(format!("{}_{}", self.id(), c.id)),
                                    sql: None,
                                    fk_dependency_related: false,
                    });
                }
                Mutation::DropIndex(d) if d.concurrently => {
                    for id in &d.ids {
                        violations.push(Violation {
                            source_range: None,
                            rule_id: self.id(),
                            operation_kind: OperationKind::DropIndex,
                            object_kind: ObjectKind::Index,
                            object_name: id.to_string(),
                            tier: self.default_tier(),
                            reason: format!(
                                "DROP INDEX CONCURRENTLY on {} inside a transaction block",
                                id
                            ),
                            recipe: self.recipe(),
                            dedup_key: None,
                            sql: None,
                            fk_dependency_related: false,
                        });
                    }
                }
                _ => {}
            }
        }

        violations
    }
}

pub struct AlterTypeAddValueRule;

impl Rule for AlterTypeAddValueRule {
    fn id(&self) -> &'static str {
        "alter-type-add-value-txn"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier2
    }
    fn recipe(&self) -> &'static str {
        "Commit before later statements use the new enum value, or put the dependent work in a later migration."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        _result: &MutationResult,
        _pre_state: &crate::analysis::state::PreState,
        state: &AnalysisState,
        _config: &Config,
        _cascade: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        if !state.local.transactions.is_empty()
            && let Mutation::AlterType(alter) = mutation
            && matches!(alter.action, AlterTypeActionMutation::AddValue { .. })
        {
            return vec![Violation {
                source_range: None,
                rule_id: self.id(),
                operation_kind: OperationKind::AlterType,
                object_kind: ObjectKind::Type,
                object_name: alter.id.to_string(),
                tier: self.default_tier(),
                reason: format!(
                    "ALTER TYPE {} ADD VALUE is inside a transaction; PostgreSQL does not allow the new value to be used until commit",
                    alter.id
                ),
                recipe: self.recipe(),
                dedup_key: None,
                sql: None,
                fk_dependency_related: false,
            }];
        }
        vec![]
    }
}

pub struct VacuumFullRule;

impl Rule for VacuumFullRule {
    fn id(&self) -> &'static str {
        "vacuum-full"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "VACUUM FULL rewrites the entire table and requires an ACCESS EXCLUSIVE lock. Run this manually outside of migration pipelines."
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
        if let Mutation::Vacuum {
            is_full: true,
            table_id,
        } = mutation
        {
            let object_name = table_id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_else(|| "<all tables>".to_string());
            return vec![Violation {
                source_range: None,
                rule_id: self.id(),
                operation_kind: OperationKind::VacuumFull,
                object_kind: ObjectKind::Table,
                object_name,
                tier: self.default_tier(),
                reason: "VACUUM FULL requires an ACCESS EXCLUSIVE lock".to_string(),
                recipe: self.recipe(),
                dedup_key: None,
                sql: None,
                fk_dependency_related: false,
            }];
        }
        vec![]
    }
}
