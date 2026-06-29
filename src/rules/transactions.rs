// FILE: src/rules/transactions.rs
use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult};
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier};
use crate::rules::Rule;

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
                    violations.push(Violation {
                        rule_id: self.id(),
                        title: format!("CREATE INDEX CONCURRENTLY on {} inside a transaction block", c.table),
                        tier: self.default_tier(),
                        recipe: "Move CONCURRENTLY index creation outside of explicit transaction blocks.",
                        dedup_key: Some(format!("{}_{}", self.id(), c.id)),
                    });
                }
                Mutation::DropIndex(d) if d.concurrently => {
                    violations.push(Violation {
                        rule_id: self.id(),
                        title: format!(
                            "DROP INDEX CONCURRENTLY on {} inside a transaction block",
                            d.id
                        ),
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

pub struct AlterTypeAddValueRule;

impl Rule for AlterTypeAddValueRule {
    fn id(&self) -> &'static str {
        "alter-type-add-value-txn"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "ALTER TYPE ... ADD VALUE cannot be executed inside a transaction block in PostgreSQL."
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
        {
            return vec![Violation {
                rule_id: self.id(),
                title: format!("ALTER TYPE {} ADD VALUE inside transaction", alter.id),
                tier: self.default_tier(),
                recipe: self.recipe(),
                dedup_key: None,
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
        if let Mutation::Vacuum { is_full: true } = mutation {
            return vec![Violation {
                rule_id: self.id(),
                title: "VACUUM FULL requires an ACCESS EXCLUSIVE lock".to_string(),
                tier: self.default_tier(),
                recipe: self.recipe(),
                dedup_key: None,
            }];
        }
        vec![]
    }
}
