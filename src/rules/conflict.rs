use crate::analysis::state::MutationResult;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::rules::{Rule, RuleContext};

pub struct ConflictRule;

impl ConflictRule {
    const ID: &'static str = "chain-conflict";
    const DEFAULT_TIER: ViolationTier = ViolationTier::Tier1;
    const RECIPE: &'static str = "Correct the migration so this statement can execute against the schema state produced by earlier statements. Use an idempotency guard only when a no-op is intended.";

    fn extract_conflict_reason(result: &MutationResult) -> Option<&str> {
        match result {
            MutationResult::Conflict { reason } => Some(reason.as_str()),
            _ => None,
        }
    }

    fn is_dedicated_transaction_conflict(reason: &str) -> bool {
        matches!(
            reason,
            "CREATE INDEX CONCURRENTLY cannot run inside a transaction"
                | "DROP INDEX CONCURRENTLY cannot run inside a transaction"
                | "REFRESH MATERIALIZED VIEW CONCURRENTLY cannot run inside a transaction"
        )
    }
}

impl Rule for ConflictRule {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn default_tier(&self) -> ViolationTier {
        Self::DEFAULT_TIER
    }

    fn recipe(&self) -> &'static str {
        Self::RECIPE
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        match Self::extract_conflict_reason(context.result()) {
            Some(reason) if Self::is_dedicated_transaction_conflict(reason) => Vec::new(),
            Some(reason) => vec![Violation {
                source_range: None,
                rule_id: Self::ID,
                operation_kind: OperationKind::Conflict,
                object_kind: ObjectKind::Unknown,
                object_name: "<migration-state>".to_string(),
                tier: Self::DEFAULT_TIER,
                reason: format!("Migration chain conflict: {}", reason),
                recipe: Self::RECIPE,
                dedup_key: None,
                sql: None,
                fk_dependency_related: false,
            }],
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::mutations::Mutation;
    use crate::analysis::state::MutationResult;
    use crate::engine::config::Config;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_conflict_rule_emits_tier1_on_conflict() {
        let rule = ConflictRule;
        let result = MutationResult::Conflict {
            reason:
                "column 'x' already added with type int, this file adds it again with type text"
                    .to_string(),
        };
        let mutation = Mutation::Opaque(crate::analysis::mutations::OpaqueMutation::DynamicSql);
        let pre_state = crate::analysis::state::PreState {
            relations: HashMap::new(),
            functions: HashMap::new(),
            roles: HashMap::new(),
            publications: HashMap::new(),
            subscriptions: HashMap::new(),
            sequences: HashMap::new(),
            types: HashMap::new(),
            indexes: Vec::new(),
            baseline_foreign_keys: HashSet::new(),
        };
        let state = crate::analysis::state::AnalysisState::new(crate::db::cache::DbCache::new());
        let config = Config::default();
        let context = RuleContext::new(&mutation, &result, &pre_state, &state, &config, None);
        let violations = rule.evaluate(&context);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_id, "chain-conflict");
        assert_eq!(violations[0].tier, ViolationTier::Tier1);
        assert_eq!(violations[0].object_kind, ObjectKind::Unknown);
        assert_eq!(violations[0].object_name, "<migration-state>");
        assert!(violations[0].reason.contains("Migration chain conflict"));
        assert!(violations[0].recipe.contains("schema state"));
        assert!(!violations[0].recipe.contains("each column"));
    }

    #[test]
    fn test_conflict_rule_silent_on_applied() {
        let rule = ConflictRule;
        let result = MutationResult::Applied;
        let mutation = Mutation::Opaque(crate::analysis::mutations::OpaqueMutation::DynamicSql);
        let pre_state = crate::analysis::state::PreState {
            relations: HashMap::new(),
            functions: HashMap::new(),
            roles: HashMap::new(),
            publications: HashMap::new(),
            subscriptions: HashMap::new(),
            sequences: HashMap::new(),
            types: HashMap::new(),
            indexes: Vec::new(),
            baseline_foreign_keys: HashSet::new(),
        };
        let state = crate::analysis::state::AnalysisState::new(crate::db::cache::DbCache::new());
        let config = Config::default();
        let context = RuleContext::new(&mutation, &result, &pre_state, &state, &config, None);
        let violations = rule.evaluate(&context);
        assert!(violations.is_empty());
    }
}
