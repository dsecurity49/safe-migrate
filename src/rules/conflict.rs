// FILE: src/rules/conflict.rs

use crate::analysis::state::MutationResult;
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier, OperationKind, ObjectKind};
use crate::rules::Rule;
use crate::analysis::mutations::Mutation;

pub struct ConflictRule;

impl ConflictRule {
    const ID: &'static str = "chain-conflict";
    const DEFAULT_TIER: ViolationTier = ViolationTier::Tier1;
    const RECIPE: &'static str = "Refactor the migration chain so each column is added only once with a consistent type, or consolidate into a single DDL statement.";

    fn extract_conflict_reason(result: &MutationResult) -> Option<&str> {
        match result {
            MutationResult::Conflict { reason } => Some(reason.as_str()),
            _ => None,
        }
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

    fn evaluate(
        &self,
        _mutation: &Mutation,
        result: &MutationResult,
        _pre_state: &crate::analysis::state::PreState,
        _state: &crate::analysis::state::AnalysisState,
        _config: &Config,
        _cascade_closure: Option<&crate::analysis::state::CascadeResult>,
    ) -> Vec<Violation> {
        match Self::extract_conflict_reason(result) {
            Some(reason) => vec![Violation {
                rule_id: Self::ID,
                operation_kind: OperationKind::Other("conflict".to_string()),
                object_kind: ObjectKind::Unknown,
                object_name: "unknown".to_string(),
                tier: Self::DEFAULT_TIER,
                reason: format!("Migration chain conflict: {}", reason),
                recipe: Self::RECIPE,
                dedup_key: None,
                    sql: None,
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
    use std::collections::HashMap;

    #[test]
    fn test_conflict_rule_emits_tier1_on_conflict() {
        let rule = ConflictRule;
        let result = MutationResult::Conflict {
            reason: "column 'x' already added with type int, this file adds it again with type text".to_string(),
        };
        let violations = rule.evaluate(
            &Mutation::Opaque(crate::analysis::mutations::OpaqueMutation::DynamicSql),
            &result,
            &crate::analysis::state::PreState {
                relations: HashMap::new(),
                functions: HashMap::new(),
                roles: HashMap::new(),
                publications: HashMap::new(),
                subscriptions: HashMap::new(),
                sequences: HashMap::new(),
                types: HashMap::new(),
                indexes: Vec::new(),
            },
            &crate::analysis::state::AnalysisState::new(crate::db::cache::DbCache::new()),
            &Config::default(),
            None,
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_id, "chain-conflict");
        assert_eq!(violations[0].tier, ViolationTier::Tier1);
        assert!(violations[0].reason.contains("Migration chain conflict"));
    }

    #[test]
    fn test_conflict_rule_silent_on_applied() {
        let rule = ConflictRule;
        let result = MutationResult::Applied;
        let violations = rule.evaluate(
            &Mutation::Opaque(crate::analysis::mutations::OpaqueMutation::DynamicSql),
            &result,
            &crate::analysis::state::PreState {
                relations: HashMap::new(),
                functions: HashMap::new(),
                roles: HashMap::new(),
                publications: HashMap::new(),
                subscriptions: HashMap::new(),
                sequences: HashMap::new(),
                types: HashMap::new(),
                indexes: Vec::new(),
            },
            &crate::analysis::state::AnalysisState::new(crate::db::cache::DbCache::new()),
            &Config::default(),
            None,
        );
        assert!(violations.is_empty());
    }
}
