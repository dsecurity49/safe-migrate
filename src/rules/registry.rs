use crate::report::violations::ViolationTier;
use crate::rules::Rule;
use crate::rules::conflict::ConflictRule;
use crate::rules::constraints::BlockingConstraintRule;
use crate::rules::destructive::{
    CascadingDropRule, CreateTableAsSelectRule, DropDatabaseRule, DropSchemaCascadeRule,
    GeneralCascadeRule, ReversibilityRule, SizeAwareAddColumnRule, TypeChangeRewriteRule,
};
use crate::rules::drift::DriftDetectionRule;
use crate::rules::expressions::VolatileDefaultRule;
use crate::rules::functions::{BrokenComputeRule, FunctionVolatilityRule};
use crate::rules::idempotency::IdempotencyRule;
use crate::rules::indexes::ConcurrentIndexRule;
use crate::rules::opaque::OpaqueDynamicSqlRule;
use crate::rules::partitions::{PartitionLockRule, PartitionStrategyMismatchRule};
use crate::rules::policies::RestrictivePolicyRule;
use crate::rules::security::OverbroadGrantRule;
use crate::rules::timeouts::{RequireLockTimeoutRule, RequireStatementTimeoutRule};
use crate::rules::transactions::{
    AlterTypeAddValueRule, ConcurrentInsideTransactionRule, VacuumFullRule,
};
use crate::rules::triggers::DisableTriggerRule;
use crate::rules::views::MaterializedViewRefreshRule;

/// Stable user-facing metadata and construction for one primary rule.
///
/// Keep this registry in evaluation order. Discovery, configuration validation,
/// documentation checks, and engine construction all read it. Auxiliary
/// findings emitted by a primary rule are not entries.
pub struct RuleDescriptor {
    pub id: &'static str,
    pub title: &'static str,
    pub summary: &'static str,
    pub impact: &'static str,
    pub supported_configuration_fields: &'static [RuleConfigurationField],
    factory: fn() -> Box<dyn Rule>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleConfigurationField {
    Disabled,
    Tier1ThresholdRows,
    Tier2ThresholdRows,
}

impl RuleConfigurationField {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Tier1ThresholdRows => "tier1_threshold_rows",
            Self::Tier2ThresholdRows => "tier2_threshold_rows",
        }
    }
}

const DISABLED_ONLY: &[RuleConfigurationField] = &[RuleConfigurationField::Disabled];
const WITH_TIER1_THRESHOLD: &[RuleConfigurationField] = &[
    RuleConfigurationField::Disabled,
    RuleConfigurationField::Tier1ThresholdRows,
];
const WITH_ROW_THRESHOLDS: &[RuleConfigurationField] = &[
    RuleConfigurationField::Disabled,
    RuleConfigurationField::Tier1ThresholdRows,
    RuleConfigurationField::Tier2ThresholdRows,
];

impl RuleDescriptor {
    pub fn build(&self) -> Box<dyn Rule> {
        (self.factory)()
    }

    pub fn default_tier(&self) -> ViolationTier {
        self.build().default_tier()
    }

    pub fn recipe(&self) -> &'static str {
        self.build().recipe()
    }

    pub fn supports(&self, field: RuleConfigurationField) -> bool {
        self.supported_configuration_fields.contains(&field)
    }
}

macro_rules! descriptor {
    ($id:literal, $title:literal, $summary:literal, $impact:literal, $rule:expr) => {
        descriptor!($id, $title, $summary, $impact, $rule, DISABLED_ONLY)
    };
    ($id:literal, $title:literal, $summary:literal, $impact:literal, $rule:expr, $fields:expr) => {
        RuleDescriptor {
            id: $id,
            title: $title,
            summary: $summary,
            impact: $impact,
            supported_configuration_fields: $fields,
            factory: || Box::new($rule),
        }
    };
}

// Marker rules are currently zero-sized; their constructors are kept in this
// registry so future initialized rules can supply a dedicated factory.
pub static PRIMARY_RULES: &[RuleDescriptor] = &[
    descriptor!(
        "irreversible-migration",
        "Irreversible migration",
        "Flags destructive operations that cannot be reversed.",
        "data loss",
        ReversibilityRule,
        WITH_TIER1_THRESHOLD
    ),
    descriptor!(
        "drop-database",
        "Drop database",
        "Flags database deletion.",
        "data loss",
        DropDatabaseRule
    ),
    descriptor!(
        "drop-schema-cascade",
        "Drop schema with cascade",
        "Flags schema-wide cascading deletion.",
        "data loss",
        DropSchemaCascadeRule
    ),
    descriptor!(
        "destructive-general-cascade",
        "Destructive cascade",
        "Flags cascading non-table drops.",
        "data loss",
        GeneralCascadeRule
    ),
    descriptor!(
        "destructive-cascade",
        "Drop table with cascade",
        "Flags table drops that remove dependencies.",
        "data loss",
        CascadingDropRule
    ),
    descriptor!(
        "create-table-as-select",
        "Create table as select",
        "Flags potentially expensive CTAS operations.",
        "rewrite",
        CreateTableAsSelectRule
    ),
    descriptor!(
        "size-aware-add-column",
        "Add column on a large table",
        "Flags column additions that can rewrite large tables.",
        "rewrite",
        SizeAwareAddColumnRule,
        WITH_TIER1_THRESHOLD
    ),
    descriptor!(
        "type-change-rewrite",
        "Type change rewrite",
        "Flags column type changes that rewrite data.",
        "rewrite",
        TypeChangeRewriteRule,
        WITH_TIER1_THRESHOLD
    ),
    descriptor!(
        "blocking-constraint",
        "Blocking constraint",
        "Flags constraint changes that lock or scan tables.",
        "locking",
        BlockingConstraintRule,
        WITH_ROW_THRESHOLDS
    ),
    descriptor!(
        "require-concurrent-index",
        "Require concurrent index",
        "Flags index changes that should use CONCURRENTLY.",
        "locking",
        ConcurrentIndexRule,
        WITH_ROW_THRESHOLDS
    ),
    descriptor!(
        "require-lock-timeout",
        "Require lock timeout",
        "Flags potentially slow statements without an effective lock timeout.",
        "locking",
        RequireLockTimeoutRule
    ),
    descriptor!(
        "require-statement-timeout",
        "Require statement timeout",
        "Flags potentially slow statements without an effective statement timeout.",
        "operability",
        RequireStatementTimeoutRule
    ),
    descriptor!(
        "blocking-mat-view-refresh",
        "Blocking materialized-view refresh",
        "Flags refreshes that block readers.",
        "locking",
        MaterializedViewRefreshRule,
        WITH_ROW_THRESHOLDS
    ),
    descriptor!(
        "blocking-partition-mutation",
        "Blocking partition mutation",
        "Flags partition attach and detach locks.",
        "locking",
        PartitionLockRule,
        WITH_ROW_THRESHOLDS
    ),
    descriptor!(
        "partition-strategy-mismatch",
        "Partition strategy mismatch",
        "Flags incompatible partition attachment.",
        "correctness",
        PartitionStrategyMismatchRule
    ),
    descriptor!(
        "restrictive-policy",
        "Restrictive policy",
        "Flags policies that narrow row visibility.",
        "access control",
        RestrictivePolicyRule
    ),
    descriptor!(
        "disable-trigger",
        "Disable trigger",
        "Flags disabled triggers.",
        "correctness",
        DisableTriggerRule
    ),
    descriptor!(
        "broken-compute",
        "Broken compute dependency",
        "Flags function drops blocked by trigger dependencies.",
        "correctness",
        BrokenComputeRule
    ),
    descriptor!(
        "function-volatility-change",
        "Function volatility change",
        "Flags changed function volatility.",
        "query planning",
        FunctionVolatilityRule
    ),
    descriptor!(
        "missing-idempotency",
        "Missing idempotency",
        "Flags migrations unsafe to rerun.",
        "operability",
        IdempotencyRule
    ),
    descriptor!(
        "concurrent-in-transaction",
        "Concurrent index in transaction",
        "Flags CONCURRENTLY inside a transaction.",
        "correctness",
        ConcurrentInsideTransactionRule
    ),
    descriptor!(
        "alter-type-add-value-txn",
        "Enum value in transaction",
        "Flags enum additions whose new value is unavailable until commit.",
        "correctness",
        AlterTypeAddValueRule
    ),
    descriptor!(
        "vacuum-full",
        "Vacuum full",
        "Flags VACUUM FULL in migrations.",
        "locking",
        VacuumFullRule
    ),
    descriptor!(
        "opaque-dynamic-sql",
        "Opaque dynamic SQL",
        "Flags SQL whose schema effects cannot be modeled.",
        "confidence",
        OpaqueDynamicSqlRule
    ),
    descriptor!(
        "volatile-default",
        "Volatile default",
        "Flags volatile default expressions.",
        "correctness",
        VolatileDefaultRule
    ),
    descriptor!(
        "overbroad-grant",
        "Overbroad grant",
        "Flags broad public privileges.",
        "access control",
        OverbroadGrantRule
    ),
    descriptor!(
        "schema-drift",
        "Schema drift",
        "Flags references missing from the baseline.",
        "correctness",
        DriftDetectionRule
    ),
    descriptor!(
        "chain-conflict",
        "Migration chain conflict",
        "Flags statements that conflict with prior migration state.",
        "correctness",
        ConflictRule
    ),
];

pub fn primary_rule_ids() -> impl Iterator<Item = &'static str> {
    PRIMARY_RULES.iter().map(|rule| rule.id)
}

pub fn find_primary_rule(id: &str) -> Option<&'static RuleDescriptor> {
    PRIMARY_RULES.iter().find(|rule| rule.id == id)
}

pub fn validate_rule_configuration(config: &crate::engine::config::Config) -> Result<(), String> {
    if config.tier1_threshold_rows < config.tier2_threshold_rows {
        return Err(format!(
            "tier1_threshold_rows ({}) must be greater than or equal to tier2_threshold_rows ({})",
            config.tier1_threshold_rows, config.tier2_threshold_rows
        ));
    }

    let mut rule_ids: Vec<_> = config.rules.keys().map(String::as_str).collect();
    rule_ids.sort_unstable();
    for rule_id in rule_ids {
        let Some(descriptor) = find_primary_rule(rule_id) else {
            // Config::validate_rule_ids reports unknown IDs with the full list.
            continue;
        };
        let rule = &config.rules[rule_id];
        if rule.tier1_threshold_rows.is_some()
            && !descriptor.supports(RuleConfigurationField::Tier1ThresholdRows)
        {
            return Err(format!(
                "Rule '{rule_id}' does not support 'tier1_threshold_rows'"
            ));
        }
        if rule.tier2_threshold_rows.is_some()
            && !descriptor.supports(RuleConfigurationField::Tier2ThresholdRows)
        {
            return Err(format!(
                "Rule '{rule_id}' does not support 'tier2_threshold_rows'"
            ));
        }
        if descriptor.supports(RuleConfigurationField::Tier1ThresholdRows)
            && descriptor.supports(RuleConfigurationField::Tier2ThresholdRows)
        {
            let tier1 = config.rule_tier1_threshold(rule_id);
            let tier2 = config.rule_tier2_threshold(rule_id);
            if tier1 < tier2 {
                return Err(format!(
                    "Rule '{rule_id}' has tier1_threshold_rows ({tier1}) below tier2_threshold_rows ({tier2})"
                ));
            }
        }
    }
    Ok(())
}

pub fn build_primary_rules() -> Vec<Box<dyn Rule>> {
    PRIMARY_RULES.iter().map(RuleDescriptor::build).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn descriptors_have_unique_ids_matching_the_rules_they_construct() {
        let ids: HashSet<_> = PRIMARY_RULES
            .iter()
            .map(|descriptor| descriptor.id)
            .collect();
        assert_eq!(ids.len(), PRIMARY_RULES.len());
        for descriptor in PRIMARY_RULES {
            let rule = descriptor.build();
            assert_eq!(rule.id(), descriptor.id);
            assert_eq!(descriptor.default_tier(), rule.default_tier());
            assert_eq!(descriptor.recipe(), rule.recipe());
        }
    }

    #[test]
    fn descriptors_advertise_only_configuration_the_rules_consume() {
        let tier1_only: HashSet<_> = [
            "irreversible-migration",
            "size-aware-add-column",
            "type-change-rewrite",
        ]
        .into_iter()
        .collect();
        let both_thresholds: HashSet<_> = [
            "blocking-constraint",
            "require-concurrent-index",
            "blocking-mat-view-refresh",
            "blocking-partition-mutation",
        ]
        .into_iter()
        .collect();

        for descriptor in PRIMARY_RULES {
            assert!(descriptor.supports(RuleConfigurationField::Disabled));
            assert_eq!(
                descriptor.supports(RuleConfigurationField::Tier1ThresholdRows),
                tier1_only.contains(descriptor.id) || both_thresholds.contains(descriptor.id),
                "unexpected Tier 1 threshold metadata for {}",
                descriptor.id
            );
            assert_eq!(
                descriptor.supports(RuleConfigurationField::Tier2ThresholdRows),
                both_thresholds.contains(descriptor.id),
                "unexpected Tier 2 threshold metadata for {}",
                descriptor.id
            );
        }
    }

    #[test]
    fn stateful_rules_declare_their_required_capabilities() {
        let expected: HashSet<_> = [
            "destructive-cascade",
            "size-aware-add-column",
            "type-change-rewrite",
            "blocking-constraint",
            "require-concurrent-index",
            "blocking-mat-view-refresh",
            "blocking-partition-mutation",
            "partition-strategy-mismatch",
            "function-volatility-change",
            "broken-compute",
            "concurrent-in-transaction",
            "alter-type-add-value-txn",
            "vacuum-full",
            "schema-drift",
        ]
        .into_iter()
        .collect();

        for descriptor in PRIMARY_RULES {
            let rule = descriptor.build();
            assert_eq!(
                !rule.required_capabilities().is_empty(),
                expected.contains(descriptor.id),
                "capability declaration mismatch for {}",
                descriptor.id
            );
        }
    }

    #[test]
    fn threshold_validation_requires_tier1_at_or_above_tier2() {
        let globally_reversed = crate::engine::config::Config {
            tier1_threshold_rows: 9,
            tier2_threshold_rows: 10,
            ..crate::engine::config::Config::default()
        };
        assert!(
            validate_rule_configuration(&globally_reversed)
                .unwrap_err()
                .contains("tier1_threshold_rows (9)")
        );

        let mut per_rule_reversed = crate::engine::config::Config::default();
        per_rule_reversed.rules.insert(
            "blocking-constraint".into(),
            crate::engine::config::RuleConfig {
                tier1_threshold_rows: Some(5),
                tier2_threshold_rows: Some(6),
                ..crate::engine::config::RuleConfig::default()
            },
        );
        assert!(
            validate_rule_configuration(&per_rule_reversed)
                .unwrap_err()
                .contains("Rule 'blocking-constraint'")
        );
    }

    #[test]
    fn unsupported_per_rule_thresholds_are_rejected() {
        let mut config = crate::engine::config::Config::default();
        config.rules.insert(
            "require-lock-timeout".to_string(),
            crate::engine::config::RuleConfig {
                tier1_threshold_rows: Some(1),
                ..crate::engine::config::RuleConfig::default()
            },
        );

        assert_eq!(
            validate_rule_configuration(&config).unwrap_err(),
            "Rule 'require-lock-timeout' does not support 'tier1_threshold_rows'"
        );
    }
}
