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
use crate::rules::transactions::{
    AlterTypeAddValueRule, ConcurrentInsideTransactionRule, VacuumFullRule,
};
use crate::rules::triggers::DisableTriggerRule;
use crate::rules::views::MaterializedViewRefreshRule;

/// Stable user-facing metadata and construction for one primary rule.
///
/// Keep this registry in evaluation order. It is the canonical source for
/// rule discovery, configuration validation, documentation checks, and engine
/// construction; auxiliary findings emitted by a primary rule are not entries.
pub struct RuleDescriptor {
    pub id: &'static str,
    pub title: &'static str,
    pub summary: &'static str,
    pub impact: &'static str,
    factory: fn() -> Box<dyn Rule>,
}

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
}

macro_rules! descriptor {
    ($id:literal, $title:literal, $summary:literal, $impact:literal, $rule:expr) => {
        RuleDescriptor {
            id: $id,
            title: $title,
            summary: $summary,
            impact: $impact,
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
        ReversibilityRule
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
        SizeAwareAddColumnRule
    ),
    descriptor!(
        "type-change-rewrite",
        "Type change rewrite",
        "Flags column type changes that rewrite data.",
        "rewrite",
        TypeChangeRewriteRule
    ),
    descriptor!(
        "blocking-constraint",
        "Blocking constraint",
        "Flags constraint changes that lock or scan tables.",
        "locking",
        BlockingConstraintRule
    ),
    descriptor!(
        "require-concurrent-index",
        "Require concurrent index",
        "Flags index changes that should use CONCURRENTLY.",
        "locking",
        ConcurrentIndexRule
    ),
    descriptor!(
        "blocking-mat-view-refresh",
        "Blocking materialized-view refresh",
        "Flags refreshes that block readers.",
        "locking",
        MaterializedViewRefreshRule
    ),
    descriptor!(
        "blocking-partition-mutation",
        "Blocking partition mutation",
        "Flags partition attach and detach locks.",
        "locking",
        PartitionLockRule
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
        "Flags function changes that break triggers.",
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
        "Flags ALTER TYPE ADD VALUE in a transaction.",
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
}
