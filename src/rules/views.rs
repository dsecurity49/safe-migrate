use crate::analysis::mutations::Mutation;
use crate::analysis::state::MutationResult;
use crate::model::relation::Persistence;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::rules::{BASELINE_STATS_CAPABILITIES, Rule, RuleCapability, RuleContext};

pub struct MaterializedViewRefreshRule;

impl Rule for MaterializedViewRefreshRule {
    fn id(&self) -> &'static str {
        "blocking-mat-view-refresh"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "Refreshing a materialized view without CONCURRENTLY prevents reading from it during the refresh."
    }

    fn required_capabilities(&self) -> &'static [RuleCapability] {
        BASELINE_STATS_CAPABILITIES
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        if *context.result() == MutationResult::Skipped {
            return vec![];
        }

        let mut violations = Vec::new();

        if let Mutation::RefreshMaterializedView(refresh) = context.mutation() {
            if !refresh.concurrently {
                let (is_temp, is_stale, rows) = match context.pre_state().relations.get(&refresh.id)
                {
                    Some(rel) => {
                        let stale = rel.is_stale()
                            && context.state().baseline_relations.contains(&refresh.id);
                        (
                            rel.persistence == Persistence::Temporary,
                            stale,
                            rel.estimated_rows.unwrap_or(context.config().default_rows),
                        )
                    }
                    None => (false, true, context.config().default_rows),
                };

                if is_temp {
                    return violations;
                }

                if is_stale {
                    let key = format!("{}_stale_{}", self.id(), refresh.id);
                    violations.push(Violation { source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::RefreshMaterializedView,
                        object_kind: ObjectKind::MaterializedView,
                        object_name: refresh.id.to_string(),
                        tier: ViolationTier::Tier2,
                        reason: format!("Materialized view {} statistics are stale. Lock evaluations may be inaccurate.", refresh.id),
                        recipe: "Run ANALYZE to ensure accurate row estimates.",
                        dedup_key: Some(key),
                                    sql: None,
                                    fk_dependency_related: false,
                    });
                }

                let tier1_threshold = context.config().rule_tier1_threshold(self.id());
                let tier2_threshold = context.config().rule_tier2_threshold(self.id());

                let tier = if rows >= tier1_threshold {
                    ViolationTier::Tier1
                } else if rows >= tier2_threshold {
                    ViolationTier::Tier2
                } else {
                    ViolationTier::Tier3
                };

                if tier != ViolationTier::Tier3 {
                    let mut reason =
                        format!("Blocking materialized view refresh on {}", refresh.id);
                    if is_stale {
                        reason.push_str(" [WARNING: Based on offline/stale statistics]");
                    }

                    violations.push(Violation {
                        source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::RefreshMaterializedView,
                        object_kind: ObjectKind::MaterializedView,
                        object_name: refresh.id.to_string(),
                        tier,
                        reason,
                        recipe: self.recipe(),
                        dedup_key: None,
                        sql: None,
                        fk_dependency_related: false,
                    });
                }
            } else {
                // CONCURRENTLY refresh requires at least one unique index
                let has_unique_index = context.state().local.graph.edges().iter().any(|e| {
                    if let crate::analysis::graph::DependencyKind::IndexOnRelation {
                        is_unique,
                        has_expression_keys,
                        has_predicate,
                        is_valid,
                        is_ready,
                        is_live,
                        eligibility_known,
                        ..
                    } = &e.kind
                    {
                        e.referenced == refresh.id
                            && *eligibility_known
                            && *is_unique
                            && !*has_expression_keys
                            && !*has_predicate
                            && *is_valid
                            && *is_ready
                            && *is_live
                    } else {
                        false
                    }
                });

                if !has_unique_index {
                    violations.push(Violation { source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::RefreshMaterializedView,
                        object_kind: ObjectKind::MaterializedView,
                        object_name: refresh.id.to_string(),
                        tier: ViolationTier::Tier1,
                        reason: format!("REFRESH MATERIALIZED VIEW CONCURRENTLY on {} requires a unique index", refresh.id),
                        recipe: "Create a unique index on the materialized view before attempting a concurrent refresh.",
                        dedup_key: None,
                                    sql: None,
                                    fk_dependency_related: false,
                    });
                }
            }
        }
        violations
    }
}
