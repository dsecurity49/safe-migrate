use crate::analysis::mutations::Mutation;
use crate::analysis::state::MutationResult;
use crate::report::violations::{ObjectKind, OperationKind, Violation, ViolationTier};
use crate::rules::{FUNCTION_CAPABILITIES, Rule, RuleCapability, RuleContext};

pub struct FunctionVolatilityRule;

impl Rule for FunctionVolatilityRule {
    fn id(&self) -> &'static str {
        "function-volatility-change"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier2
    }
    fn recipe(&self) -> &'static str {
        "Changing a function's volatility (e.g., IMMUTABLE -> VOLATILE) can invalidate existing indexes or change query plan stability."
    }

    fn required_capabilities(&self) -> &'static [RuleCapability] {
        FUNCTION_CAPABILITIES
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        let mut violations = Vec::new();

        if let Mutation::AlterFunction(alter) = context.mutation()
            && let Some(old_func) = context.pre_state().functions.get(&alter.id)
            && let crate::analysis::facts::AlterFunctionAction::OptionsChange(new_opts) =
                &alter.action
            && let Some(nv) = new_opts.iter().find_map(|opt| {
                if let crate::analysis::facts::FuncOptionFact::Volatility(v) = opt {
                    match v {
                        crate::analysis::facts::VolatilityKind::Volatile => {
                            Some(crate::model::function::Volatility::Volatile)
                        }
                        crate::analysis::facts::VolatilityKind::Stable => {
                            Some(crate::model::function::Volatility::Stable)
                        }
                        crate::analysis::facts::VolatilityKind::Immutable => {
                            Some(crate::model::function::Volatility::Immutable)
                        }
                    }
                } else {
                    None
                }
            })
        {
            let ov = old_func.volatility.clone();
            if ov != nv {
                violations.push(Violation {
                    source_range: None,
                    rule_id: self.id(),
                    operation_kind: OperationKind::AlterFunction,
                    object_kind: ObjectKind::Function,
                    object_name: alter.id.to_string(),
                    tier: self.default_tier(),
                    reason: format!(
                        "Function {} volatility changed from {:?} to {:?}",
                        alter.id, ov, nv
                    ),
                    recipe: self.recipe(),
                    dedup_key: None,
                    sql: None,
                    fk_dependency_related: false,
                });
            }
        }

        violations
    }
}

pub struct BrokenComputeRule;

impl Rule for BrokenComputeRule {
    fn id(&self) -> &'static str {
        "broken-compute"
    }
    fn default_tier(&self) -> ViolationTier {
        ViolationTier::Tier1
    }
    fn recipe(&self) -> &'static str {
        "Drop or replace the dependent triggers first. Use CASCADE only after reviewing every dependent object."
    }

    fn required_capabilities(&self) -> &'static [RuleCapability] {
        FUNCTION_CAPABILITIES
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> Vec<Violation> {
        if !matches!(context.result(), MutationResult::Conflict { .. }) {
            return vec![];
        }
        if let Mutation::DropFunction(drop) = context.mutation()
            && !drop.cascade
        {
            for sig in &drop.signatures {
                let sig_str = format!("{}({})", sig.name.name.resolve(), sig.params.join(","));
                let schema = context.state().resolve_function_schema(&sig.name, &sig_str);
                let function_id = crate::ast::identifiers::ObjectId::new(schema, sig_str);

                let affected = context
                    .state()
                    .local
                    .graph
                    .triggers_for_function(&function_id);

                if !affected.is_empty() {
                    let triggers_info: Vec<String> = affected
                        .iter()
                        .map(|t| format!("trigger {} on table {}", t.dependent, t.referenced))
                        .collect();

                    return vec![Violation {
                        source_range: None,
                        rule_id: self.id(),
                        operation_kind: OperationKind::DropFunction,
                        object_kind: ObjectKind::Function,
                        object_name: function_id.to_string(),
                        tier: self.default_tier(),
                        reason: format!(
                            "PostgreSQL rejects this function drop because it is used by {}",
                            triggers_info.join(", ")
                        ),
                        recipe: self.recipe(),
                        dedup_key: None,
                        sql: None,
                        fk_dependency_related: false,
                    }];
                }
            }
        }
        vec![]
    }
}
