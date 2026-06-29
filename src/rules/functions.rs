use crate::analysis::mutations::Mutation;
use crate::analysis::state::{AnalysisState, CascadeResult, MutationResult, PreState};
use crate::engine::config::Config;
use crate::report::violations::{Violation, ViolationTier};
use crate::rules::Rule;

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

    fn evaluate(
        &self,
        mutation: &Mutation,
        _result: &MutationResult,
        pre_state: &PreState,
        _state: &AnalysisState,
        _config: &Config,
        _cascade: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        if let Mutation::AlterFunction(alter) = mutation
            && let Some(old_func) = pre_state.functions.get(&alter.id)
            && let crate::analysis::facts::AlterFunctionAction::OptionsChange(new_opts) = &alter.action
        {
            let ov = old_func.volatility.clone();
            let new_vol = new_opts.iter().find_map(|opt| {
                if let crate::analysis::facts::FuncOptionFact::Volatility(v) = opt {
                    match v {
                        crate::analysis::facts::VolatilityKind::Volatile => Some(crate::model::function::Volatility::Volatile),
                        crate::analysis::facts::VolatilityKind::Stable => Some(crate::model::function::Volatility::Stable),
                        crate::analysis::facts::VolatilityKind::Immutable => Some(crate::model::function::Volatility::Immutable),
                    }
                } else {
                    None
                }
            });

            if let Some(nv) = new_vol
                && ov != nv
            {
                violations.push(Violation {
                    rule_id: self.id(),
                    title: format!(
                        "Function {} volatility changed from {:?} to {:?}",
                        alter.id, ov, nv
                    ),
                    tier: self.default_tier(),
                    recipe: self.recipe(),
                    dedup_key: None,
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
        "Dropping a function used by a trigger will cause the trigger to fail at runtime."
    }

    fn evaluate(
        &self,
        mutation: &Mutation,
        _result: &MutationResult,
        _pre_state: &PreState,
        state: &AnalysisState,
        _config: &Config,
        _cascade_closure: Option<&CascadeResult>,
    ) -> Vec<Violation> {
        if let Mutation::DropFunction(drop) = mutation {
            for sig in &drop.signatures {
                // Construct ID in same way as during creation
                let function_id = crate::ast::identifiers::ObjectId::new(
                    sig.name.schema.as_ref().map(|s| s.resolve()).unwrap_or_else(|| "public".to_string()),
                    format!("{}({})", sig.name.name.resolve(), sig.params.join(","))
                );

                let affected = state.local.graph.triggers_for_function(&function_id);

                if !affected.is_empty() {
                    let triggers_info: Vec<String> = affected.iter()
                        .map(|t| format!("trigger {} on table {}", t.trigger_id, t.table_id))
                        .collect();

                    return vec![Violation {
                        rule_id: self.id(),
                        title: format!("Broken Compute: Dropping Function Used by Trigger: {}", triggers_info.join(", ")),
                        tier: self.default_tier(),
                        recipe: self.recipe(),
                        dedup_key: None,
                    }];
                }
            }
        }
        vec![]
    }
}
