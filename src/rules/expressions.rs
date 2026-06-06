// src/rules/expressions.rs
use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::state::AnalysisState;
use crate::report::Reporter;
use crate::rules::Rule;

pub struct VolatileDefaultRule;

impl Rule for VolatileDefaultRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        _state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if let Mutation::AlterTable { id, action } = mutation {
            if let AlterTableActionMutation::AddColumn { name, default: Some(expr), .. } = action {
                if expr.is_volatile() {
                    reporter.report(format!(
                        "DANGER: Adding column '{}.{}' with a volatile default expression. This will force a full table rewrite and lock the table!",
                        id.name, name
                    ));
                }
            }
        }
    }
}
