// src/rules/constraints.rs
use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::state::AnalysisState;
use crate::report::reporter::Reporter;
use crate::report::violation::{Severity, Violation};
use crate::rules::Rule;

pub struct SafeAddColumnRule;

impl Rule for SafeAddColumnRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if let Mutation::AlterTable(m) = mutation {
            if let AlterTableActionMutation::AddColumn { name } = &m.action {
                // We can query the state here! Does the table exist?
                if state.get_relation(&m.id).is_none() {
                    reporter.report(Violation::new(
                        Severity::Error,
                        format!("Cannot add column '{}' to table '{}' because the table does not exist.", name, m.id.name)
                    ));
                } else {
                    reporter.report(Violation::new(
                        Severity::Warning,
                        format!("Adding column '{}' to '{}'. Ensure it is nullable or has a default value.", name, m.id.name)
                    ));
                }
            }
        }
    }
}
