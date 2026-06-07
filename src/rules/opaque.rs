// src/rules/opaque.rs
use crate::analysis::mutations::{Mutation, OpaqueMutation};
use crate::analysis::state::AnalysisState;
use crate::report::reporter::Reporter;
use crate::report::violations::{Severity, Violation};
use crate::rules::Rule;

pub struct OpaqueExecutionRule;

impl Rule for OpaqueExecutionRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        _state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if matches!(
            mutation,
            Mutation::Opaque(
                OpaqueMutation::DoBlock
                    | OpaqueMutation::Execute
                    | OpaqueMutation::DynamicSql
            )
        ) {
            reporter.report(Violation::new(
                Severity::Warning,
                "Opaque execution detected. Confidence should be treated as tainted.",
            ));
        }
    }
}
