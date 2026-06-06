use crate::analysis::mutations::{Mutation, OpaqueMutation};
use crate::analysis::state::AnalysisState;
use crate::report::reporter::Reporter;
use crate::report::violation::{Severity, Violation};
use crate::rules::Rule;

pub struct OpaqueExecutionRule;

impl Rule for OpaqueExecutionRule {
    fn evaluate(&self, mutation: &Mutation, _state: &AnalysisState, reporter: &mut Reporter) {
        if let Mutation::Opaque(OpaqueMutation::DoBlock) = mutation {
            reporter.report(Violation::new(
                Severity::Warning, 
                "Opaque DO block detected. The engine's state confidence is now Tainted."
            ));
        }
    }
}
