use crate::analysis::mutations::Mutation;
use crate::analysis::state::AnalysisState;
use crate::report::reporter::Reporter;
use crate::report::violations::{Severity, Violation};
use crate::rules::Rule;

pub struct DestructiveDropRule;

impl Rule for DestructiveDropRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        _state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        // Correctly match the inline struct variant here:
        if let Mutation::DropTable { id } = mutation {
            reporter.report(Violation::new(
                Severity::Warning,
                format!("Destructive operation detected: dropping table '{}.{}'", id.schema, id.name),
            ));
        }
    }
}
