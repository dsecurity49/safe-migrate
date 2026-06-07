use crate::analysis::mutations::Mutation;
use crate::analysis::state::AnalysisState;
use crate::report::reporter::Reporter;
use crate::report::violations::{Severity, Violation};
use crate::rules::Rule;

/// Fires a warning whenever a DROP TABLE is encountered.
///
/// If the statement uses IF EXISTS the severity is lowered —
/// the author acknowledged the table may not be there, which
/// is a weaker signal than an unconditional drop.
pub struct DestructiveDropRule;

impl Rule for DestructiveDropRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        _state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        // FIX B1: Mutation::DropTable is a tuple variant — Mutation::DropTable(DropTable { .. })
        // The old code used struct-variant syntax { id } which does not compile.
        if let Mutation::DropTable(drop) = mutation {
            let severity = if drop.if_exists {
                Severity::Warning
            } else {
                Severity::Error
            };

            reporter.report(Violation::new(
                severity,
                format!(
                    "Destructive operation: DROP TABLE '{}'. \
                     Ensure this table is no longer needed before applying.",
                    drop.id   // ObjectId implements Display as schema.name
                ),
            ));
        }
    }
}
