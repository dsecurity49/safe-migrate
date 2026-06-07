use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::state::AnalysisState;
use crate::report::reporter::Reporter;
use crate::report::violations::{Severity, Violation};
use crate::rules::Rule;

/// Detects ADD COLUMN statements where the column type or name
/// pattern suggests a volatile default would be needed at apply time.
///
/// ## Current implementation
/// Full ExprIr-based default analysis is not yet wired through the
/// visitor. Until it is, we inspect the raw type string for patterns
/// known to commonly pair with volatile defaults:
///   - timestamptz / timestamp  → authors often pair with now()
///   - uuid                     → authors often pair with gen_random_uuid()
///
/// This is a heuristic warning, not a certain violation. The rule will
/// be upgraded to full ExprIr evaluation once default extraction is
/// implemented in the visitor (Phase 2).
pub struct VolatileDefaultRule;

impl Rule for VolatileDefaultRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        _state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        // FIX B1: tuple variant — Mutation::AlterTable(alter), not { id, action }
        // FIX B2: AddColumn has no `default` field — that was never defined.
        //         We work against `ty: Option<String>` instead.
        if let Mutation::AlterTable(alter) = mutation {
            if let AlterTableActionMutation::AddColumn { name, ty, .. } = &alter.action {
                if let Some(type_str) = ty {
                    if Self::type_commonly_volatile(type_str) {
                        reporter.report(Violation::new(
                            Severity::Warning,
                            format!(
                                "ADD COLUMN '{}' on '{}': type '{}' is commonly paired with a \
                                 volatile default (e.g. now(), gen_random_uuid()). If a volatile \
                                 default is present this will force a full table rewrite on \
                                 PostgreSQL < 11.",
                                name, alter.id, type_str
                            ),
                        ));
                    }
                }
            }
        }
    }
}

impl VolatileDefaultRule {
    /// Returns true for type strings that are commonly paired with
    /// volatile default expressions in real migrations.
    ///
    /// Matching is case-insensitive and substring-based so that
    /// qualified forms like `pg_catalog.timestamptz` also match.
    fn type_commonly_volatile(ty: &str) -> bool {
        let lower = ty.to_lowercase();
        lower.contains("timestamptz")
            || lower.contains("timestamp")
            || lower.contains("uuid")
    }
}
