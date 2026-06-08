use crate::analysis::mutations::{AlterTableActionMutation, Mutation};
use crate::analysis::state::AnalysisState;
use crate::report::reporter::Reporter;
use crate::report::violations::{Severity, Violation};
use crate::rules::Rule;

// ─────────────────────────────────────────────
// VolatileDefaultRule
//
// Fires when ADD COLUMN or SET DEFAULT uses a
// volatile default expression — one whose return
// value changes on every call (now(), random(),
// gen_random_uuid(), etc.).
//
// On PostgreSQL < 11, any non-NULL default on
// ADD COLUMN causes a full table rewrite with an
// ACCESS EXCLUSIVE lock. On PG 11+ only volatile
// defaults cause the rewrite; stable/immutable
// defaults are stored as metadata.
//
// This rule now uses real ExprIr::is_volatile()
// evaluation rather than the previous type-string
// heuristic. If no default was extracted (None),
// no violation is emitted — we don't guess.
// ─────────────────────────────────────────────

pub struct VolatileDefaultRule;

impl Rule for VolatileDefaultRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        _state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if let Mutation::AlterTable(alter) = mutation {
            match &alter.action {
                // ADD COLUMN with a volatile default.
                AlterTableActionMutation::AddColumn { name, default: Some(expr), .. } => {
                    if expr.is_volatile() {
                        reporter.report(Violation::new(
                            Severity::Warning,
                            format!(
                                "ADD COLUMN '{}' on '{}': volatile default expression detected. \
                                 On PostgreSQL < 11 this causes a full table rewrite with an \
                                 ACCESS EXCLUSIVE lock. On PG 11+ only volatile defaults trigger \
                                 a rewrite — consider using a stable or immutable expression.",
                                name, alter.id
                            ),
                        ));
                    }
                }

                // SET DEFAULT with a volatile expression.
                AlterTableActionMutation::SetDefault { column, default: Some(expr) } => {
                    if expr.is_volatile() {
                        reporter.report(Violation::new(
                            Severity::Warning,
                            format!(
                                "ALTER COLUMN '{}' SET DEFAULT on '{}': volatile default \
                                 expression detected. Future ADD COLUMN operations using this \
                                 default will trigger a full table rewrite on PostgreSQL < 11.",
                                column, alter.id
                            ),
                        ));
                    }
                }

                _ => {}
            }
        }
    }
}

// ─────────────────────────────────────────────
// SetTypeRule
//
// Fires when ALTER COLUMN SET TYPE is used.
//
// SET TYPE takes an ACCESS EXCLUSIVE lock and
// rewrites the entire table unless the cast is
// binary-compatible (e.g. varchar(50) → varchar(100),
// or int2 → int4 on some platforms).
//
// We cannot determine binary compatibility
// statically without a full type compatibility
// table. We always warn and let the author
// confirm whether their cast is safe.
//
// The safe alternative for non-binary-compatible
// casts on live tables:
//   1. ADD COLUMN new_col new_type
//   2. UPDATE table SET new_col = old_col::new_type
//   3. DROP COLUMN old_col
//   4. RENAME COLUMN new_col TO old_col
// ─────────────────────────────────────────────

pub struct SetTypeRule;

impl Rule for SetTypeRule {
    fn evaluate(
        &self,
        mutation: &Mutation,
        state: &AnalysisState,
        reporter: &mut Reporter,
    ) {
        if let Mutation::AlterTable(alter) = mutation {
            if let AlterTableActionMutation::SetType { column, ty } = &alter.action {
                // Get the current type so we can include it in the message.
                let current_type = state
                    .get_relation(&alter.id)
                    .and_then(|overlay| {
                        if let crate::model::relation::RelationOverlay::Present(rel) = overlay {
                            rel.get_column(column)
                                .and_then(|c| c.data_type.as_deref())
                                .map(|t| t.to_string())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| "<unknown>".to_string());

                reporter.report(Violation::new(
                    Severity::Warning,
                    format!(
                        "ALTER COLUMN '{}' SET TYPE '{}' (was '{}') on '{}': requires \
                         ACCESS EXCLUSIVE lock and rewrites the table unless the cast is \
                         binary-compatible. Verify the cast is safe, or use the \
                         add-copy-drop-rename pattern for zero-downtime type changes.",
                        column, ty, current_type, alter.id
                    ),
                ));
            }
        }
    }
}
