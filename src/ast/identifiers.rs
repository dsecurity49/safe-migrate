// AST identity types
//
// This module contains ONLY syntactic forms —
// types that come directly off the AST before
// any resolution has occurred.
//
// INVARIANT: QualifiedName is NEVER used for
// state lookups. It is always resolved into an
// ObjectId (defined in crate::model::relation)
// by the Resolver before touching AnalysisState.
// ─────────────────────────────────────────────

// Re-export ObjectId here so the rest of the
// analysis layer can use a single import path:
//   use crate::ast::identifiers::{ObjectId, QualifiedName};
// without breaking the canonical ownership in
// model::relation.
pub use crate::model::relation::ObjectId;

/// A raw, unresolved identifier extracted directly from the AST.
///
/// `schema` is `None` when the SQL did not include a schema qualifier
/// (e.g. `users` vs `public.users`). The Resolver expands the `None`
/// case using the current simulated `search_path`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QualifiedName {
    pub schema: Option<String>,
    pub name: String,
}

impl QualifiedName {
    pub fn new(schema: Option<String>, name: impl Into<String>) -> Self {
        Self {
            schema,
            name: name.into(),
        }
    }
}
