//! PostgreSQL's implicit namespaces.
//!
//! `search_path` is not the whole story. A session that has created a temporary
//! object also has a temporary schema, which is searched *before* `pg_catalog`
//! and before every explicit path entry, and which receives unqualified
//! creations declared `TEMPORARY`. PostgreSQL accepts the alias `pg_temp` for
//! it, so the model uses that as the stable name for the per-session namespace.
//!
//! PostgreSQL searches it for relations and types only, so routines and
//! operators must not consult it.

use crate::_internal::ast::identifiers::ObjectId;

/// The session's temporary schema, under the alias PostgreSQL accepts for it.
pub(crate) const SESSION_TEMP_SCHEMA: &str = "pg_temp";

/// Whether a schema name is the session's temporary schema.
///
/// PostgreSQL resolves the `pg_temp` alias to it; any other `pg_temp_N` belongs
/// to a different session and is unreachable from here.
pub(crate) fn is_session_temp_schema(schema: &str) -> bool {
    schema == SESSION_TEMP_SCHEMA
}

/// A temporary relation is always created in the session schema, so the two are
/// the same identity for lookup purposes.
pub(crate) fn temp_object_id(name: &str) -> ObjectId {
    ObjectId::new(SESSION_TEMP_SCHEMA, name)
}
