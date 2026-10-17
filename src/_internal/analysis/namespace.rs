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

/// The schema every database has, which sync deliberately does not model.
///
/// PostgreSQL searches it before every explicit path entry unless the path
/// names it, so entries of this name stay in the effective path even though no
/// `SchemaOverlay` will ever exist for them.
pub(crate) const SYSTEM_CATALOG_SCHEMA: &str = "pg_catalog";

/// One entry of the effective `search_path`, in session order.
///
/// PostgreSQL silently ignores a path entry that does not name an existing
/// schema, so every entry is either a schema the model can search or a
/// position whose contents are unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SearchPathEntry {
    /// A schema the model searches: one whose presence it can prove, or the
    /// implicitly existing system catalog.
    Schema(String),
    /// An entry the model cannot search: `$user` under an unknown role (no
    /// name is carried) or a schema whose existence sync cannot prove (its
    /// written name is carried). Such an entry may still exist on the server
    /// and may hold any object, so a lookup that resolves past one is not
    /// certain, and one cannot serve as a creation target.
    Unresolved(Option<String>),
}

impl SearchPathEntry {
    /// The schema this entry names, when it names one — searched or not.
    pub(crate) fn name(&self) -> Option<&str> {
        match self {
            Self::Schema(name) => Some(name),
            Self::Unresolved(name) => name.as_deref(),
        }
    }

    pub(crate) fn searched_schema(&self) -> Option<&str> {
        match self {
            Self::Schema(name) => Some(name),
            Self::Unresolved(_) => None,
        }
    }

    /// Entries for a path captured as plain catalog names, as cache metadata
    /// stores it: every recorded name is searchable there.
    pub(crate) fn from_catalog_names(names: &[String]) -> Vec<Self> {
        names
            .iter()
            .map(|name| Self::Schema(name.clone()))
            .collect()
    }
}

/// Resolve an unqualified object name through the effective search path.
///
/// `pg_catalog` is searched before every explicit entry unless the path names
/// it, in which case its written position decides. An entry the model cannot
/// search may hold the object, so a name found past one is not the one
/// PostgreSQL chose with certainty.
pub(crate) fn resolve_unqualified<T>(
    search_path: &[SearchPathEntry],
    lookup: impl Fn(&str) -> Option<T>,
) -> Option<T> {
    if !search_path
        .iter()
        .any(|entry| entry.searched_schema() == Some(SYSTEM_CATALOG_SCHEMA))
        && let Some(found) = lookup(SYSTEM_CATALOG_SCHEMA)
    {
        return Some(found);
    }
    let mut shadowed = false;
    for entry in search_path {
        match entry {
            SearchPathEntry::Unresolved(_) => shadowed = true,
            SearchPathEntry::Schema(schema) => {
                if let Some(found) = lookup(schema) {
                    return if shadowed { None } else { Some(found) };
                }
            }
        }
    }
    None
}

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
