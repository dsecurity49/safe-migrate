use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::builtin_type::BuiltinTypeCatalogue;
use crate::_internal::model::constraint::{ConstraintKind, ConstraintState};
use crate::_internal::model::extension::{ExtensionMemberKind, ExtensionState};
use crate::_internal::model::function::FunctionState;
use crate::_internal::model::relation::{RelationKind, RelationState};
use crate::_internal::model::replication::{PublicationState, SubscriptionState};
use crate::_internal::model::role::{RoleMembershipGrantor, RoleState};
use crate::_internal::model::schema::SchemaState;
use crate::_internal::model::sequence::{SequenceKind, SequenceState};
use crate::_internal::model::trigger::TriggerEnableMode;
use crate::_internal::model::types::{TypeKind, TypeState};
use serde::{Deserialize, Serialize};

use crate::_internal::model::index::IndexDefinition;
use std::collections::{BTreeSet, HashMap, HashSet};

mod coverage;
mod entries;
#[cfg(test)]
mod tests;
mod validate;
pub(crate) use coverage::*;
pub(crate) use entries::*;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct CacheMetadata {
    /// Seconds since the Unix epoch when `safe-migrate sync` assembled this
    /// baseline. `None` represents a cache written before provenance support.
    pub created_at_unix_secs: Option<u64>,
    /// Whether all scope-boundary dependency queries completed in the same
    /// repeatable-read synchronization transaction. This is deliberately
    /// explicit: timestamps identify age, not catalog-query completeness.
    #[serde(default)]
    pub boundary_queries_complete: bool,
    /// PostgreSQL database name only; connection credentials and host details
    /// are deliberately never stored in a cache.
    pub source_database: Option<String>,
    /// Session role used when the cache was synchronized. This is needed to
    /// resolve PostgreSQL's special `$user` search-path entry.
    pub source_role: Option<String>,
    /// `SESSION_USER` at synchronization time. This remains distinct from
    /// `source_role` when the connection has selected another effective role.
    pub source_session_role: Option<String>,
    /// Parsed `search_path` setting before PostgreSQL expands `$user`.
    pub source_search_path: Option<Vec<String>>,
    /// Every schema that existed at sync time, before the scope filter. A
    /// default search-path entry absent here named no schema then, which
    /// PostgreSQL skips rather than resolving.
    pub source_existing_schemas: Option<Vec<String>>,
    /// Effective `lock_timeout` observed on the fresh synchronization
    /// connection, normalized to milliseconds. PostgreSQL uses zero to mean
    /// that the timeout is disabled.
    pub source_lock_timeout_ms: u64,
    /// Effective `statement_timeout` observed on the fresh synchronization
    /// connection, normalized to milliseconds. PostgreSQL uses zero to mean
    /// that the timeout is disabled.
    pub source_statement_timeout_ms: u64,
    /// Explicit schema scope passed to sync. `None` means all non-system
    /// schemas were requested.
    pub schemas: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DbCache {
    pub pg_version_num: Option<u32>,
    pub metadata: CacheMetadata,
    pub coverage: CatalogCoverage,
    pub search_path: Vec<String>,
    pub relations: HashMap<ObjectId, RelationState>,
    pub foreign_keys: Vec<ForeignKeyCache>,
    pub indexes: Vec<IndexCache>,
    pub constraints: Vec<ConstraintState>,
    pub constraint_keys: Vec<ConstraintKeyCache>,
    pub constraint_dependencies: Vec<ConstraintDependencyCache>,
    pub generated_column_dependencies: Vec<GeneratedColumnDependencyCache>,
    pub default_sequence_dependencies: Vec<DefaultSequenceDependencyCache>,
    pub triggers: Vec<TriggerCache>,
    pub functions: HashMap<ObjectId, FunctionState>,
    pub types: HashMap<ObjectId, TypeState>,
    pub roles: HashMap<ObjectId, RoleState>,
    /// Grantor provenance for role memberships, used by membership CASCADE.
    /// PostgreSQL bookkeeping allows several records per (member, role) pair,
    /// one per grantor, each carrying its own option flags.
    #[serde(default)]
    pub role_membership_grantors: Vec<RoleMembershipGrantor>,
    /// True only when the synchronizer queried every membership grantor row.
    #[serde(default)]
    pub role_membership_grantors_complete: bool,
    /// The cluster's bootstrap superuser (the role PostgreSQL 16+ attributes
    /// implicit superuser-issued role grants to, via `BOOTSTRAP_SUPERUSERID`).
    /// Absent when a programmatic cache did not record it.
    #[serde(default)]
    pub bootstrap_superuser: Option<String>,
    pub schemas: HashMap<String, SchemaState>,
    /// Built-in types of the synchronized cluster, derived from `pg_type`.
    ///
    /// `None` when no baseline was synchronized, which is distinct from an
    /// empty catalogue: the former means "unknown", the latter cannot occur
    /// against a real server.
    pub builtin_types: Option<BuiltinTypeCatalogue>,
    pub opclasses: Option<crate::_internal::model::opclass::OpclassCatalogue>,
    /// Collations of the synchronized cluster, as `pg_collation` records them.
    ///
    /// `None` when no baseline was synchronized, which is distinct from an
    /// empty catalogue: written collations stay unresolved rather than
    /// equated.
    pub collations: Option<crate::_internal::model::collation::CollationCatalogue>,
    /// The cluster's implicit casts, from `pg_cast`. `None` when unsynchronized.
    pub casts: Option<crate::_internal::model::cast::CastCatalogue>,
    /// The built-in `pg_catalog` aggregate signatures. `None` when unsynchronized.
    pub aggregates: Option<crate::_internal::model::aggregate::AggregateCatalogue>,
    pub sequences: HashMap<ObjectId, SequenceState>,
    /// PostgreSQL extensions, keyed by extension name. Extensions are
    /// database-global, unlike every schema-scoped catalog family.
    pub extensions: HashMap<String, ExtensionState>,
    pub dependencies: Vec<ViewDependencyCache>,
    /// Dependencies from a view to a routine or type, which the relation
    /// dependency rows cannot express.
    pub view_object_dependencies: Vec<ViewObjectDependencyCache>,
    /// Every observed cross-scope dependency edge, tagged with the catalog
    /// family of the in-scope endpoint. Scoped destructive transitions stay
    /// conservative for these identities; an absent entry means no external
    /// dependent was observed when the boundary query ran.
    pub scoped_external_dependencies: Vec<ScopedDependencyEdge>,
    /// Schemas outside the synchronized scope that depend on an in-scope object
    /// through a catalog class this build does not model as an object, such as
    /// an operator. They cannot be attributed to a catalog family, but a
    /// consumer still has to be told that widening the scope would change the
    /// answer.
    pub external_referencing_schemas: Vec<String>,
    pub inheritances: Vec<InheritanceCache>,
    pub index_attachments: Vec<IndexAttachmentCache>,
    pub publications: HashMap<String, PublicationState>,
    pub subscriptions: HashMap<String, SubscriptionState>,
    #[serde(skip)]
    pub routine_dependencies: Vec<RoutineDependencyCache>,
}

// Durable cache layout version.
//
// Any change to the fields of `DbCache` or `DbCacheVersioned` requires bumping
// this: bincode carries no field names, so bytes are laid out exactly as the
// current definitions describe. The header encodes the same number, and the
// magic must stay one digit wide or the fixed-size prefix read breaks.
pub(crate) const CACHE_FORMAT_VERSION: u32 = 12;

/// Current durable cache header. V12 adds parsed catalog index predicates and
/// expression keys; V11 added extension membership and the full
/// type/domain/sequence state.
pub(crate) const CACHE_MAGIC: &[u8] = b"SMCACHE12";

// The prefix read in `api.rs` consumes a fixed number of bytes, so the magic
// must stay the same width as the version grows. Two version digits fit.
const _: () = assert!(
    CACHE_MAGIC.len() == 9,
    "the cache magic must stay 9 bytes; a wider version needs a new prefix read"
);

/// Typed extension payload appended in Cache V12.1 while keeping the major V12
/// (`SMCACHE12`) header and `DbCache` base layout backward-compatible with V12.0.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CacheExtensionV12_1 {
    pub casts: Vec<crate::_internal::model::cast::CastEntry>,
    pub routine_dependencies: Vec<RoutineDependencyCache>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DbCacheVersioned {
    // Unit variants reserve the historic bincode discriminants. The reader
    // rejects non-current headers before decoding, so legacy layouts are not part
    // of the production model and cannot be converted accidentally.
    V1,
    V2,
    V3,
    V4,
    V5(Box<DbCache>),
    V6(Box<DbCache>),
    V7(Box<DbCache>),
    V8(Box<DbCache>),
    V9(Box<DbCache>),
    V10(Box<DbCache>),
    V11(Box<DbCache>),
    V12(Box<DbCache>),
    V12_1(Box<DbCache>, CacheExtensionV12_1),
}

impl DbCacheVersioned {
    /// The variant this build writes. Naming it in one place keeps a format
    /// bump from silently leaving a writer or a fixture on a stale layout.
    pub(crate) fn current(cache: DbCache) -> Self {
        let ext = CacheExtensionV12_1 {
            casts: cache
                .casts
                .as_ref()
                .map(|c| c.entries())
                .unwrap_or_default(),
            routine_dependencies: cache.routine_dependencies.clone(),
        };
        DbCacheVersioned::V12_1(Box::new(cache), ext)
    }

    pub(crate) fn format_version(&self) -> u32 {
        match self {
            DbCacheVersioned::V1 => 1,
            DbCacheVersioned::V2 => 2,
            DbCacheVersioned::V3 => 3,
            DbCacheVersioned::V4 => 4,
            DbCacheVersioned::V5(_) => 5,
            DbCacheVersioned::V6(_) => 6,
            DbCacheVersioned::V7(_) => 7,
            DbCacheVersioned::V8(_) => 8,
            DbCacheVersioned::V9(_) => 9,
            DbCacheVersioned::V10(_) => 10,
            DbCacheVersioned::V11(_) => 11,
            DbCacheVersioned::V12(_) | DbCacheVersioned::V12_1(_, _) => 12,
        }
    }

    pub(crate) fn minor_version(&self) -> u32 {
        match self {
            DbCacheVersioned::V12_1(_, _) => 1,
            _ => 0,
        }
    }

    pub(crate) fn into_cache(self) -> Result<DbCache, String> {
        match self {
            DbCacheVersioned::V1
            | DbCacheVersioned::V2
            | DbCacheVersioned::V3
            | DbCacheVersioned::V4
            | DbCacheVersioned::V5(_)
            | DbCacheVersioned::V6(_)
            | DbCacheVersioned::V7(_)
            | DbCacheVersioned::V8(_)
            | DbCacheVersioned::V9(_)
            | DbCacheVersioned::V10(_)
            | DbCacheVersioned::V11(_) => Err(
                "This cache format is unsupported. Run `safe-migrate sync` to rebuild it."
                    .to_string(),
            ),
            DbCacheVersioned::V12(mut c) => {
                if let Some(casts) = c.casts.as_mut() {
                    casts.clear_full_cast_coverage();
                }
                c.validate_semantics()?;
                Ok(*c)
            }
            DbCacheVersioned::V12_1(mut c, ext) => {
                if let Some(casts) = c.casts.as_mut() {
                    casts.validate_and_hydrate_extension_entries(ext.casts)?;
                } else if !ext.casts.is_empty() {
                    return Err(
                        "cache extension carries cast entries without a base cast catalogue"
                            .to_string(),
                    );
                }
                c.routine_dependencies = ext.routine_dependencies;
                c.validate_semantics()?;
                Ok(*c)
            }
        }
    }
}

impl Default for DbCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DbCache {
    pub(crate) fn new() -> Self {
        Self {
            pg_version_num: None,
            metadata: CacheMetadata::default(),
            coverage: CatalogCoverage::default(),
            search_path: vec!["public".to_string()],
            relations: HashMap::new(),
            foreign_keys: Vec::new(),
            indexes: Vec::new(),
            constraints: Vec::new(),
            constraint_keys: Vec::new(),
            constraint_dependencies: Vec::new(),
            generated_column_dependencies: Vec::new(),
            default_sequence_dependencies: Vec::new(),
            triggers: Vec::new(),
            functions: HashMap::new(),
            types: HashMap::new(),
            roles: HashMap::new(),
            role_membership_grantors: Vec::new(),
            role_membership_grantors_complete: false,
            bootstrap_superuser: None,
            schemas: HashMap::new(),
            builtin_types: None,
            opclasses: None,
            collations: None,
            casts: None,
            aggregates: None,
            sequences: HashMap::new(),
            extensions: HashMap::new(),
            dependencies: Vec::new(),
            view_object_dependencies: Vec::new(),
            scoped_external_dependencies: Vec::new(),
            external_referencing_schemas: Vec::new(),
            inheritances: Vec::new(),
            index_attachments: Vec::new(),
            publications: HashMap::new(),
            subscriptions: HashMap::new(),
            routine_dependencies: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn insert_baseline(&mut self, id: ObjectId, state: RelationState) {
        self.relations.insert(id, state);
    }

    pub(crate) fn baseline_relations(&self) -> impl Iterator<Item = (&ObjectId, &RelationState)> {
        self.relations.iter()
    }
}
