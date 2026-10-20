use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::builtin_type::BuiltinTypeCatalogue;
use crate::_internal::model::constraint::{ConstraintKind, ConstraintState};
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
}

// Durable cache layout version.
//
// Any change to the fields of `DbCache` or `DbCacheVersioned` requires bumping
// this: bincode carries no field names, so bytes are laid out exactly as the
// current definitions describe. The header encodes the same number, and the
// magic must stay one digit wide or the fixed-size prefix read breaks.
pub(crate) const CACHE_FORMAT_VERSION: u32 = 10;

/// Current durable cache header. V10 is unreleased, so its layout is still
/// being shaped within the version that introduced it; caches anyone holds are
/// V9 or older, which this header already rejects with resync guidance.
pub(crate) const CACHE_MAGIC: &[u8] = b"SMCACHE10";

// The prefix read in `api.rs` consumes a fixed number of bytes, so the magic
// must stay the same width as the version grows. Two version digits fit.
const _: () = assert!(
    CACHE_MAGIC.len() == 9,
    "the cache magic must stay 9 bytes; a wider version needs a new prefix read"
);

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
}

impl DbCacheVersioned {
    /// The variant this build writes. Naming it in one place keeps a format
    /// bump from silently leaving a writer or a fixture on a stale layout.
    pub(crate) fn current(cache: DbCache) -> Self {
        DbCacheVersioned::V10(Box::new(cache))
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
            | DbCacheVersioned::V9(_) => Err(
                "This cache format is unsupported. Run `safe-migrate sync` to rebuild it."
                    .to_string(),
            ),
            DbCacheVersioned::V10(c) => {
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
            dependencies: Vec::new(),
            view_object_dependencies: Vec::new(),
            scoped_external_dependencies: Vec::new(),
            external_referencing_schemas: Vec::new(),
            inheritances: Vec::new(),
            index_attachments: Vec::new(),
            publications: HashMap::new(),
            subscriptions: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn insert_baseline(&mut self, id: ObjectId, state: RelationState) {
        self.relations.insert(id, state);
    }

    pub(crate) fn baseline_relations(&self) -> impl Iterator<Item = (&ObjectId, &RelationState)> {
        self.relations.iter()
    }

    fn role_membership_cycle(&self) -> Option<ObjectId> {
        fn visit(
            role_id: &ObjectId,
            roles: &HashMap<ObjectId, RoleState>,
            visiting: &mut HashSet<ObjectId>,
            visited: &mut HashSet<ObjectId>,
        ) -> Option<ObjectId> {
            if visiting.contains(role_id) {
                return Some(role_id.clone());
            }
            if !visited.insert(role_id.clone()) {
                return None;
            }
            visiting.insert(role_id.clone());
            if let Some(role) = roles.get(role_id) {
                for parent in &role.member_of {
                    if let Some(cycle) = visit(parent, roles, visiting, visited) {
                        return Some(cycle);
                    }
                }
            }
            visiting.remove(role_id);
            None
        }

        let mut visiting = HashSet::new();
        let mut visited = HashSet::new();
        self.roles
            .keys()
            .find_map(|role_id| visit(role_id, &self.roles, &mut visiting, &mut visited))
    }

    /// Validate cross-record identity, relationship, and catalog-coverage
    /// invariants before a cache is used as an authoritative baseline.
    pub(crate) fn validate_semantics(&self) -> Result<(), String> {
        // Cache identities are authoritative catalog names, never resolver
        // guesses. Reject malformed or inferred IDs at the boundary so every
        // downstream map lookup has one canonical representation.
        let validate_id = |label: &str, id: &ObjectId, require_schema: bool| {
            if id.name.is_empty() {
                return Err(format!("{label} has an empty object name"));
            }
            if require_schema && id.schema.is_empty() {
                return Err(format!(
                    "{label} '{}' must include a schema identity",
                    id.name
                ));
            }
            if id.inferred_schema {
                return Err(format!(
                    "{label} '{}' is marked as an inferred schema identity",
                    id
                ));
            }
            Ok(())
        };
        let validate_role_ref = |label: &str, id: &ObjectId| {
            validate_id(label, id, false)?;
            if !self.roles.is_empty() && !self.roles.contains_key(id) {
                return Err(format!(
                    "{label} '{}' references a role absent from the synchronized role catalog",
                    id.name
                ));
            }
            Ok(())
        };

        if self.pg_version_num.is_some_and(|version| version < 140_000) {
            return Err("This cache was synchronized from an unsupported PostgreSQL version; PostgreSQL 14 or newer is required".to_string());
        }

        if let Some(schemas) = &self.metadata.schemas {
            let mut seen = HashSet::new();
            for schema in schemas {
                if schema.is_empty() {
                    return Err("cache schema scope contains an empty schema identity".to_string());
                }
                if !seen.insert(schema) {
                    return Err(format!(
                        "cache schema scope contains duplicate schema '{}'",
                        schema
                    ));
                }
            }
        }
        for (label, value) in [
            ("source database", self.metadata.source_database.as_deref()),
            ("source role", self.metadata.source_role.as_deref()),
            (
                "source session role",
                self.metadata.source_session_role.as_deref(),
            ),
        ] {
            if value.is_some_and(str::is_empty) {
                return Err(format!("cache metadata contains an empty {label} identity"));
            }
        }
        if let Some(template) = &self.metadata.source_search_path
            && template.iter().any(String::is_empty)
        {
            return Err(
                "cache metadata source search path contains an empty schema identity".to_string(),
            );
        }
        if let Some(existing) = &self.metadata.source_existing_schemas
            && existing.iter().any(String::is_empty)
        {
            return Err(
                "cache metadata source existing schemas contain an empty schema identity"
                    .to_string(),
            );
        }
        let mut search_path = HashSet::new();
        for schema in &self.search_path {
            if schema.is_empty() {
                return Err("cache search path contains an empty schema identity".to_string());
            }
            if !search_path.insert(schema) {
                return Err(format!(
                    "cache search path contains duplicate schema '{}'",
                    schema
                ));
            }
        }
        for family in CatalogFamily::ALL {
            if !self.coverage.has(*family) {
                return Err(format!(
                    "Cache coverage is missing the required '{}' catalog family",
                    family.as_str(),
                ));
            }
        }
        let mut seen_edges = HashSet::new();
        for edge in &self.scoped_external_dependencies {
            validate_id("scoped dependency endpoint", &edge.scoped, true)?;
            if !seen_edges.insert(edge.clone()) {
                return Err(format!(
                    "scoped external dependency '{}' appears more than once",
                    edge.scoped
                ));
            }
            if !matches!(self.coverage.schema_scope, SchemaCoverage::Explicit(_)) {
                return Err(format!(
                    "scoped external dependency '{}' requires an explicit schema scope",
                    edge.scoped
                ));
            }
            if !self.coverage.schema_scope.covers(&edge.scoped.schema) {
                return Err(format!(
                    "scoped external dependency '{}' is outside the cache schema scope",
                    edge.scoped
                ));
            }
            let Some(external) = &edge.external else {
                continue;
            };
            validate_id("scoped dependency endpoint", external, true)?;
            if self.coverage.schema_scope.covers(&external.schema) {
                return Err(format!(
                    "scoped external dependency '{}' -> '{}' must not be in the cache schema scope",
                    edge.scoped, external
                ));
            }
        }
        let coverage_scope = self
            .coverage
            .schema_scope
            .explicit_schemas()
            .map(|schemas| schemas.into_iter().collect::<BTreeSet<_>>());
        let metadata_scope = self
            .metadata
            .schemas
            .as_ref()
            .map(|schemas| schemas.iter().cloned().collect::<BTreeSet<_>>());
        if coverage_scope != metadata_scope {
            return Err(
                "Cache schema coverage disagrees with legacy metadata schema scope".to_string(),
            );
        }
        let mut extended_statistics_ids = HashSet::new();
        for (id, relation) in &self.relations {
            validate_id("relation cache identity", id, true)?;
            validate_id("relation embedded identity", &relation.id, true)?;
            validate_role_ref("relation owner identity", &relation.owner)?;
            if id != &relation.id {
                return Err(format!(
                    "relation cache key '{}' disagrees with embedded identity '{}'",
                    id, relation.id
                ));
            }
            if relation.is_populated.is_some()
                && !matches!(relation.kind, RelationKind::MaterializedView)
            {
                return Err(format!(
                    "relation '{}' carries materialized-view population state but is not a materialized view",
                    id
                ));
            }
            for (label, value) in [
                ("tablespace", relation.tablespace.as_deref()),
                ("access method", relation.access_method.as_deref()),
                ("cluster index", relation.cluster_index.as_deref()),
            ] {
                if value.is_some_and(str::is_empty) {
                    return Err(format!("relation '{}' has an empty {label}", id));
                }
            }
            if relation
                .table_options
                .iter()
                .any(|(key, value)| key.is_empty() || value.is_empty())
            {
                return Err(format!("relation '{}' has a malformed table option", id));
            }
            let mut column_names = HashSet::new();
            for column in &relation.columns {
                if column.name.is_empty() {
                    return Err(format!(
                        "relation '{}' contains a column with an empty identity",
                        id
                    ));
                }
                if !column_names.insert(column.name.as_str()) {
                    return Err(format!(
                        "relation '{}' contains duplicate column '{}', which makes lookup ambiguous",
                        id, column.name
                    ));
                }
                if column
                    .options
                    .iter()
                    .any(|(key, value)| key.is_empty() || value.is_empty())
                {
                    return Err(format!(
                        "relation '{}.{}' has a malformed column option",
                        id, column.name
                    ));
                }
            }
            for (statistics_id, statistics) in &relation.extended_statistics {
                validate_id("extended statistics identity", statistics_id, true)?;
                if statistics_id != &statistics.id
                    || !extended_statistics_ids.insert(statistics_id.clone())
                {
                    return Err(format!(
                        "extended statistics '{}' have a duplicate or inconsistent identity",
                        statistics_id
                    ));
                }
                if statistics.kinds.is_empty()
                    || statistics
                        .kinds
                        .iter()
                        .any(|kind| !matches!(kind.as_str(), "d" | "f" | "m"))
                    || (statistics.columns.is_empty()
                        && statistics.expressions.as_deref().is_none_or(str::is_empty))
                    || statistics
                        .columns
                        .iter()
                        .any(|column| !column_names.contains(column.as_str()))
                    || statistics.target.is_some_and(|target| target < -1)
                {
                    return Err(format!(
                        "extended statistics '{}' contain malformed catalog metadata",
                        statistics_id
                    ));
                }
            }
            if relation.rules.keys().any(String::is_empty) {
                return Err(format!("relation '{}' contains an empty rule identity", id));
            }
            for (column, provenance) in &relation.column_inheritance {
                if !column_names.contains(column.as_str())
                    || provenance.parent_count > i32::MAX as u32
                    || (provenance.parent_count == 0 && !provenance.is_local)
                {
                    return Err(format!(
                        "relation '{}' contains invalid inheritance provenance for column '{}'",
                        id, column
                    ));
                }
            }
            for column in relation.identity_columns.keys() {
                let Some(column_state) = relation.get_column(column) else {
                    return Err(format!(
                        "relation '{}' identifies missing column '{}' as an identity column",
                        id, column
                    ));
                };
                if column_state.generated == Some(true) {
                    return Err(format!(
                        "relation '{}.{}' cannot be both identity and generated",
                        id, column
                    ));
                }
            }
            for (column, generated) in &relation.generated_columns {
                let Some(column_state) = relation.get_column(column) else {
                    return Err(format!(
                        "relation '{}' identifies missing column '{}' as generated",
                        id, column
                    ));
                };
                if relation.identity_columns.contains_key(column)
                    || column_state.generated == Some(false)
                {
                    return Err(format!(
                        "relation '{}.{}' has inconsistent generated-column metadata",
                        id, column
                    ));
                }
                if generated.expression.as_deref().is_some_and(str::is_empty) {
                    return Err(format!(
                        "relation '{}.{}' has an empty generated expression",
                        id, column
                    ));
                }
            }
            for column in &relation.columns {
                if column.generated == Some(true)
                    && !relation.generated_columns.contains_key(&column.name)
                {
                    return Err(format!(
                        "relation '{}.{}' lacks generated-column metadata",
                        id, column.name
                    ));
                }
            }
            if let Some(type_id) = &relation.of_type {
                validate_id("typed-table composite type identity", type_id, true)?;
                let Some(type_state) = self.types.get(type_id) else {
                    return Err(format!(
                        "typed table '{}' references missing composite type '{}'",
                        id, type_id
                    ));
                };
                let TypeKind::Composite { fields } = &type_state.kind else {
                    return Err(format!(
                        "typed table '{}' references non-composite type '{}'",
                        id, type_id
                    ));
                };
                let matches_layout = relation.columns.len() == fields.len()
                    && relation.columns.iter().zip(fields).all(|(column, field)| {
                        column.name == field.name
                            && column.data_type.as_deref().is_some_and(|data_type| {
                                data_type
                                    .trim()
                                    .eq_ignore_ascii_case(field.data_type.trim())
                            })
                    });
                if !matches_layout {
                    let table_layout = relation
                        .columns
                        .iter()
                        .map(|column| (&column.name, column.data_type.as_deref()))
                        .collect::<Vec<_>>();
                    return Err(format!(
                        "typed table '{}' does not match composite type '{}' column layout: table={table_layout:?}, composite={fields:?}",
                        id, type_id,
                    ));
                }
            }
            for (grantee, privileges) in &relation.privileges.grants {
                validate_id("relation privilege grantee", grantee, false)?;
                if !grantee.schema.is_empty() {
                    return Err(format!(
                        "relation '{}' privilege grantee '{}' must use the cluster role namespace",
                        id, grantee
                    ));
                }
                if privileges.is_empty() {
                    return Err(format!(
                        "relation '{}' has an empty privilege set for grantee '{}'",
                        id, grantee
                    ));
                }
                if grantee.name != "public" && !self.roles.contains_key(grantee) {
                    return Err(format!(
                        "relation '{}' privilege references missing grantee role '{}'",
                        id, grantee
                    ));
                }
            }
            for ((grantee, privilege), grantors) in &relation.privileges.grantors {
                validate_id("relation privilege provenance grantee", grantee, false)?;
                if !grantee.schema.is_empty() {
                    return Err(format!(
                        "relation '{}' privilege provenance grantee '{}' must use the cluster role namespace",
                        id, grantee
                    ));
                }
                if !relation.privileges.has_privilege(grantee, *privilege) {
                    return Err(format!(
                        "relation '{}' privilege provenance exists without the effective '{}' privilege for '{}'",
                        id,
                        format_args!("{privilege:?}"),
                        grantee
                    ));
                }
                for grantor in grantors {
                    validate_id("relation privilege provenance grantor", grantor, false)?;
                    if !grantor.schema.is_empty() {
                        return Err(format!(
                            "relation '{}' privilege provenance grantor '{}' must use the cluster role namespace",
                            id, grantor
                        ));
                    }
                    if grantor.name != "public" && !self.roles.contains_key(grantor) {
                        return Err(format!(
                            "relation '{}' privilege provenance references missing grantor role '{}'",
                            id, grantor
                        ));
                    }
                }
            }
            for ((grantee, privilege), grantors) in &relation.privileges.grant_option_grantors {
                validate_id("relation grant-option provenance grantee", grantee, false)?;
                if !relation.privileges.has_grant_option(grantee, *privilege) {
                    return Err(format!(
                        "relation '{}' grant-option provenance exists without the grant option for '{}'",
                        id, grantee
                    ));
                }
                for grantor in grantors {
                    validate_id("relation grant-option provenance grantor", grantor, false)?;
                    if !grantor.schema.is_empty()
                        || (grantor.name != "public" && !self.roles.contains_key(grantor))
                    {
                        return Err(format!(
                            "relation '{}' grant-option provenance references invalid grantor role '{}'",
                            id, grantor
                        ));
                    }
                }
            }
        }
        for (id, function) in &self.functions {
            validate_id("routine cache identity", id, true)?;
            validate_id("routine embedded identity", &function.id, true)?;
            if id != &function.id {
                return Err(format!(
                    "routine cache key '{}' disagrees with embedded identity '{}'",
                    id, function.id
                ));
            }
        }
        for (id, ty) in &self.types {
            validate_id("type cache identity", id, true)?;
            validate_id("type embedded identity", &ty.id, true)?;
            if id != &ty.id {
                return Err(format!(
                    "type cache key '{}' disagrees with embedded identity '{}'",
                    id, ty.id
                ));
            }
        }
        for (id, role) in &self.roles {
            validate_id("role cache identity", id, false)?;
            validate_id("role embedded identity", &role.id, false)?;
            if id != &role.id {
                return Err(format!(
                    "role cache key '{}' disagrees with embedded identity '{}'",
                    id, role.id
                ));
            }
            if !id.schema.is_empty() {
                return Err(format!(
                    "role '{}' must use the cluster role namespace, not schema '{}'",
                    id.name, id.schema
                ));
            }
        }
        if let Some(role_id) = self.role_membership_cycle() {
            return Err(format!(
                "role membership graph contains a circular path at '{}'",
                role_id.name
            ));
        }
        for (name, schema) in &self.schemas {
            if name.is_empty() {
                return Err("schema cache contains an empty schema identity".to_string());
            }
            if schema.name.is_empty() {
                return Err("schema cache contains an empty embedded schema identity".to_string());
            }
            validate_role_ref("schema owner identity", &schema.owner)?;
            if name != &schema.name {
                return Err(format!(
                    "schema cache key '{}' disagrees with embedded identity '{}'",
                    name, schema.name
                ));
            }
        }
        for (id, sequence) in &self.sequences {
            validate_id("sequence cache identity", id, true)?;
            validate_id("sequence embedded identity", &sequence.id, true)?;
            validate_role_ref("sequence owner identity", &sequence.owner)?;
            if id != &sequence.id {
                return Err(format!(
                    "sequence cache key '{}' disagrees with embedded identity '{}'",
                    id, sequence.id
                ));
            }
            if self.relations.contains_key(id) {
                return Err(format!(
                    "sequence '{}' collides with another relation-namespace object",
                    id
                ));
            }
            let (type_min, type_max) = match sequence.parameters.data_type.as_str() {
                "smallint" => (i16::MIN as i64, i16::MAX as i64),
                "integer" => (i32::MIN as i64, i32::MAX as i64),
                "bigint" => (i64::MIN, i64::MAX),
                other => {
                    return Err(format!(
                        "sequence '{}' has unsupported data type '{}'",
                        id, other
                    ));
                }
            };
            if sequence.parameters.increment == 0
                || sequence.parameters.cache_size < 1
                || sequence.parameters.min_value < type_min
                || sequence.parameters.max_value > type_max
                || sequence.parameters.min_value >= sequence.parameters.max_value
                || !(sequence.parameters.min_value..=sequence.parameters.max_value)
                    .contains(&sequence.parameters.start_value)
            {
                return Err(format!("sequence '{}' has invalid sequence parameters", id));
            }
        }
        for (name, publication) in &self.publications {
            if name.is_empty() || publication.name.is_empty() {
                return Err("publication cache contains an empty identity".to_string());
            }
            if name != &publication.name {
                return Err(format!(
                    "publication cache key '{}' disagrees with embedded identity '{}'",
                    name, publication.name
                ));
            }
            if let Some(owner) = &publication.owner {
                if owner.is_empty() {
                    return Err(format!(
                        "publication '{}' has an empty owner identity",
                        name
                    ));
                }
                if !self.roles.is_empty() && !self.roles.contains_key(&ObjectId::new("", owner)) {
                    return Err(format!(
                        "publication '{}' owner '{}' is absent from the synchronized role catalog",
                        name, owner
                    ));
                }
            }
            match &publication.scope {
                crate::_internal::analysis::facts::PublicationScope::AllTables { except } => {
                    let mut seen = HashSet::new();
                    for table in except {
                        let resolved =
                            crate::_internal::ast::identifiers::Ident::new(table, false).resolve();
                        if resolved.is_empty() || !seen.insert(resolved) {
                            return Err(format!(
                                "publication '{}' has an empty or duplicate EXCEPT table",
                                name
                            ));
                        }
                    }
                }
                crate::_internal::analysis::facts::PublicationScope::Explicit(objects) => {
                    let mut seen = HashSet::new();
                    for object in objects {
                        let key = match object {
                            crate::_internal::analysis::facts::PublicationObjectFact::Table {
                                name: table,
                                columns,
                                ..
                            } => {
                                let table_name = table.name.resolve();
                                let schema = table
                                    .schema
                                    .as_ref()
                                    .map(|schema| schema.resolve());
                                if table_name.is_empty()
                                    || schema.as_ref().is_some_and(String::is_empty)
                                {
                                    return Err(format!(
                                        "publication '{}' contains an empty table identity",
                                        name
                                    ));
                                }
                                if let Some(columns) = columns {
                                    let mut column_names = HashSet::new();
                                    for column in columns {
                                        let resolved =
                                            crate::_internal::ast::identifiers::Ident::new(column, false)
                                                .resolve();
                                        if resolved.is_empty() || !column_names.insert(resolved) {
                                            return Err(format!(
                                                "publication '{}' contains an empty or duplicate table column",
                                                name
                                            ));
                                        }
                                    }
                                }
                                format!(
                                    "table:{}:{table_name}",
                                    schema.unwrap_or_else(|| "unqualified".to_string())
                                )
                            }
                            crate::_internal::analysis::facts::PublicationObjectFact::SchemaTables {
                                schema,
                                ..
                            } => {
                                if schema.is_empty() {
                                    return Err(format!(
                                        "publication '{}' contains an empty schema identity",
                                        name
                                    ));
                                }
                                format!("schema:{schema}")
                            }
                            crate::_internal::analysis::facts::PublicationObjectFact::CurrentSchemaShorthand =>
                                "current_schema".to_string(),
                            crate::_internal::analysis::facts::PublicationObjectFact::Unknown => {
                                return Err(format!(
                                    "publication '{}' contains unsupported unknown scope metadata",
                                    name
                                ));
                            }
                        };
                        if !seen.insert(key) {
                            return Err(format!(
                                "publication '{}' contains duplicate scope metadata",
                                name
                            ));
                        }
                    }
                }
            }
        }
        for (name, subscription) in &self.subscriptions {
            if name.is_empty() || subscription.name.is_empty() {
                return Err("subscription cache contains an empty identity".to_string());
            }
            if name != &subscription.name {
                return Err(format!(
                    "subscription cache key '{}' disagrees with embedded identity '{}'",
                    name, subscription.name
                ));
            }
            if let Some(owner) = &subscription.owner {
                if owner.is_empty() {
                    return Err(format!(
                        "subscription '{}' has an empty owner identity",
                        name
                    ));
                }
                if !self.roles.is_empty() && !self.roles.contains_key(&ObjectId::new("", owner)) {
                    return Err(format!(
                        "subscription '{}' owner '{}' is absent from the synchronized role catalog",
                        name, owner
                    ));
                }
            }
            let mut publication_names = HashSet::new();
            for publication in &subscription.publications {
                if publication.is_empty() || !publication_names.insert(publication) {
                    return Err(format!(
                        "subscription '{}' contains an empty or duplicate publication name",
                        name
                    ));
                }
            }
        }

        for schema in &self.search_path {
            if !self.schemas.is_empty() && !self.schemas.contains_key(schema) {
                return Err(format!(
                    "effective search path references missing schema '{}'",
                    schema
                ));
            }
        }

        for (id, sequence) in &self.sequences {
            if let Some((table_id, column_name)) = &sequence.owned_by {
                validate_id("sequence ownership table identity", table_id, true)?;
                if id.schema != table_id.schema {
                    return Err(format!(
                        "sequence '{}' must be in the same schema as owning table '{}'",
                        id, table_id
                    ));
                }
                if column_name.is_empty() {
                    return Err(format!(
                        "sequence '{}' ownership has an empty column identity",
                        id
                    ));
                }
                let Some(relation) = self.relations.get(table_id) else {
                    let omitted_owner_schema =
                        self.metadata.schemas.as_ref().is_some_and(|schemas| {
                            !schemas.iter().any(|schema| schema == &table_id.schema)
                        });
                    if omitted_owner_schema {
                        continue;
                    }
                    return Err(format!(
                        "sequence '{}' ownership references missing relation '{}'",
                        id, table_id
                    ));
                };
                if !matches!(relation.kind, RelationKind::Table) {
                    return Err(format!(
                        "sequence '{}' ownership target '{}' is not a table",
                        id, table_id
                    ));
                }
                if !relation.has_column(column_name) {
                    return Err(format!(
                        "sequence '{}' ownership references missing column '{}.{}'",
                        id, table_id, column_name
                    ));
                }
                if matches!(sequence.kind, SequenceKind::Identity)
                    && !relation.identity_columns.contains_key(column_name)
                {
                    return Err(format!(
                        "identity sequence '{}' owns non-identity column '{}.{}'",
                        id, table_id, column_name
                    ));
                }
            }
        }
        for relation in self.relations.values() {
            for column in relation.identity_columns.keys() {
                let owners = self
                    .sequences
                    .values()
                    .filter(|sequence| {
                        matches!(sequence.kind, SequenceKind::Identity)
                            && sequence.owned_by.as_ref()
                                == Some(&(relation.id.clone(), column.clone()))
                    })
                    .count();
                if owners != 1 {
                    return Err(format!(
                        "identity column '{}.{}' must have exactly one owned identity sequence",
                        relation.id, column
                    ));
                }
            }
        }

        for (id, role) in &self.roles {
            let mut memberships = HashSet::new();
            for target in role.member_of.iter().chain(&role.can_set_role_to) {
                validate_id("role membership target", target, false)?;
                if !target.schema.is_empty() {
                    return Err(format!(
                        "role '{}' membership target '{}' must use the cluster role namespace",
                        id.name, target
                    ));
                }
                if !self.roles.contains_key(target) {
                    return Err(format!(
                        "role '{}' membership references missing role '{}'",
                        id, target
                    ));
                }
            }
            for target in &role.member_of {
                if target == id {
                    return Err(format!("role '{}' cannot be a member of itself", id.name));
                }
                if !memberships.insert(target) {
                    return Err(format!(
                        "role '{}' contains duplicate membership in '{}'",
                        id.name, target.name
                    ));
                }
            }
            let mut set_role_targets = HashSet::new();
            for target in &role.can_set_role_to {
                if !memberships.contains(target) {
                    return Err(format!(
                        "role '{}' has SET ROLE access to '{}' without membership",
                        id.name, target.name
                    ));
                }
                if !set_role_targets.insert(target) {
                    return Err(format!(
                        "role '{}' contains duplicate SET ROLE target '{}'",
                        id.name, target.name
                    ));
                }
            }
            let mut admin_targets = HashSet::new();
            for target in &role.can_administer_membership {
                if !memberships.contains(target) {
                    return Err(format!(
                        "role '{}' has ADMIN option for '{}' without membership",
                        id.name, target.name
                    ));
                }
                if !admin_targets.insert(target) {
                    return Err(format!(
                        "role '{}' contains duplicate ADMIN target '{}'",
                        id.name, target.name
                    ));
                }
            }
            let mut inherit_targets = HashSet::new();
            for target in &role.can_inherit_from {
                if !memberships.contains(target) {
                    return Err(format!(
                        "role '{}' has INHERIT option for '{}' without membership",
                        id.name, target.name
                    ));
                }
                if !inherit_targets.insert(target) {
                    return Err(format!(
                        "role '{}' contains duplicate INHERIT target '{}'",
                        id.name, target.name
                    ));
                }
            }
        }

        let mut membership_grantors = HashSet::new();
        for provenance in &self.role_membership_grantors {
            validate_id("role membership grantee", &provenance.member, false)?;
            validate_id("role membership role", &provenance.role, false)?;
            validate_id("role membership grantor", &provenance.grantor, false)?;
            for id in [&provenance.member, &provenance.role, &provenance.grantor] {
                if !id.schema.is_empty() {
                    return Err(format!(
                        "role membership provenance '{}' must use the cluster role namespace",
                        id
                    ));
                }
                if !self.roles.contains_key(id) {
                    return Err(format!(
                        "role membership provenance references missing role '{}'",
                        id
                    ));
                }
            }
            let Some(member) = self.roles.get(&provenance.member) else {
                unreachable!("validated role provenance member disappeared")
            };
            if !member.member_of.contains(&provenance.role) {
                return Err(format!(
                    "role membership provenance '{}' -> '{}' has no membership edge",
                    provenance.member, provenance.role
                ));
            }
            // PostgreSQL 16+ may record several memberships for the same
            // edge, one per grantor.  Uniqueness applies to the full tuple,
            // not the (member, role) pair.
            if !membership_grantors.insert((
                provenance.member.clone(),
                provenance.role.clone(),
                provenance.grantor.clone(),
            )) {
                return Err(format!(
                    "duplicate role membership provenance for '{}' -> '{}' by '{}'",
                    provenance.member, provenance.role, provenance.grantor
                ));
            }
        }
        if self.role_membership_grantors_complete {
            for (member_id, role) in &self.roles {
                for role_id in &role.member_of {
                    if !membership_grantors
                        .iter()
                        .any(|(m, r, _)| m == member_id && r == role_id)
                    {
                        return Err(format!(
                            "complete role membership provenance is missing for '{}' -> '{}'",
                            member_id, role_id
                        ));
                    }
                }
            }
        }

        let mut constraint_ids = HashSet::new();
        for constraint in &self.constraints {
            validate_id("constraint table identity", &constraint.table_id, true)?;
            if constraint.name.is_empty() {
                return Err(format!(
                    "constraint on '{}' has an empty constraint name",
                    constraint.table_id
                ));
            }
            let Some(relation) = self.relations.get(&constraint.table_id) else {
                return Err(format!(
                    "constraint '{}.{}' references a missing relation",
                    constraint.table_id, constraint.name
                ));
            };
            if !matches!(relation.kind, RelationKind::Table) {
                return Err(format!(
                    "constraint '{}.{}' targets a non-table relation",
                    constraint.table_id, constraint.name
                ));
            }
            if !constraint_ids.insert((constraint.table_id.clone(), constraint.name.clone())) {
                return Err(format!(
                    "constraint '{}.{}' appears more than once",
                    constraint.table_id, constraint.name
                ));
            }
            if matches!(constraint.kind, ConstraintKind::Check)
                && constraint
                    .definition
                    .as_deref()
                    .is_none_or(|definition| definition.trim().is_empty())
            {
                return Err(format!(
                    "CHECK constraint '{}.{}' lacks its expression definition",
                    constraint.table_id, constraint.name
                ));
            }
            if let Some(backing_index) = &constraint.backing_index {
                if !matches!(
                    constraint.kind,
                    ConstraintKind::PrimaryKey | ConstraintKind::Unique | ConstraintKind::Exclusion
                ) {
                    return Err(format!(
                        "constraint '{}.{}' has a backing index but is not a key or exclusion constraint",
                        constraint.table_id, constraint.name
                    ));
                }
                validate_id("constraint backing index identity", backing_index, true)?;
                let Some(index) = self.indexes.iter().find(|index| {
                    index.index_id == *backing_index && index.table_id == constraint.table_id
                }) else {
                    return Err(format!(
                        "constraint '{}.{}' references missing or unrelated backing index '{}'",
                        constraint.table_id, constraint.name, backing_index
                    ));
                };
                if !index.definition.is_usable() {
                    return Err(format!(
                        "constraint '{}.{}' references an unusable backing index '{}'",
                        constraint.table_id, constraint.name, backing_index
                    ));
                }
                if matches!(
                    constraint.kind,
                    ConstraintKind::PrimaryKey | ConstraintKind::Unique
                ) && !index.definition.unique
                {
                    return Err(format!(
                        "constraint '{}.{}' references non-unique backing index '{}'",
                        constraint.table_id, constraint.name, backing_index
                    ));
                }
            }
        }

        let mut constraint_key_ids = HashSet::new();
        for key in &self.constraint_keys {
            validate_id("constraint key table identity", &key.table_id, true)?;
            if key.constraint_name.is_empty() {
                return Err(format!(
                    "constraint key on '{}' has an empty constraint name",
                    key.table_id
                ));
            }
            let Some(relation) = self.relations.get(&key.table_id) else {
                return Err(format!(
                    "constraint key '{}.{}' references a missing relation",
                    key.table_id, key.constraint_name
                ));
            };
            if !matches!(relation.kind, RelationKind::Table) {
                return Err(format!(
                    "constraint key '{}.{}' targets a non-table relation",
                    key.table_id, key.constraint_name
                ));
            }
            let valid_target_kind = self.constraints.iter().any(|constraint| {
                constraint.table_id == key.table_id
                    && constraint.name == key.constraint_name
                    && (constraint.kind == ConstraintKind::PrimaryKey
                        || constraint.kind == ConstraintKind::Unique
                        || constraint.kind == ConstraintKind::NotNull)
            });
            if !valid_target_kind {
                return Err(format!(
                    "constraint key '{}.{}' has no matching primary, unique, or not-null constraint",
                    key.table_id, key.constraint_name
                ));
            }
            if key.columns.is_empty() {
                return Err(format!(
                    "constraint key '{}.{}' has no column identities",
                    key.table_id, key.constraint_name
                ));
            }
            let mut key_columns = HashSet::new();
            if let Some(column) = key
                .columns
                .iter()
                .find(|column| !key_columns.insert(column.as_str()))
            {
                return Err(format!(
                    "constraint key '{}.{}' repeats column '{}'",
                    key.table_id, key.constraint_name, column
                ));
            }
            for column in &key.columns {
                if !relation.has_column(column) {
                    return Err(format!(
                        "constraint key '{}.{}' references missing column '{}.{}'",
                        key.table_id, key.constraint_name, key.table_id, column
                    ));
                }
            }
            if !constraint_key_ids.insert((key.table_id.clone(), key.constraint_name.clone())) {
                return Err(format!(
                    "constraint key '{}.{}' appears more than once",
                    key.table_id, key.constraint_name
                ));
            }
        }

        let mut index_ids = HashSet::new();
        for index in &self.indexes {
            validate_id("index identity", &index.index_id, true)?;
            validate_id("index table identity", &index.table_id, true)?;
            if index.index_id.schema != index.table_id.schema {
                return Err(format!(
                    "index '{}' must be in the same schema as indexed relation '{}'",
                    index.index_id, index.table_id
                ));
            }
            if self.relations.contains_key(&index.index_id)
                || self.sequences.contains_key(&index.index_id)
            {
                return Err(format!(
                    "index '{}' collides with another relation-namespace object",
                    index.index_id
                ));
            }
            if index.definition.method.as_deref().is_none_or(str::is_empty) {
                return Err(format!(
                    "index '{}' has an empty access method",
                    index.index_id
                ));
            }
            let Some(relation) = self.relations.get(&index.table_id) else {
                return Err(format!(
                    "index '{}' references missing relation '{}'",
                    index.index_id, index.table_id
                ));
            };
            if !matches!(
                relation.kind,
                RelationKind::Table | RelationKind::MaterializedView
            ) {
                return Err(format!(
                    "index '{}' targets a non-indexable relation '{}'",
                    index.index_id, index.table_id
                ));
            }
            if !index_ids.insert(index.index_id.clone()) {
                return Err(format!("index '{}' appears more than once", index.index_id));
            }
            // `keys` counts expression keys too, so this cannot be satisfied by an
            // index that merely recorded expression positions as absent columns.
            if index.definition.keys.is_empty() {
                return Err(format!(
                    "index '{}' has no key column identities",
                    index.index_id
                ));
            }
            if !index.dependency_columns_known {
                return Err(format!(
                    "index '{}' is missing complete dependency-column evidence",
                    index.index_id
                ));
            }
            for column in index
                .definition
                .key_column_names()
                .iter()
                .chain(&index.definition.included_column_names())
                .chain(&index.dependency_columns)
            {
                if !relation.has_column(column) {
                    return Err(format!(
                        "index '{}' references missing column '{}.{}'",
                        index.index_id, index.table_id, column
                    ));
                }
            }
        }

        // These relation fields are consumed by typed ALTER TABLE handling.
        // Validate their cross-catalog references at the cache boundary so a
        // decoded baseline cannot turn malformed metadata into an exact state.
        for relation in self.relations.values() {
            if let Some(cluster_index) = &relation.cluster_index {
                let index_id = ObjectId::new(&relation.id.schema, cluster_index);
                if !self
                    .indexes
                    .iter()
                    .any(|index| index.index_id == index_id && index.table_id == relation.id)
                {
                    return Err(format!(
                        "relation '{}' clusters on index '{}' that does not belong to it",
                        relation.id, cluster_index
                    ));
                }
            }
            let Some(replica_identity) = &relation.replica_identity else {
                continue;
            };
            let Some(index_name) = replica_identity.strip_prefix("USING INDEX ") else {
                if matches!(
                    replica_identity.as_str(),
                    "DEFAULT" | "NOTHING" | "FULL" | "USING INDEX"
                ) {
                    continue;
                }
                return Err(format!(
                    "relation '{}' has an invalid replica identity '{}'",
                    relation.id, replica_identity
                ));
            };
            if index_name.is_empty() {
                return Err(format!(
                    "relation '{}' has an empty replica identity index",
                    relation.id
                ));
            }
            let index_id = ObjectId::new(&relation.id.schema, index_name);
            let Some(index) = self
                .indexes
                .iter()
                .find(|index| index.index_id == index_id && index.table_id == relation.id)
            else {
                return Err(format!(
                    "relation '{}' uses missing replica identity index '{}'",
                    relation.id, index_name
                ));
            };
            let all_keys_not_null = index.definition.key_column_names().iter().all(|column| {
                relation
                    .get_column(column)
                    .is_some_and(|column| !column.is_nullable)
            });
            if !index.definition.is_usable()
                || !index.definition.unique
                || index.definition.has_predicate()
                || index.definition.has_expression_keys()
                || !index.is_immediate
                || !all_keys_not_null
            {
                return Err(format!(
                    "relation '{}' uses ineligible replica identity index '{}'",
                    relation.id, index_name
                ));
            }
        }

        let mut trigger_ids = HashSet::new();
        for trigger in &self.triggers {
            validate_id("trigger identity", &trigger.trigger_id, true)?;
            validate_id("trigger table identity", &trigger.table_id, true)?;
            validate_id("trigger function identity", &trigger.function_id, true)?;
            if trigger.trigger_id.schema != trigger.table_id.schema {
                return Err(format!(
                    "trigger '{}' must be in the same schema as trigger table '{}'",
                    trigger.trigger_id, trigger.table_id
                ));
            }
            let Some(relation) = self.relations.get(&trigger.table_id) else {
                return Err(format!(
                    "trigger '{}' references missing relation '{}'",
                    trigger.trigger_id, trigger.table_id
                ));
            };
            if !matches!(
                relation.kind,
                RelationKind::Table | RelationKind::View | RelationKind::ForeignTable
            ) {
                return Err(format!(
                    "trigger '{}' targets a relation kind that cannot have triggers",
                    trigger.trigger_id
                ));
            }
            if !trigger_ids.insert((trigger.table_id.clone(), trigger.trigger_id.name.clone())) {
                return Err(format!(
                    "trigger '{}' appears more than once on relation '{}'",
                    trigger.trigger_id.name, trigger.table_id
                ));
            }
        }
        let trigger_keys: HashSet<ObjectId> = self
            .triggers
            .iter()
            .map(|trigger| {
                ObjectId::new(
                    &trigger.table_id.schema,
                    format!("{}\0{}", trigger.table_id.name, trigger.trigger_id.name),
                )
            })
            .collect();
        for trigger in &self.triggers {
            if let Some(parent_id) = &trigger.parent_trigger_id {
                if !trigger.row_level {
                    return Err(format!(
                        "statement-level trigger '{}' cannot be a partition clone",
                        trigger.trigger_id
                    ));
                }
                if !trigger_keys.contains(parent_id) {
                    return Err(format!(
                        "trigger '{}' references missing parent trigger '{}'",
                        trigger.trigger_id, parent_id
                    ));
                }
            }
        }

        let mut foreign_key_ids = HashSet::new();
        for foreign_key in &self.foreign_keys {
            validate_id("foreign-key source identity", &foreign_key.from_table, true)?;
            validate_id("foreign-key target identity", &foreign_key.to_table, true)?;
            if foreign_key.constraint_name.is_empty() {
                return Err(format!(
                    "foreign key on '{}' has an empty constraint name",
                    foreign_key.from_table
                ));
            }
            let Some(from_relation) = self.relations.get(&foreign_key.from_table) else {
                return Err(format!(
                    "foreign key '{}.{}' references a missing relation",
                    foreign_key.from_table, foreign_key.constraint_name
                ));
            };
            let Some(to_relation) = self.relations.get(&foreign_key.to_table) else {
                return Err(format!(
                    "foreign key '{}.{}' references a missing relation",
                    foreign_key.from_table, foreign_key.constraint_name
                ));
            };
            if !matches!(from_relation.kind, RelationKind::Table)
                || !matches!(to_relation.kind, RelationKind::Table)
            {
                return Err(format!(
                    "foreign key '{}.{}' must reference tables",
                    foreign_key.from_table, foreign_key.constraint_name
                ));
            }
            if foreign_key.from_columns.is_empty() || foreign_key.to_columns.is_empty() {
                return Err(format!(
                    "foreign key '{}.{}' is missing ordered column identities",
                    foreign_key.from_table, foreign_key.constraint_name
                ));
            }
            if foreign_key.from_columns.len() != foreign_key.to_columns.len() {
                return Err(format!(
                    "foreign key '{}.{}' has {} source columns but {} referenced columns",
                    foreign_key.from_table,
                    foreign_key.constraint_name,
                    foreign_key.from_columns.len(),
                    foreign_key.to_columns.len()
                ));
            }
            let column_count = foreign_key.from_columns.len();
            for (label, operators) in [
                ("PK/FK", &foreign_key.pk_fk_equality_operators),
                ("PK/PK", &foreign_key.pk_pk_equality_operators),
                ("FK/FK", &foreign_key.fk_fk_equality_operators),
            ] {
                if operators.len() != column_count
                    || operators.iter().any(|operator| operator.trim().is_empty())
                {
                    return Err(format!(
                        "foreign key '{}.{}' has incomplete {} equality-operator evidence",
                        foreign_key.from_table, foreign_key.constraint_name, label
                    ));
                }
            }
            let mut source_columns = HashSet::new();
            if let Some(column) = foreign_key
                .from_columns
                .iter()
                .find(|column| !source_columns.insert(column.as_str()))
            {
                return Err(format!(
                    "foreign key '{}.{}' repeats source column '{}'",
                    foreign_key.from_table, foreign_key.constraint_name, column
                ));
            }
            let mut target_columns = HashSet::new();
            if let Some(column) = foreign_key
                .to_columns
                .iter()
                .find(|column| !target_columns.insert(column.as_str()))
            {
                return Err(format!(
                    "foreign key '{}.{}' repeats referenced column '{}'",
                    foreign_key.from_table, foreign_key.constraint_name, column
                ));
            }
            for column in &foreign_key.from_columns {
                if !from_relation.has_column(column) {
                    return Err(format!(
                        "foreign key '{}.{}' references missing source column '{}.{}'",
                        foreign_key.from_table,
                        foreign_key.constraint_name,
                        foreign_key.from_table,
                        column
                    ));
                }
            }
            for column in &foreign_key.to_columns {
                if !to_relation.has_column(column) {
                    return Err(format!(
                        "foreign key '{}.{}' references missing target column '{}.{}'",
                        foreign_key.from_table,
                        foreign_key.constraint_name,
                        foreign_key.to_table,
                        column
                    ));
                }
            }
            if !foreign_key_ids.insert((
                foreign_key.from_table.clone(),
                foreign_key.constraint_name.clone(),
            )) {
                return Err(format!(
                    "foreign key '{}.{}' appears more than once",
                    foreign_key.from_table, foreign_key.constraint_name
                ));
            }
            if !self.constraints.iter().any(|constraint| {
                constraint.table_id == foreign_key.from_table
                    && constraint.name == foreign_key.constraint_name
                    && matches!(
                        constraint.kind,
                        crate::_internal::model::constraint::ConstraintKind::ForeignKey
                    )
            }) {
                return Err(format!(
                    "foreign key '{}.{}' has no matching constraint",
                    foreign_key.from_table, foreign_key.constraint_name
                ));
            }
        }

        let mut inheritance_pairs = HashSet::new();
        let mut pending_parents = HashSet::new();
        for inheritance in &self.inheritances {
            validate_id("inheritance child identity", &inheritance.child, true)?;
            validate_id("inheritance parent identity", &inheritance.parent, true)?;
            if inheritance.child == inheritance.parent || inheritance.sequence < 1 {
                return Err(format!(
                    "inheritance '{} -> {}' has invalid direct relationship metadata",
                    inheritance.child, inheritance.parent
                ));
            }
            if inheritance.detach_pending {
                if !inheritance.is_partition
                    || self
                        .relations
                        .get(&inheritance.parent)
                        .is_some_and(|parent| parent.partition_type.is_none())
                    || self
                        .relations
                        .get(&inheritance.child)
                        .is_some_and(|child| child.partition_bound.is_none())
                {
                    return Err(
                        "pending detach requires a bounded partition and partitioned parent".into(),
                    );
                }
                if !pending_parents.insert(inheritance.parent.clone()) {
                    return Err("a partitioned parent cannot have multiple pending detaches".into());
                }
            }
            let omitted_schema = |schema: &str| {
                self.metadata
                    .schemas
                    .as_ref()
                    .is_some_and(|schemas| !schemas.iter().any(|known| known == schema))
            };
            for id in [&inheritance.child, &inheritance.parent] {
                if let Some(relation) = self.relations.get(id) {
                    if !relation.kind.is_table_like() {
                        return Err(format!(
                            "inheritance '{} -> {}' must reference tables",
                            inheritance.child, inheritance.parent
                        ));
                    }
                } else if !omitted_schema(&id.schema) {
                    return Err(format!(
                        "inheritance '{} -> {}' references a missing relation '{}'",
                        inheritance.child, inheritance.parent, id
                    ));
                }
            }
            if !inheritance_pairs.insert((
                inheritance.child.clone(),
                inheritance.parent.clone(),
                inheritance.sequence,
            )) {
                return Err(format!(
                    "inheritance '{} -> {}' appears more than once at sequence {}",
                    inheritance.child, inheritance.parent, inheritance.sequence
                ));
            }
        }

        let mut constraint_dependency_ids = HashSet::new();
        for dependency in &self.constraint_dependencies {
            validate_id(
                "constraint dependency table identity",
                &dependency.table_id,
                true,
            )?;
            if dependency.constraint_name.is_empty() {
                return Err(format!(
                    "constraint dependency on '{}' has an empty constraint name",
                    dependency.table_id
                ));
            }
            if !constraint_dependency_ids.insert((
                dependency.table_id.clone(),
                dependency.constraint_name.clone(),
            )) {
                return Err(format!(
                    "constraint dependency '{}.{}' appears more than once",
                    dependency.table_id, dependency.constraint_name
                ));
            }
            let Some(relation) = self.relations.get(&dependency.table_id) else {
                return Err(format!(
                    "constraint dependency '{}' references missing relation '{}'",
                    dependency.constraint_name, dependency.table_id
                ));
            };
            if !self.constraints.iter().any(|constraint| {
                constraint.table_id == dependency.table_id
                    && constraint.name == dependency.constraint_name
                    && matches!(
                        constraint.kind,
                        crate::_internal::model::constraint::ConstraintKind::Check
                            | crate::_internal::model::constraint::ConstraintKind::Exclusion
                    )
            }) {
                return Err(format!(
                    "constraint dependency '{}.{}' has no matching CHECK or EXCLUDE constraint",
                    dependency.table_id, dependency.constraint_name
                ));
            }
            for column in &dependency.columns {
                if !relation.has_column(column) {
                    return Err(format!(
                        "constraint dependency '{}.{}' references missing column '{}.{}'",
                        dependency.table_id,
                        dependency.constraint_name,
                        dependency.table_id,
                        column
                    ));
                }
            }
        }

        let mut generated_dependency_ids = HashSet::new();
        for dependency in &self.generated_column_dependencies {
            validate_id(
                "generated dependency table identity",
                &dependency.table_id,
                true,
            )?;
            if dependency.column_name.is_empty() || dependency.depends_on_column.is_empty() {
                return Err(format!(
                    "generated dependency on '{}' has an empty column identity",
                    dependency.table_id
                ));
            }
            if !generated_dependency_ids.insert((
                dependency.table_id.clone(),
                dependency.column_name.clone(),
                dependency.depends_on_column.clone(),
            )) {
                return Err(format!(
                    "generated column dependency '{}.{} -> {}' appears more than once",
                    dependency.table_id, dependency.column_name, dependency.depends_on_column
                ));
            }
            if dependency.column_name == dependency.depends_on_column {
                return Err(format!(
                    "generated column dependency '{}.{}' cannot depend on itself",
                    dependency.table_id, dependency.column_name
                ));
            }
            let Some(relation) = self.relations.get(&dependency.table_id) else {
                return Err(format!(
                    "generated column dependency references missing relation '{}'",
                    dependency.table_id
                ));
            };
            if !relation.has_column(&dependency.column_name) {
                return Err(format!(
                    "generated column dependency references missing generated column '{}.{}'",
                    dependency.table_id, dependency.column_name
                ));
            }
            if !relation.has_column(&dependency.depends_on_column) {
                return Err(format!(
                    "generated column dependency '{}.{}' references missing source column '{}.{}'",
                    dependency.table_id,
                    dependency.column_name,
                    dependency.table_id,
                    dependency.depends_on_column
                ));
            }
        }

        let mut default_sequence_dependency_ids = HashSet::new();
        for dependency in &self.default_sequence_dependencies {
            validate_id(
                "default dependency table identity",
                &dependency.table_id,
                true,
            )?;
            validate_id(
                "default dependency sequence identity",
                &dependency.sequence_id,
                true,
            )?;
            if dependency.column_name.is_empty() {
                return Err(format!(
                    "default sequence dependency on '{}' has an empty column identity",
                    dependency.table_id
                ));
            }
            if !default_sequence_dependency_ids.insert((
                dependency.table_id.clone(),
                dependency.column_name.clone(),
                dependency.sequence_id.clone(),
            )) {
                return Err(format!(
                    "default sequence dependency '{}.{} -> {}' appears more than once",
                    dependency.table_id, dependency.column_name, dependency.sequence_id
                ));
            }
            let Some(relation) = self.relations.get(&dependency.table_id) else {
                return Err(format!(
                    "default sequence dependency references missing relation '{}'",
                    dependency.table_id
                ));
            };
            if !relation.has_column(&dependency.column_name) {
                return Err(format!(
                    "default sequence dependency '{}.{}' references missing column",
                    dependency.table_id, dependency.column_name
                ));
            }
            if !self.sequences.contains_key(&dependency.sequence_id)
                && !self.metadata.schemas.as_ref().is_some_and(|schemas| {
                    !schemas.iter().any(|s| s == &dependency.sequence_id.schema)
                })
            {
                return Err(format!(
                    "default sequence dependency references missing sequence '{}'",
                    dependency.sequence_id
                ));
            }
        }

        let mut view_dependency_ids = HashSet::new();
        for dependency in &self.dependencies {
            validate_id("view dependent identity", &dependency.dependent, true)?;
            validate_id("view referenced identity", &dependency.referenced, true)?;
            if !view_dependency_ids.insert((
                dependency.dependent.clone(),
                dependency.referenced.clone(),
                dependency.referenced_column.clone(),
            )) {
                return Err(format!(
                    "view dependency '{} -> {}' appears more than once",
                    dependency.dependent, dependency.referenced
                ));
            }
            let omitted_schema = |schema: Option<&str>| {
                self.metadata
                    .schemas
                    .as_ref()
                    .zip(schema)
                    .is_some_and(|(schemas, schema)| !schemas.iter().any(|known| known == schema))
            };
            let object_missing = !self.relations.contains_key(&dependency.dependent);
            let referenced_missing = !self.relations.contains_key(&dependency.referenced);
            if (object_missing && !omitted_schema(Some(&dependency.dependent.schema)))
                || (referenced_missing && !omitted_schema(Some(&dependency.referenced.schema)))
            {
                return Err(format!(
                    "view dependency '{} -> {}' references a missing relation",
                    dependency.dependent, dependency.referenced
                ));
            }
            if let Some(relation) = self.relations.get(&dependency.dependent)
                && !matches!(
                    relation.kind,
                    RelationKind::View | RelationKind::MaterializedView
                )
            {
                return Err(format!(
                    "view dependency '{} -> {}' has a non-view dependent",
                    dependency.dependent, dependency.referenced
                ));
            }
            if let Some(column) = &dependency.referenced_column
                && column.is_empty()
            {
                return Err(format!(
                    "view dependency '{} -> {}' has an empty referenced column identity",
                    dependency.dependent, dependency.referenced
                ));
            }
            if let Some(column) = &dependency.referenced_column
                && let Some(relation) = self.relations.get(&dependency.referenced)
                && !relation.has_column(column)
            {
                return Err(format!(
                    "view dependency '{} -> {}' references missing column '{}.{}'",
                    dependency.dependent, dependency.referenced, dependency.referenced, column
                ));
            }
        }

        Ok(())
    }

    /// Return this cache only when all semantic invariants pass validation.
    /// This is the supported constructor for library callers that build a
    /// cache without going through the on-disk decoder.
    pub(crate) fn validated(self) -> Result<Self, String> {
        self.validate_semantics()?;
        Ok(self)
    }
}
