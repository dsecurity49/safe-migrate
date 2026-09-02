use crate::ast::identifiers::ObjectId;
use crate::model::constraint::{ConstraintKind, ConstraintState};
use crate::model::function::FunctionState;
use crate::model::relation::{RelationKind, RelationState};
use crate::model::replication::{PublicationState, SubscriptionState};
use crate::model::role::RoleState;
use crate::model::schema::SchemaState;
use crate::model::sequence::SequenceState;
use crate::model::trigger::TriggerEnableMode;
use crate::model::types::TypeState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};

/// Catalog families whose completeness is independently meaningful to the
/// analyzer. The V7 cache records this explicitly instead of treating one
/// optional schema list as evidence for every object class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogFamily {
    Schemas,
    Relations,
    Sequences,
    Indexes,
    Constraints,
    Triggers,
    Routines,
    Types,
    Dependencies,
    Inheritance,
    Roles,
    Publications,
    Subscriptions,
}

impl CatalogFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Schemas => "schemas",
            Self::Relations => "relations",
            Self::Sequences => "sequences",
            Self::Indexes => "indexes",
            Self::Constraints => "constraints",
            Self::Triggers => "triggers",
            Self::Routines => "routines",
            Self::Types => "types",
            Self::Dependencies => "dependencies",
            Self::Inheritance => "inheritance",
            Self::Roles => "roles",
            Self::Publications => "publications",
            Self::Subscriptions => "subscriptions",
        }
    }
}

/// Schema boundary for the schema-scoped catalog families in [`CatalogCoverage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaCoverage {
    AllNonSystem,
    Explicit(BTreeSet<String>),
}

impl SchemaCoverage {
    pub fn from_sync_scope(schemas: Option<&[String]>) -> Self {
        match schemas {
            Some(schemas) => Self::Explicit(schemas.iter().cloned().collect()),
            None => Self::AllNonSystem,
        }
    }

    pub fn covers(&self, schema: &str) -> bool {
        match self {
            Self::AllNonSystem => true,
            Self::Explicit(schemas) => schemas.contains(schema),
        }
    }

    pub fn explicit_schemas(&self) -> Option<Vec<String>> {
        match self {
            Self::AllNonSystem => None,
            Self::Explicit(schemas) => Some(schemas.iter().cloned().collect()),
        }
    }
}

/// Completeness contract emitted by synchronization and consumed by cache
/// validation. The schema boundary applies to schema-scoped families; role,
/// publication, and subscription rows are recorded separately in `families`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogCoverage {
    pub schema_scope: SchemaCoverage,
    pub families: BTreeSet<CatalogFamily>,
}

impl CatalogCoverage {
    pub fn from_sync_scope(schemas: Option<&[String]>) -> Self {
        Self {
            schema_scope: SchemaCoverage::from_sync_scope(schemas),
            families: [
                CatalogFamily::Schemas,
                CatalogFamily::Relations,
                CatalogFamily::Sequences,
                CatalogFamily::Indexes,
                CatalogFamily::Constraints,
                CatalogFamily::Triggers,
                CatalogFamily::Routines,
                CatalogFamily::Types,
                CatalogFamily::Dependencies,
                CatalogFamily::Inheritance,
                CatalogFamily::Roles,
                CatalogFamily::Publications,
                CatalogFamily::Subscriptions,
            ]
            .into_iter()
            .collect(),
        }
    }

    pub fn has(&self, family: CatalogFamily) -> bool {
        self.families.contains(&family)
    }

    pub fn family_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.families.iter().copied().map(CatalogFamily::as_str)
    }
}

impl Default for CatalogCoverage {
    fn default() -> Self {
        // Programmatic test baselines retain the historical all-schema
        // assumption. Production sync always overwrites this with its actual
        // requested scope before a V7 cache can be written.
        Self::from_sync_scope(None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignKeyCache {
    pub constraint_name: String,
    pub from_table: ObjectId,
    pub to_table: ObjectId,
    /// Ordered `pg_constraint.conkey` identities resolved through
    /// `pg_attribute`. Empty vectors are invalid for V7 FK records.
    pub from_columns: Vec<String>,
    /// Ordered `pg_constraint.confkey` identities resolved through
    /// `pg_attribute`. Position pairs with `from_columns`.
    pub to_columns: Vec<String>,
    /// Ordered equality operators selected by PostgreSQL for PK = FK
    /// comparisons. These are textual identities rather than OIDs so a cache
    /// remains meaningful across cluster restarts and logical restores.
    pub pk_fk_equality_operators: Vec<String>,
    /// Ordered equality operators selected for PK = PK comparisons.
    pub pk_pk_equality_operators: Vec<String>,
    /// Ordered equality operators selected for FK = FK comparisons.
    pub fk_fk_equality_operators: Vec<String>,
}

impl ForeignKeyCache {
    pub fn has_complete_operator_evidence(&self) -> bool {
        let count = self.from_columns.len();
        count > 0
            && self.to_columns.len() == count
            && [
                &self.pk_fk_equality_operators,
                &self.pk_pk_equality_operators,
                &self.fk_fk_equality_operators,
            ]
            .iter()
            .all(|operators| {
                operators.len() == count
                    && operators.iter().all(|operator| !operator.trim().is_empty())
            })
    }
}

/// Ordered key columns for a primary or unique constraint. This is separate
/// from `ConstraintState` so the runtime state model remains focused on the
/// mutable constraint lifecycle while Cache V7 can preserve catalog proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintKeyCache {
    pub table_id: ObjectId,
    pub constraint_name: String,
    pub columns: Vec<String>,
    pub is_primary: bool,
}

/// Complete direct column dependencies for expression-backed constraints
/// (currently CHECK and EXCLUDE). An empty vector is authoritative: the
/// expression has no relation-column dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintDependencyCache {
    pub table_id: ObjectId,
    pub constraint_name: String,
    pub columns: Vec<String>,
}

/// A generated column's direct source-column dependencies from `pg_attrdef`.
/// The generated column itself is identified separately so dropping it can
/// remove only its own expression edge; source-column drops remain
/// conservative until dependent-column CASCADE is modeled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedColumnDependencyCache {
    pub table_id: ObjectId,
    pub column_name: String,
    pub depends_on_column: String,
}

/// A normal `pg_attrdef` dependency from a column default to a sequence.
/// This is distinct from sequence OWNED BY metadata: a default can reference
/// a standalone sequence without making that sequence owned by the table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefaultSequenceDependencyCache {
    pub table_id: ObjectId,
    pub column_name: String,
    pub sequence_id: ObjectId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexCache {
    pub index_id: ObjectId,
    pub table_id: ObjectId,
    pub using_method: String,
    /// Ordered simple key columns. An expression key is omitted, so this is
    /// complete only when `has_expression_keys` is false.
    pub key_columns: Vec<String>,
    /// Columns stored with `INCLUDE`; they remain dependencies of the index.
    pub included_columns: Vec<String>,
    /// Every table column named by PostgreSQL's `pg_depend` rows for this
    /// index, including expression keys and predicates. This is unordered
    /// dependency evidence, not an index definition.
    pub dependency_columns: Vec<String>,
    /// Whether `dependency_columns` came from complete catalog evidence.
    /// Locally parsed expression/predicate indexes cannot claim this yet.
    pub dependency_columns_known: bool,
    pub has_expression_keys: bool,
    pub has_predicate: bool,
    pub is_unique: bool,
    pub is_valid: bool,
    pub is_ready: bool,
    pub is_live: bool,
    pub has_default_sort_order: bool,
    pub has_default_opclasses: bool,
    pub has_default_collations: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerCache {
    pub trigger_id: ObjectId,
    pub table_id: ObjectId,
    pub function_id: ObjectId,
    pub enabled_mode: TriggerEnableMode,
}

/// A normalized `pg_rewrite`/`pg_depend` view edge.
///
/// Raw catalog OIDs are deliberately not serialized: their only useful
/// contribution to the modeled relation dependency is `refobjsubid`, which is
/// resolved during sync to the stable column identity below. Keeping raw OIDs
/// alongside names made the old record look more authoritative without adding
/// a transition consumer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewDependencyCache {
    pub dependent: ObjectId,
    pub referenced: ObjectId,
    /// `None` means PostgreSQL reported a relation-level dependency. Such a
    /// row must remain conservative for column-level transitions.
    pub referenced_column: Option<String>,
}

/// One direct table or index inheritance relationship from `pg_inherits`.
///
/// The row is retained separately from generic dependencies because PostgreSQL
/// exposes detach-in-progress state here and the transition engine needs the
/// direct parent/child direction for partition-cycle and publication scope
/// reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InheritanceCache {
    pub child: ObjectId,
    pub parent: ObjectId,
    pub sequence: i32,
    /// `pg_class.relispartition` for `child`. Distinguishes declarative
    /// partitioning from traditional `INHERITS`, which shares `pg_inherits`.
    pub is_partition: bool,
    pub detach_pending: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CacheMetadata {
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
pub struct DbCache {
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
    pub schemas: HashMap<String, SchemaState>,
    pub sequences: HashMap<ObjectId, SequenceState>,
    pub dependencies: Vec<ViewDependencyCache>,
    /// Synchronized relations with a known dependent outside an explicit
    /// schema scope. Scoped destructive transitions stay conservative for
    /// these identities; an absent entry means no such dependent was observed
    /// in the catalog families the synchronizer resolves.
    pub scoped_external_relation_dependencies: Vec<ObjectId>,
    pub scoped_external_type_dependencies: Vec<ObjectId>,
    pub scoped_external_routine_dependencies: Vec<ObjectId>,
    pub inheritances: Vec<InheritanceCache>,
    pub publications: HashMap<String, PublicationState>,
    pub subscriptions: HashMap<String, SubscriptionState>,
}

pub const CACHE_FORMAT_VERSION: u32 = 7;

/// Current durable cache header. V7 adds PostgreSQL-selected FK equality
/// operator evidence to the normalized catalog snapshot.
pub const CACHE_V7_MAGIC: &[u8] = b"SMCACHE07";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DbCacheVersioned {
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
}

impl DbCacheVersioned {
    pub fn format_version(&self) -> u32 {
        match self {
            DbCacheVersioned::V1 => 1,
            DbCacheVersioned::V2 => 2,
            DbCacheVersioned::V3 => 3,
            DbCacheVersioned::V4 => 4,
            DbCacheVersioned::V5(_) => 5,
            DbCacheVersioned::V6(_) => 6,
            DbCacheVersioned::V7(_) => 7,
        }
    }

    pub fn into_cache(self) -> Result<DbCache, String> {
        match self {
            DbCacheVersioned::V1
            | DbCacheVersioned::V2
            | DbCacheVersioned::V3
            | DbCacheVersioned::V4
            | DbCacheVersioned::V5(_)
            | DbCacheVersioned::V6(_) => Err(
                "This cache format is unsupported. Run `safe-migrate sync` to rebuild it."
                    .to_string(),
            ),
            DbCacheVersioned::V7(c) => {
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
    pub fn new() -> Self {
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
            schemas: HashMap::new(),
            sequences: HashMap::new(),
            dependencies: Vec::new(),
            scoped_external_relation_dependencies: Vec::new(),
            scoped_external_type_dependencies: Vec::new(),
            scoped_external_routine_dependencies: Vec::new(),
            inheritances: Vec::new(),
            publications: HashMap::new(),
            subscriptions: HashMap::new(),
        }
    }

    pub fn insert_baseline(&mut self, id: ObjectId, state: RelationState) {
        self.relations.insert(id, state);
    }

    pub fn baseline_relations(&self) -> impl Iterator<Item = (&ObjectId, &RelationState)> {
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
    pub fn validate_semantics(&self) -> Result<(), String> {
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
        let required_families = [
            CatalogFamily::Schemas,
            CatalogFamily::Relations,
            CatalogFamily::Sequences,
            CatalogFamily::Indexes,
            CatalogFamily::Constraints,
            CatalogFamily::Triggers,
            CatalogFamily::Routines,
            CatalogFamily::Types,
            CatalogFamily::Dependencies,
            CatalogFamily::Inheritance,
            CatalogFamily::Roles,
            CatalogFamily::Publications,
            CatalogFamily::Subscriptions,
        ];
        for family in required_families {
            if !self.coverage.has(family) {
                return Err(format!(
                    "Cache V7 coverage is missing the required '{}' catalog family",
                    family.as_str(),
                ));
            }
        }
        let mut scoped_external_relations = HashSet::new();
        for id in &self.scoped_external_relation_dependencies {
            validate_id("scoped external relation dependency identity", id, true)?;
            if !scoped_external_relations.insert(id) {
                return Err(format!(
                    "scoped external relation dependency '{}' appears more than once",
                    id
                ));
            }
            if !matches!(self.coverage.schema_scope, SchemaCoverage::Explicit(_)) {
                return Err(format!(
                    "scoped external relation dependency '{}' requires an explicit schema scope",
                    id
                ));
            }
            if !self.coverage.schema_scope.covers(&id.schema) {
                return Err(format!(
                    "scoped external relation dependency '{}' is outside the cache schema scope",
                    id
                ));
            }
        }
        for (label, ids) in [
            (
                "scoped external type dependency",
                &self.scoped_external_type_dependencies,
            ),
            (
                "scoped external routine dependency",
                &self.scoped_external_routine_dependencies,
            ),
        ] {
            let mut seen = HashSet::new();
            for id in ids {
                validate_id(label, id, true)?;
                if !seen.insert(id) {
                    return Err(format!("{label} '{}' appears more than once", id));
                }
                if !matches!(self.coverage.schema_scope, SchemaCoverage::Explicit(_)) {
                    return Err(format!(
                        "{label} '{}' requires an explicit schema scope",
                        id
                    ));
                }
                if !self.coverage.schema_scope.covers(&id.schema) {
                    return Err(format!(
                        "{label} '{}' is outside the cache schema scope",
                        id
                    ));
                }
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
                "Cache V7 schema coverage disagrees with legacy metadata schema scope".to_string(),
            );
        }
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
                crate::analysis::facts::PublicationScope::AllTables { except } => {
                    let mut seen = HashSet::new();
                    for table in except {
                        let resolved = crate::ast::identifiers::Ident::new(table, false).resolve();
                        if resolved.is_empty() || !seen.insert(resolved) {
                            return Err(format!(
                                "publication '{}' has an empty or duplicate EXCEPT table",
                                name
                            ));
                        }
                    }
                }
                crate::analysis::facts::PublicationScope::Explicit(objects) => {
                    let mut seen = HashSet::new();
                    for object in objects {
                        let key = match object {
                            crate::analysis::facts::PublicationObjectFact::Table {
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
                                            crate::ast::identifiers::Ident::new(column, false)
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
                                    schema.unwrap_or_else(|| "<unqualified>".to_string())
                                )
                            }
                            crate::analysis::facts::PublicationObjectFact::SchemaTables {
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
                            crate::analysis::facts::PublicationObjectFact::CurrentSchemaShorthand =>
                                "current_schema".to_string(),
                            crate::analysis::facts::PublicationObjectFact::Unknown => {
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
                if !index.is_valid || !index.is_ready || !index.is_live {
                    return Err(format!(
                        "constraint '{}.{}' references an unusable backing index '{}'",
                        constraint.table_id, constraint.name, backing_index
                    ));
                }
                if matches!(
                    constraint.kind,
                    ConstraintKind::PrimaryKey | ConstraintKind::Unique
                ) && !index.is_unique
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
            let expected_kind = if key.is_primary {
                ConstraintKind::PrimaryKey
            } else {
                ConstraintKind::Unique
            };
            if !self.constraints.iter().any(|constraint| {
                constraint.table_id == key.table_id
                    && constraint.name == key.constraint_name
                    && constraint.kind == expected_kind
            }) {
                return Err(format!(
                    "constraint key '{}.{}' has no matching primary or unique constraint",
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
            if index.using_method.is_empty() {
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
            if !index.has_expression_keys && index.key_columns.is_empty() {
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
                .key_columns
                .iter()
                .chain(&index.included_columns)
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
            if !matches!(relation.kind, RelationKind::Table | RelationKind::View) {
                return Err(format!(
                    "trigger '{}' targets a relation kind that cannot have triggers",
                    trigger.trigger_id
                ));
            }
            if !trigger_ids.insert(trigger.trigger_id.clone()) {
                return Err(format!(
                    "trigger '{}' appears more than once",
                    trigger.trigger_id
                ));
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
                        crate::model::constraint::ConstraintKind::ForeignKey
                    )
            }) {
                return Err(format!(
                    "foreign key '{}.{}' has no matching constraint",
                    foreign_key.from_table, foreign_key.constraint_name
                ));
            }
        }

        let mut inheritance_pairs = HashSet::new();
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
                return Err(format!(
                    "inheritance '{} -> {}' is being detached; synchronize after the detach completes",
                    inheritance.child, inheritance.parent
                ));
            }
            let omitted_schema = |schema: &str| {
                self.metadata
                    .schemas
                    .as_ref()
                    .is_some_and(|schemas| !schemas.iter().any(|known| known == schema))
            };
            for id in [&inheritance.child, &inheritance.parent] {
                if let Some(relation) = self.relations.get(id) {
                    if !matches!(relation.kind, RelationKind::Table) {
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
                        crate::model::constraint::ConstraintKind::Check
                            | crate::model::constraint::ConstraintKind::Exclusion
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
    pub fn validated(self) -> Result<Self, String> {
        self.validate_semantics()?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(id: ObjectId, columns: &[&str]) -> RelationState {
        let mut relation = RelationState::new(
            id,
            ObjectId::new("", "postgres"),
            0,
            None,
            RelationKind::Table,
            crate::model::relation::Persistence::Permanent,
            0,
        );
        relation.columns = columns
            .iter()
            .map(|name| crate::model::column::Column {
                name: (*name).to_string(),
                data_type: Some("integer".to_string()),
                type_id: None,
                is_nullable: false,
                default: None,
                avg_width: Some(4),
                default_expr_text: None,
                type_modifier: None,
            })
            .collect();
        relation
    }

    #[test]
    fn every_legacy_cache_variant_is_rejected_generically() {
        for (versioned, expected_version) in [
            (DbCacheVersioned::V1, 1),
            (DbCacheVersioned::V2, 2),
            (DbCacheVersioned::V3, 3),
            (DbCacheVersioned::V4, 4),
        ] {
            assert_eq!(versioned.format_version(), expected_version);
            assert_eq!(
                versioned.into_cache().unwrap_err(),
                "This cache format is unsupported. Run `safe-migrate sync` to rebuild it."
            );
        }
        let v5 = DbCacheVersioned::V5(Box::default());
        assert_eq!(v5.format_version(), 5);
        assert_eq!(
            v5.into_cache().unwrap_err(),
            "This cache format is unsupported. Run `safe-migrate sync` to rebuild it."
        );
        let v6 = DbCacheVersioned::V6(Box::default());
        assert_eq!(v6.format_version(), 6);
        assert_eq!(
            v6.into_cache().unwrap_err(),
            "This cache format is unsupported. Run `safe-migrate sync` to rebuild it."
        );
    }

    #[test]
    fn current_cache_format_is_v7() {
        assert_eq!(CACHE_FORMAT_VERSION, 7);
        assert_eq!(DbCacheVersioned::V7(Box::default()).format_version(), 7);
        assert_eq!(CACHE_V7_MAGIC, b"SMCACHE07");
    }

    #[test]
    fn current_cache_rejects_external_boundary_identity_outside_scope() {
        let mut cache = DbCache::new();
        let schemas = vec!["public".to_string()];
        cache.coverage = CatalogCoverage::from_sync_scope(Some(&schemas));
        cache.metadata.schemas = Some(schemas);
        cache
            .scoped_external_relation_dependencies
            .push(ObjectId::new("omitted", "table"));

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("outside the cache schema scope"), "{error}");
    }

    #[test]
    fn current_cache_rejects_mismatched_embedded_identity() {
        let mut cache = DbCache::new();
        cache.schemas.insert(
            "app".to_string(),
            SchemaState {
                name: "other".to_string(),
                owner: ObjectId::new("", "postgres"),
                generation: 0,
            },
        );

        let error = DbCacheVersioned::V7(Box::new(cache))
            .into_cache()
            .unwrap_err();
        assert!(error.contains("schema cache key 'app'"));
    }

    #[test]
    fn current_cache_rejects_mismatched_schema_coverage() {
        let mut cache = DbCache::new();
        cache.metadata.schemas = Some(vec!["app".to_string()]);

        let error = DbCacheVersioned::V7(Box::new(cache))
            .into_cache()
            .unwrap_err();
        assert!(error.contains("schema coverage disagrees"));
    }

    #[test]
    fn current_cache_rejects_invalid_foreign_key_column_identity() {
        let child = ObjectId::new("public", "child");
        let parent = ObjectId::new("public", "parent");
        let mut cache = DbCache::new();
        cache.insert_baseline(child.clone(), table(child.clone(), &["parent_id"]));
        cache.insert_baseline(parent.clone(), table(parent.clone(), &["id"]));
        cache.constraints.push(ConstraintState {
            table_id: child.clone(),
            name: "child_parent_id_fkey".to_string(),
            kind: crate::model::constraint::ConstraintKind::ForeignKey,
            validated: true,
            backing_index: None,
        });
        cache.foreign_keys.push(ForeignKeyCache {
            constraint_name: "child_parent_id_fkey".to_string(),
            from_table: child,
            to_table: parent,
            from_columns: vec!["missing".to_string()],
            to_columns: vec!["id".to_string()],
            pk_fk_equality_operators: vec!["=".to_string()],
            pk_pk_equality_operators: vec!["=".to_string()],
            fk_fk_equality_operators: vec!["=".to_string()],
        });

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("missing source column 'public.child.missing'"));
    }

    #[test]
    fn current_cache_rejects_repeated_foreign_key_columns() {
        let child = ObjectId::new("public", "child");
        let parent = ObjectId::new("public", "parent");
        let mut cache = DbCache::new();
        cache.insert_baseline(child.clone(), table(child.clone(), &["a", "b"]));
        cache.insert_baseline(parent.clone(), table(parent.clone(), &["id", "other"]));
        cache.constraints.push(ConstraintState {
            table_id: child.clone(),
            name: "child_parent_fkey".to_string(),
            kind: ConstraintKind::ForeignKey,
            validated: true,
            backing_index: None,
        });
        cache.foreign_keys.push(ForeignKeyCache {
            constraint_name: "child_parent_fkey".to_string(),
            from_table: child,
            to_table: parent,
            from_columns: vec!["a".to_string(), "a".to_string()],
            to_columns: vec!["id".to_string(), "other".to_string()],
            pk_fk_equality_operators: vec!["=".to_string(), "=".to_string()],
            pk_pk_equality_operators: vec!["=".to_string(), "=".to_string()],
            fk_fk_equality_operators: vec!["=".to_string(), "=".to_string()],
        });

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("repeats source column 'a'"));
    }

    #[test]
    fn current_cache_rejects_incomplete_foreign_key_operator_evidence() {
        let child = ObjectId::new("public", "child");
        let parent = ObjectId::new("public", "parent");
        let mut cache = DbCache::new();
        cache.insert_baseline(child.clone(), table(child.clone(), &["parent_id"]));
        cache.insert_baseline(parent.clone(), table(parent.clone(), &["id"]));
        cache.constraints.push(ConstraintState {
            table_id: child.clone(),
            name: "child_parent_fkey".into(),
            kind: ConstraintKind::ForeignKey,
            validated: true,
            backing_index: None,
        });
        cache.foreign_keys.push(ForeignKeyCache {
            constraint_name: "child_parent_fkey".into(),
            from_table: child,
            to_table: parent,
            from_columns: vec!["parent_id".into()],
            to_columns: vec!["id".into()],
            pk_fk_equality_operators: vec!["".into()],
            pk_pk_equality_operators: vec!["=".into()],
            fk_fk_equality_operators: vec!["=".into()],
        });

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("incomplete PK/FK equality-operator evidence"));
    }

    #[test]
    fn current_cache_accepts_a_valid_primary_key_record() {
        let parent = ObjectId::new("public", "parent");
        let mut cache = DbCache::new();
        cache.insert_baseline(parent.clone(), table(parent.clone(), &["id"]));
        cache.constraints.push(ConstraintState {
            table_id: parent.clone(),
            name: "parent_pkey".to_string(),
            kind: ConstraintKind::PrimaryKey,
            validated: true,
            backing_index: None,
        });
        cache.constraint_keys.push(ConstraintKeyCache {
            table_id: parent,
            constraint_name: "parent_pkey".to_string(),
            columns: vec!["id".to_string()],
            is_primary: true,
        });

        assert!(cache.validate_semantics().is_ok());
    }

    #[test]
    fn current_cache_accepts_non_unique_exclusion_backing_index() {
        let table_id = ObjectId::new("public", "ranges");
        let index_id = ObjectId::new("public", "ranges_excl");
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
        cache.indexes.push(IndexCache {
            index_id: index_id.clone(),
            table_id: table_id.clone(),
            using_method: "gist".to_string(),
            key_columns: vec!["id".to_string()],
            included_columns: Vec::new(),
            dependency_columns: vec!["id".to_string()],
            dependency_columns_known: true,
            has_expression_keys: false,
            has_predicate: false,
            is_unique: false,
            is_valid: true,
            is_ready: true,
            is_live: true,
            has_default_sort_order: true,
            has_default_opclasses: true,
            has_default_collations: true,
        });
        cache.constraints.push(ConstraintState {
            table_id,
            name: "ranges_excl_constraint".to_string(),
            kind: ConstraintKind::Exclusion,
            validated: true,
            backing_index: Some(index_id),
        });

        assert!(cache.validate_semantics().is_ok());
    }

    #[test]
    fn current_cache_rejects_population_state_on_non_materialized_relation() {
        let table_id = ObjectId::new("public", "events");
        let mut relation = table(table_id.clone(), &[]);
        relation.is_populated = Some(true);
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id, relation);

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("materialized-view population state"));
    }

    #[test]
    fn current_cache_rejects_inconsistent_role_membership_edges() {
        let member = ObjectId::new("", "member");
        let parent = ObjectId::new("", "parent");
        let mut cache = DbCache::new();
        cache.roles.insert(
            member.clone(),
            RoleState {
                id: member.clone(),
                can_login: true,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: vec![parent.clone()],
            },
        );
        cache.roles.insert(
            parent.clone(),
            RoleState {
                id: parent,
                can_login: false,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("SET ROLE access") && error.contains("without membership"));
    }

    #[test]
    fn current_cache_rejects_membership_options_without_membership() {
        let member = ObjectId::new("", "member");
        let parent = ObjectId::new("", "parent");
        let mut cache = DbCache::new();
        cache.roles.insert(
            member.clone(),
            RoleState {
                id: member,
                can_login: true,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: vec![parent.clone()],
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
        cache.roles.insert(
            parent.clone(),
            RoleState {
                id: parent,
                can_login: false,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("ADMIN option") && error.contains("without membership"));
    }

    #[test]
    fn current_cache_rejects_circular_role_membership() {
        let first = ObjectId::new("", "first");
        let second = ObjectId::new("", "second");
        let mut cache = DbCache::new();
        cache.roles.insert(
            first.clone(),
            RoleState {
                id: first.clone(),
                can_login: false,
                is_superuser: false,
                inherits: true,
                member_of: vec![second.clone()],
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: vec![second.clone()],
            },
        );
        cache.roles.insert(
            second.clone(),
            RoleState {
                id: second,
                can_login: false,
                is_superuser: false,
                inherits: true,
                member_of: vec![first.clone()],
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: vec![first],
            },
        );

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("circular path"));
    }

    #[test]
    fn current_cache_rejects_schema_qualified_role_identity() {
        let role = ObjectId::new("public", "app_role");
        let mut cache = DbCache::new();
        cache.roles.insert(
            role.clone(),
            RoleState {
                id: role,
                can_login: false,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("cluster role namespace"));
    }

    #[test]
    fn current_cache_rejects_schema_qualified_role_membership_target() {
        let member = ObjectId::new("", "member");
        let parent = ObjectId::new("public", "parent");
        let mut cache = DbCache::new();
        cache.roles.insert(
            member.clone(),
            RoleState {
                id: member,
                can_login: false,
                is_superuser: false,
                inherits: true,
                member_of: vec![parent.clone()],
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: vec![parent.clone()],
            },
        );
        cache.roles.insert(
            parent.clone(),
            RoleState {
                id: parent,
                can_login: false,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("cluster role namespace"));
    }

    #[test]
    fn current_cache_rejects_ambiguous_relation_columns() {
        let table_id = ObjectId::new("public", "entries");
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id.clone(), table(table_id, &["id", "id"]));

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("duplicate column 'id'"));
    }

    #[test]
    fn current_cache_rejects_empty_relation_column_identity() {
        let table_id = ObjectId::new("public", "entries");
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id.clone(), table(table_id, &[""]));

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("empty identity"));
    }

    #[test]
    fn current_cache_rejects_noncanonical_object_identities() {
        let mut quoted_whitespace = DbCache::new();
        let id = ObjectId::new("public", " ");
        quoted_whitespace
            .relations
            .insert(id.clone(), table(id, &[" "]));
        assert!(quoted_whitespace.validate_semantics().is_ok());

        let mut empty_name = DbCache::new();
        let id = ObjectId::new("public", "");
        empty_name.relations.insert(id.clone(), table(id, &[]));
        let error = empty_name.validate_semantics().unwrap_err();
        assert!(error.contains("empty object name"));

        let mut inferred = DbCache::new();
        let mut id = ObjectId::new("public", "items");
        id.inferred_schema = true;
        inferred.relations.insert(id.clone(), table(id, &[]));
        let error = inferred.validate_semantics().unwrap_err();
        assert!(error.contains("inferred schema identity"));
    }

    #[test]
    fn current_cache_rejects_ambiguous_schema_scope_and_search_path() {
        let mut duplicate_scope = DbCache::new();
        duplicate_scope.metadata.schemas = Some(vec!["app".into(), "app".into()]);
        let error = duplicate_scope.validate_semantics().unwrap_err();
        assert!(error.contains("duplicate schema 'app'"));

        let mut duplicate_path = DbCache::new();
        duplicate_path.search_path = vec!["public".into(), "public".into()];
        let error = duplicate_path.validate_semantics().unwrap_err();
        assert!(error.contains("search path contains duplicate schema 'public'"));
    }

    #[test]
    fn current_cache_accepts_explicit_scope_in_caller_order() {
        let scope = vec!["public".to_string(), "app".to_string()];
        let mut cache = DbCache::new();
        cache.metadata.schemas = Some(scope.clone());
        cache.coverage = CatalogCoverage::from_sync_scope(Some(&scope));
        assert!(cache.validate_semantics().is_ok());
    }

    #[test]
    fn current_cache_rejects_owner_absent_from_role_catalog() {
        let table_id = ObjectId::new("public", "items");
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id.clone(), table(table_id, &[]));
        let role_id = ObjectId::new("", "known_owner");
        cache.roles.insert(
            role_id.clone(),
            RoleState {
                id: role_id,
                can_login: false,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("relation owner identity 'postgres'"));
    }

    #[test]
    fn current_cache_rejects_empty_provenance_identities() {
        let mut cache = DbCache::new();
        cache.metadata.source_role = Some(String::new());
        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("empty source role identity"));

        let mut cache = DbCache::new();
        cache.metadata.source_search_path = Some(vec![String::new()]);
        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("source search path contains an empty"));
    }

    #[test]
    fn current_cache_rejects_malformed_publication_scope_metadata() {
        let table = crate::analysis::facts::PublicationObjectFact::Table {
            name: crate::ast::identifiers::QualifiedName::new(
                Some(crate::ast::identifiers::Ident::new("public", false)),
                crate::ast::identifiers::Ident::new("items", false),
            ),
            only: false,
            include_partitions: false,
            columns: Some(vec!["id".into(), "id".into()]),
            row_filter: None,
        };
        let mut cache = DbCache::new();
        cache.publications.insert(
            "pub_items".into(),
            PublicationState {
                name: "pub_items".into(),
                owner: None,
                scope: crate::analysis::facts::PublicationScope::Explicit(vec![
                    table.clone(),
                    table,
                ]),
                params: Vec::new(),
                generation: 0,
            },
        );

        let error = DbCacheVersioned::V7(Box::new(cache))
            .into_cache()
            .unwrap_err();
        assert!(error.contains("empty or duplicate table column"));
    }

    #[test]
    fn current_cache_rejects_subscription_owner_outside_role_catalog() {
        let mut cache = DbCache::new();
        cache.roles.insert(
            ObjectId::new("", "present_owner"),
            RoleState {
                id: ObjectId::new("", "present_owner"),
                can_login: false,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
        cache.subscriptions.insert(
            "sub".into(),
            SubscriptionState {
                name: "sub".into(),
                owner: Some("missing_owner".into()),
                connection: crate::analysis::facts::ConnectionTarget::Redacted,
                publications: vec!["pub".into()],
                params: None,
                enabled: true,
                slot_name: None,
                generation: 0,
            },
        );

        let error = DbCacheVersioned::V7(Box::new(cache))
            .into_cache()
            .unwrap_err();
        assert!(error.contains("owner 'missing_owner' is absent"));
    }

    #[test]
    fn current_cache_rejects_duplicate_view_dependencies() {
        let view = ObjectId::new("public", "active_entries");
        let table_id = ObjectId::new("public", "entries");
        let mut cache = DbCache::new();
        let mut view_state = table(view.clone(), &["id"]);
        view_state.kind = RelationKind::View;
        cache.insert_baseline(view.clone(), view_state);
        cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
        let dependency = ViewDependencyCache {
            dependent: view,
            referenced: table_id,
            referenced_column: Some("id".into()),
        };
        cache.dependencies = vec![dependency.clone(), dependency];

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("appears more than once"));
    }

    #[test]
    fn current_cache_rejects_empty_view_dependency_column() {
        let view = ObjectId::new("public", "active_entries");
        let table_id = ObjectId::new("public", "entries");
        let mut cache = DbCache::new();
        let mut view_state = table(view.clone(), &["id"]);
        view_state.kind = RelationKind::View;
        cache.insert_baseline(view.clone(), view_state);
        cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
        cache.dependencies.push(ViewDependencyCache {
            dependent: view,
            referenced: table_id,
            referenced_column: Some(String::new()),
        });

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("empty referenced column identity"));
    }

    #[test]
    fn current_cache_rejects_privilege_for_missing_role() {
        let table_id = ObjectId::new("public", "entries");
        let mut cache = DbCache::new();
        let mut relation = table(table_id.clone(), &["id"]);
        relation.privileges.grants.insert(
            ObjectId::new("", "missing_role"),
            [crate::model::relation::Privilege::Select]
                .into_iter()
                .collect(),
        );
        cache.insert_baseline(table_id, relation);

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("missing grantee role"));
    }

    #[test]
    fn current_cache_allows_public_privilege_grantee() {
        let table_id = ObjectId::new("public", "entries");
        let mut cache = DbCache::new();
        let mut relation = table(table_id.clone(), &["id"]);
        relation.privileges.grants.insert(
            ObjectId::new("", "public"),
            [crate::model::relation::Privilege::Select]
                .into_iter()
                .collect(),
        );
        cache.insert_baseline(table_id, relation);

        assert!(cache.validate_semantics().is_ok());
    }

    #[test]
    fn current_cache_rejects_repeated_constraint_key_columns() {
        let table_id = ObjectId::new("public", "entries");
        let mut cache = DbCache::new();
        cache.insert_baseline(
            table_id.clone(),
            table(table_id.clone(), &["id", "tenant_id"]),
        );
        cache.constraints.push(ConstraintState {
            table_id: table_id.clone(),
            name: "entries_key".to_string(),
            kind: ConstraintKind::Unique,
            validated: true,
            backing_index: None,
        });
        cache.constraint_keys.push(ConstraintKeyCache {
            table_id,
            constraint_name: "entries_key".to_string(),
            columns: vec!["id".to_string(), "id".to_string()],
            is_primary: false,
        });

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("constraint key 'public.entries.entries_key' repeats column 'id'"));
    }

    #[test]
    fn scoped_cache_accepts_a_dependency_to_an_omitted_schema() {
        let view_id = ObjectId::new("app", "v");
        let mut cache = DbCache::new();
        cache.metadata.schemas = Some(vec!["app".to_string()]);
        cache.coverage = CatalogCoverage::from_sync_scope(cache.metadata.schemas.as_deref());
        cache.insert_baseline(
            view_id.clone(),
            RelationState::new(
                view_id.clone(),
                ObjectId::new("", "postgres"),
                0,
                None,
                crate::model::relation::RelationKind::View,
                crate::model::relation::Persistence::Permanent,
                0,
            ),
        );
        cache.dependencies.push(ViewDependencyCache {
            dependent: view_id,
            referenced: ObjectId::new("tenant", "base"),
            referenced_column: None,
        });

        assert!(cache.validate_semantics().is_ok());
    }

    #[test]
    fn current_cache_rejects_view_dependency_on_a_missing_column() {
        let table_id = ObjectId::new("public", "entries");
        let view_id = ObjectId::new("public", "entry_view");
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
        cache.insert_baseline(
            view_id.clone(),
            RelationState::new(
                view_id.clone(),
                ObjectId::new("", "postgres"),
                0,
                None,
                RelationKind::View,
                crate::model::relation::Persistence::Permanent,
                0,
            ),
        );
        cache.dependencies.push(ViewDependencyCache {
            dependent: view_id,
            referenced: table_id,
            referenced_column: Some("missing".to_string()),
        });

        assert!(
            cache
                .validate_semantics()
                .unwrap_err()
                .contains("references missing column")
        );
    }

    #[test]
    fn current_cache_rejects_view_dependency_with_a_non_view_dependent() {
        let table_id = ObjectId::new("public", "entries");
        let referenced_id = ObjectId::new("public", "source");
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
        cache.insert_baseline(referenced_id.clone(), table(referenced_id.clone(), &["id"]));
        cache.dependencies.push(ViewDependencyCache {
            dependent: table_id,
            referenced: referenced_id,
            referenced_column: Some("id".to_string()),
        });

        assert!(
            cache
                .validate_semantics()
                .unwrap_err()
                .contains("has a non-view dependent")
        );
    }

    #[test]
    fn current_cache_rejects_constraint_dependency_on_a_missing_column() {
        let table_id = ObjectId::new("public", "entries");
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
        cache
            .constraints
            .push(crate::model::constraint::ConstraintState {
                table_id: table_id.clone(),
                name: "entries_check".to_string(),
                kind: crate::model::constraint::ConstraintKind::Check,
                validated: true,
                backing_index: None,
            });
        cache
            .constraint_dependencies
            .push(ConstraintDependencyCache {
                table_id,
                constraint_name: "entries_check".to_string(),
                columns: vec!["missing".to_string()],
            });

        assert!(
            cache
                .validate_semantics()
                .unwrap_err()
                .contains("constraint dependency")
        );
    }

    #[test]
    fn current_cache_rejects_generated_dependency_on_a_missing_source_column() {
        let table_id = ObjectId::new("public", "entries");
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id", "total"]));
        cache
            .generated_column_dependencies
            .push(GeneratedColumnDependencyCache {
                table_id,
                column_name: "total".to_string(),
                depends_on_column: "missing".to_string(),
            });

        assert!(
            cache
                .validate_semantics()
                .unwrap_err()
                .contains("generated column dependency")
        );
    }

    #[test]
    fn current_cache_rejects_self_referencing_generated_dependency() {
        let table_id = ObjectId::new("public", "entries");
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["total"]));
        cache
            .generated_column_dependencies
            .push(GeneratedColumnDependencyCache {
                table_id,
                column_name: "total".to_string(),
                depends_on_column: "total".to_string(),
            });

        let error = cache.validate_semantics().unwrap_err();
        assert!(error.contains("cannot depend on itself"));
    }

    #[test]
    fn current_cache_rejects_duplicate_generated_dependency_rows() {
        let table_id = ObjectId::new("public", "entries");
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id", "total"]));
        let dependency = GeneratedColumnDependencyCache {
            table_id,
            column_name: "total".to_string(),
            depends_on_column: "id".to_string(),
        };
        cache.generated_column_dependencies.push(dependency.clone());
        cache.generated_column_dependencies.push(dependency);

        assert!(cache.validate_semantics().unwrap_err().contains(
            "generated column dependency 'public.entries.total -> id' appears more than once"
        ));
    }
    #[test]
    fn current_cache_rejects_dangling_index_relationship() {
        let mut cache = DbCache::new();
        cache.indexes.push(IndexCache {
            index_id: ObjectId::new("public", "items_idx"),
            table_id: ObjectId::new("public", "items"),
            using_method: "btree".into(),
            key_columns: vec!["id".into()],
            included_columns: Vec::new(),
            dependency_columns: vec!["id".into()],
            dependency_columns_known: true,
            has_expression_keys: false,
            has_predicate: false,
            is_unique: false,
            is_valid: true,
            is_ready: true,
            is_live: true,
            has_default_sort_order: true,
            has_default_opclasses: true,
            has_default_collations: true,
        });

        let error = DbCacheVersioned::V7(Box::new(cache))
            .into_cache()
            .unwrap_err();
        assert!(error.contains("references missing relation 'public.items'"));
    }

    #[test]
    fn current_cache_rejects_index_in_a_different_schema_than_relation() {
        let table_id = ObjectId::new("public", "items");
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
        cache.indexes.push(IndexCache {
            index_id: ObjectId::new("other", "items_idx"),
            table_id,
            using_method: "btree".into(),
            key_columns: vec!["id".into()],
            included_columns: Vec::new(),
            dependency_columns: vec!["id".into()],
            dependency_columns_known: true,
            has_expression_keys: false,
            has_predicate: false,
            is_unique: false,
            is_valid: true,
            is_ready: true,
            is_live: true,
            has_default_sort_order: true,
            has_default_opclasses: true,
            has_default_collations: true,
        });

        let error = DbCacheVersioned::V7(Box::new(cache))
            .into_cache()
            .unwrap_err();
        assert!(error.contains("must be in the same schema as indexed relation"));
    }

    #[test]
    fn current_cache_rejects_index_colliding_with_relation_namespace_object() {
        let table_id = ObjectId::new("public", "items");
        let index_id = ObjectId::new("public", "shared_name");
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id.clone(), table(table_id, &["id"]));
        cache.insert_baseline(index_id.clone(), table(index_id.clone(), &["id"]));
        cache.indexes.push(IndexCache {
            index_id,
            table_id: ObjectId::new("public", "items"),
            using_method: "btree".into(),
            key_columns: vec!["id".into()],
            included_columns: Vec::new(),
            dependency_columns: vec!["id".into()],
            dependency_columns_known: true,
            has_expression_keys: false,
            has_predicate: false,
            is_unique: false,
            is_valid: true,
            is_ready: true,
            is_live: true,
            has_default_sort_order: true,
            has_default_opclasses: true,
            has_default_collations: true,
        });

        let error = DbCacheVersioned::V7(Box::new(cache))
            .into_cache()
            .unwrap_err();
        assert!(error.contains("collides with another relation-namespace object"));
    }

    #[test]
    fn current_cache_rejects_sequence_colliding_with_relation_namespace_object() {
        let table_id = ObjectId::new("public", "items");
        let shared_id = ObjectId::new("public", "shared_name");
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id.clone(), table(table_id, &["id"]));
        cache.insert_baseline(shared_id.clone(), table(shared_id.clone(), &["id"]));
        cache.sequences.insert(
            shared_id.clone(),
            SequenceState {
                id: shared_id,
                owner: ObjectId::new("", "postgres"),
                owned_by: None,
                kind: crate::model::sequence::SequenceKind::Owned,
                generation: 0,
            },
        );

        let error = DbCacheVersioned::V7(Box::new(cache))
            .into_cache()
            .unwrap_err();
        assert!(error.contains("collides with another relation-namespace object"));
    }

    #[test]
    fn current_cache_rejects_trigger_in_a_different_schema_than_table() {
        let table_id = ObjectId::new("public", "items");
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
        cache.triggers.push(TriggerCache {
            trigger_id: ObjectId::new("other", "items_trigger"),
            table_id,
            function_id: ObjectId::new("public", "items_trigger_fn()"),
            enabled_mode: TriggerEnableMode::Origin,
        });

        let error = DbCacheVersioned::V7(Box::new(cache))
            .into_cache()
            .unwrap_err();
        assert!(error.contains("must be in the same schema as trigger table"));
    }

    #[test]
    fn current_cache_rejects_index_without_complete_dependency_evidence() {
        let table_id = ObjectId::new("public", "items");
        let mut cache = DbCache::new();
        cache.insert_baseline(table_id.clone(), table(table_id.clone(), &["id"]));
        cache.indexes.push(IndexCache {
            index_id: ObjectId::new("public", "items_idx"),
            table_id,
            using_method: "btree".into(),
            key_columns: vec!["id".into()],
            included_columns: Vec::new(),
            dependency_columns: vec!["id".into()],
            dependency_columns_known: false,
            has_expression_keys: false,
            has_predicate: false,
            is_unique: false,
            is_valid: true,
            is_ready: true,
            is_live: true,
            has_default_sort_order: true,
            has_default_opclasses: true,
            has_default_collations: true,
        });

        assert!(
            DbCacheVersioned::V7(Box::new(cache))
                .into_cache()
                .unwrap_err()
                .contains("missing complete dependency-column evidence")
        );
    }

    #[test]
    fn current_cache_validates_stable_direct_inheritance() {
        let parent = ObjectId::new("public", "parent");
        let child = ObjectId::new("public", "child");
        let mut cache = DbCache::new();
        cache.search_path.clear();
        cache.insert_baseline(parent.clone(), table(parent.clone(), &["id"]));
        cache.insert_baseline(child.clone(), table(child.clone(), &["id"]));
        cache.inheritances.push(InheritanceCache {
            child: child.clone(),
            parent: parent.clone(),
            sequence: 1,
            is_partition: false,
            detach_pending: false,
        });
        assert!(
            DbCacheVersioned::V7(Box::new(cache.clone()))
                .into_cache()
                .is_ok()
        );

        cache.inheritances[0].detach_pending = true;
        let error = DbCacheVersioned::V7(Box::new(cache))
            .into_cache()
            .unwrap_err();
        assert!(error.contains("being detached"));
    }

    #[test]
    fn current_cache_rejects_cross_catalog_contradictions() {
        let mut missing_search_schema = DbCache::new();
        missing_search_schema.schemas.insert(
            "app".to_string(),
            SchemaState {
                name: "app".to_string(),
                owner: ObjectId::new("", "postgres"),
                generation: 0,
            },
        );
        assert!(
            missing_search_schema
                .validate_semantics()
                .unwrap_err()
                .contains("search path references missing schema 'public'")
        );

        let mut missing_sequence_owner = DbCache::new();
        let sequence_id = ObjectId::new("public", "items_id_seq");
        missing_sequence_owner.sequences.insert(
            sequence_id.clone(),
            SequenceState {
                id: sequence_id,
                owner: ObjectId::new("", "postgres"),
                owned_by: Some((ObjectId::new("public", "items"), "id".to_string())),
                kind: crate::model::sequence::SequenceKind::Owned,
                generation: 0,
            },
        );
        assert!(
            missing_sequence_owner
                .validate_semantics()
                .unwrap_err()
                .contains("ownership references missing relation 'public.items'")
        );

        let mut cross_schema_sequence_owner = DbCache::new();
        let table_id = ObjectId::new("public", "items");
        cross_schema_sequence_owner.insert_baseline(table_id.clone(), table(table_id, &["id"]));
        cross_schema_sequence_owner.sequences.insert(
            ObjectId::new("archive", "items_id_seq"),
            SequenceState {
                id: ObjectId::new("archive", "items_id_seq"),
                owner: ObjectId::new("", "postgres"),
                owned_by: Some((ObjectId::new("public", "items"), "id".to_string())),
                kind: crate::model::sequence::SequenceKind::Owned,
                generation: 0,
            },
        );
        assert!(
            cross_schema_sequence_owner
                .validate_semantics()
                .unwrap_err()
                .contains("must be in the same schema as owning table")
        );

        let mut missing_membership_role = DbCache::new();
        let role_id = ObjectId::new("", "member");
        missing_membership_role.roles.insert(
            role_id.clone(),
            RoleState {
                id: role_id,
                can_login: true,
                is_superuser: false,
                inherits: true,
                member_of: vec![ObjectId::new("", "missing")],
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
        assert!(
            missing_membership_role
                .validate_semantics()
                .unwrap_err()
                .contains("membership references missing role")
        );

        let mut invalid_view_dependency = DbCache::new();
        invalid_view_dependency
            .dependencies
            .push(ViewDependencyCache {
                dependent: ObjectId::new("public", "view"),
                referenced: ObjectId::new("public", "missing"),
                referenced_column: None,
            });
        assert!(
            invalid_view_dependency
                .validate_semantics()
                .unwrap_err()
                .contains("references a missing relation")
        );
    }
}
