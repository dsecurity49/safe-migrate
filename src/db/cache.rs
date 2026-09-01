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
/// analyzer. The V8 cache records this explicitly instead of treating one
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
        // requested scope before a V8 cache can be written.
        Self::from_sync_scope(None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignKeyCache {
    pub constraint_name: String,
    pub from_table: ObjectId,
    pub to_table: ObjectId,
    /// Ordered `pg_constraint.conkey` identities resolved through
    /// `pg_attribute`. Empty vectors are invalid for V8 FK records.
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
/// mutable constraint lifecycle while Cache V8 can preserve catalog proof.
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
    #[serde(default)]
    pub generated_column_dependencies: Vec<GeneratedColumnDependencyCache>,
    #[serde(default)]
    pub default_sequence_dependencies: Vec<DefaultSequenceDependencyCache>,
    pub triggers: Vec<TriggerCache>,
    pub functions: HashMap<ObjectId, FunctionState>,
    pub types: HashMap<ObjectId, TypeState>,
    pub roles: HashMap<ObjectId, RoleState>,
    pub schemas: HashMap<String, SchemaState>,
    pub sequences: HashMap<ObjectId, SequenceState>,
    pub dependencies: Vec<ViewDependencyCache>,
    pub inheritances: Vec<InheritanceCache>,
    pub publications: HashMap<String, PublicationState>,
    pub subscriptions: HashMap<String, SubscriptionState>,
}

pub const CACHE_FORMAT_VERSION: u32 = 8;

/// Current durable cache header. V8 adds PostgreSQL-selected FK equality
/// operator evidence to the normalized catalog snapshot.
pub const CACHE_V8_MAGIC: &[u8] = b"SMCACHE08";
/// Retained for decoding fixtures and reporting actionable legacy-cache errors.
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
    V8(Box<DbCache>),
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
            DbCacheVersioned::V8(_) => 8,
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
            DbCacheVersioned::V7(c) | DbCacheVersioned::V8(c) => {
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

    pub(crate) fn validate_semantics(&self) -> Result<(), String> {
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
                    "Cache V8 coverage is missing the required '{}' catalog family",
                    family.as_str(),
                ));
            }
        }
        if self.coverage.schema_scope.explicit_schemas() != self.metadata.schemas {
            return Err(
                "Cache V8 schema coverage disagrees with legacy metadata schema scope".to_string(),
            );
        }
        for (id, relation) in &self.relations {
            if id != &relation.id {
                return Err(format!(
                    "relation cache key '{}' disagrees with embedded identity '{}'",
                    id, relation.id
                ));
            }
        }
        for (id, function) in &self.functions {
            if id != &function.id {
                return Err(format!(
                    "routine cache key '{}' disagrees with embedded identity '{}'",
                    id, function.id
                ));
            }
        }
        for (id, ty) in &self.types {
            if id != &ty.id {
                return Err(format!(
                    "type cache key '{}' disagrees with embedded identity '{}'",
                    id, ty.id
                ));
            }
        }
        for (id, role) in &self.roles {
            if id != &role.id {
                return Err(format!(
                    "role cache key '{}' disagrees with embedded identity '{}'",
                    id, role.id
                ));
            }
        }
        for (name, schema) in &self.schemas {
            if name != &schema.name {
                return Err(format!(
                    "schema cache key '{}' disagrees with embedded identity '{}'",
                    name, schema.name
                ));
            }
        }
        for (id, sequence) in &self.sequences {
            if id != &sequence.id {
                return Err(format!(
                    "sequence cache key '{}' disagrees with embedded identity '{}'",
                    id, sequence.id
                ));
            }
        }
        for (name, publication) in &self.publications {
            if name != &publication.name {
                return Err(format!(
                    "publication cache key '{}' disagrees with embedded identity '{}'",
                    name, publication.name
                ));
            }
        }
        for (name, subscription) in &self.subscriptions {
            if name != &subscription.name {
                return Err(format!(
                    "subscription cache key '{}' disagrees with embedded identity '{}'",
                    name, subscription.name
                ));
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
            for target in role.member_of.iter().chain(&role.can_set_role_to) {
                if !self.roles.contains_key(target) {
                    return Err(format!(
                        "role '{}' membership references missing role '{}'",
                        id, target
                    ));
                }
            }
        }

        let mut constraint_ids = HashSet::new();
        for constraint in &self.constraints {
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
        }

        let mut constraint_key_ids = HashSet::new();
        for key in &self.constraint_keys {
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

        for dependency in &self.dependencies {
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
    fn current_cache_format_is_v8() {
        assert_eq!(CACHE_FORMAT_VERSION, 8);
        assert_eq!(DbCacheVersioned::V8(Box::default()).format_version(), 8);
        assert_eq!(CACHE_V8_MAGIC, b"SMCACHE08");
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

        let error = DbCacheVersioned::V8(Box::new(cache))
            .into_cache()
            .unwrap_err();
        assert!(error.contains("schema cache key 'app'"));
    }

    #[test]
    fn current_cache_rejects_mismatched_schema_coverage() {
        let mut cache = DbCache::new();
        cache.metadata.schemas = Some(vec!["app".to_string()]);

        let error = DbCacheVersioned::V8(Box::new(cache))
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
        assert!(error.contains("incomplete equality-operator evidence"));
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

        let mut missing_membership_role = DbCache::new();
        let role_id = ObjectId::new("", "member");
        missing_membership_role.roles.insert(
            role_id.clone(),
            RoleState {
                id: role_id,
                can_login: true,
                is_superuser: false,
                member_of: vec![ObjectId::new("", "missing")],
                can_set_role_to: Vec::new(),
                granted_privileges: Vec::new(),
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
