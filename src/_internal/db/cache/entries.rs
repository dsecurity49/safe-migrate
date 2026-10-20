use super::*;

/// A cross-scope dependency, keeping both endpoints.
///
/// Direction matters: `scoped` is the object inside the synced schemas and
/// `external` depends on it from outside. Storing only the external endpoint
/// cannot answer "does this object have dependents out of scope?".
///
/// `family` is the catalog family of `scoped`. Identity is `(schema, name)`,
/// which a table and a type in one schema may share, so the family keeps
/// cross-scope exposure attributable to the object that actually has it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct ScopedDependencyEdge {
    pub family: CatalogFamily,
    pub scoped: ObjectId,
    /// The out-of-scope dependent, absent when its catalog class could not be
    /// resolved. That is exposure we can neither model nor name, and it still
    /// forces the scoped endpoint to stay unevaluated.
    pub external: Option<ObjectId>,
}

impl ScopedDependencyEdge {
    pub(crate) fn new(family: CatalogFamily, scoped: ObjectId, external: ObjectId) -> Self {
        Self {
            family,
            scoped,
            external: Some(external),
        }
    }

    pub(crate) fn unresolved_external(family: CatalogFamily, scoped: ObjectId) -> Self {
        Self {
            family,
            scoped,
            external: None,
        }
    }

    /// True when this edge makes `scoped` unevaluatable: a modeled external
    /// dependent, or an external dependent we could not resolve at all.
    pub(crate) fn exposes(&self, family: CatalogFamily, id: &ObjectId) -> bool {
        self.family == family && self.scoped == *id
    }
}

impl Ord for ScopedDependencyEdge {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.family
            .cmp(&other.family)
            .then_with(|| self.scoped.cmp_identity(&other.scoped))
            .then_with(|| match (&self.external, &other.external) {
                (None, None) => std::cmp::Ordering::Equal,
                (None, Some(_)) => std::cmp::Ordering::Less,
                (Some(_), None) => std::cmp::Ordering::Greater,
                (Some(a), Some(b)) => a.cmp_identity(b),
            })
    }
}

impl PartialOrd for ScopedDependencyEdge {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ForeignKeyCache {
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
    pub(crate) fn has_complete_operator_evidence(&self) -> bool {
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
/// mutable constraint lifecycle while the cache can preserve catalog proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConstraintKeyCache {
    pub table_id: ObjectId,
    pub constraint_name: String,
    pub columns: Vec<String>,
    pub is_primary: bool,
}

/// Complete direct column dependencies for expression-backed constraints
/// (currently CHECK and EXCLUDE). An empty vector is authoritative: the
/// expression has no relation-column dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConstraintDependencyCache {
    pub table_id: ObjectId,
    pub constraint_name: String,
    pub columns: Vec<String>,
}

/// A generated column's direct source-column dependencies from `pg_attrdef`.
/// The generated column itself is identified separately so dropping it can
/// remove only its own expression edge; source-column drops remain
/// conservative until dependent-column CASCADE is modeled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GeneratedColumnDependencyCache {
    pub table_id: ObjectId,
    pub column_name: String,
    pub depends_on_column: String,
}

/// A normal `pg_attrdef` dependency from a column default to a sequence.
/// This is distinct from sequence OWNED BY metadata: a default can reference
/// a standalone sequence without making that sequence owned by the table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DefaultSequenceDependencyCache {
    pub table_id: ObjectId,
    pub column_name: String,
    pub sequence_id: ObjectId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IndexCache {
    pub index_id: ObjectId,
    pub table_id: ObjectId,
    /// The index's shape, exactly as the catalog states it.
    pub definition: IndexDefinition,
    /// Every table column named by PostgreSQL's `pg_depend` rows for this
    /// index, including expression keys and predicates. This is unordered
    /// dependency evidence, not an index definition.
    pub dependency_columns: Vec<String>,
    /// Whether `dependency_columns` came from complete catalog evidence.
    /// Locally parsed expression/predicate indexes cannot claim this yet.
    pub dependency_columns_known: bool,
    /// `pg_index.indimmediate`; deferred unique indexes cannot be a replica identity.
    pub is_immediate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TriggerCache {
    pub trigger_id: ObjectId,
    pub table_id: ObjectId,
    pub function_id: ObjectId,
    #[serde(default)]
    pub row_level: bool,
    #[serde(default)]
    pub parent_trigger_id: Option<ObjectId>,
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
pub(crate) struct ViewDependencyCache {
    pub dependent: ObjectId,
    pub referenced: ObjectId,
    /// `None` means PostgreSQL reported a relation-level dependency. Such a
    /// row must remain conservative for column-level transitions.
    pub referenced_column: Option<String>,
}

/// The non-relation object a view depends on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ViewDependencyTarget {
    Routine { routine: ObjectId },
    Type { ty: ObjectId },
}

/// A `pg_depend` row from a view to a routine or a type.
///
/// PostgreSQL records these from the rewrite rules of the view, so a synced
/// view carries the same obligations as one built from the statements in this
/// migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ViewObjectDependencyCache {
    pub dependent: ObjectId,
    pub target: ViewDependencyTarget,
}

/// One direct table or index inheritance relationship from `pg_inherits`.
///
/// The row is retained separately from generic dependencies because PostgreSQL
/// exposes detach-in-progress state here and the transition engine needs the
/// direct parent/child direction for partition-cycle and publication scope
/// reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InheritanceCache {
    pub child: ObjectId,
    pub parent: ObjectId,
    pub sequence: i32,
    /// `pg_class.relispartition` for `child`. Distinguishes declarative
    /// partitioning from traditional `INHERITS`, which shares `pg_inherits`.
    pub is_partition: bool,
    pub detach_pending: bool,
}

/// An index that is a partition of a partitioned index.
///
/// PostgreSQL stores this in the same `pg_inherits` rows as table partitions,
/// with the parent's `relkind` `I` and the child's `i`. The row is what makes
/// `DROP INDEX` on the child fail while the parent exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IndexAttachmentCache {
    /// The attached (partition) index.
    pub child: ObjectId,
    /// The partitioned (parent) index.
    pub parent: ObjectId,
}
