use crate::_internal::analysis::expr_ir::ExprIr;
use crate::_internal::ast::identifiers::{Ident, QualifiedName};
use crate::_internal::model::index::{IndexOrder, IndexPredicate, WrittenName};

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum PersistenceFact {
    Permanent,
    Temporary,
    Unlogged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OnCommitFact {
    PreserveRows,
    DeleteRows,
    Drop,
}

/// Properties selected by `CREATE TABLE ... LIKE` after applying its ordered
/// INCLUDING/EXCLUDING clauses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct LikePropertiesFact {
    pub defaults: bool,
    pub generated: bool,
    pub storage: bool,
    pub compression: bool,
    pub statistics: bool,
    pub constraints: bool,
    pub indexes: bool,
    pub identity: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LikeSourceFact {
    pub relation: QualifiedName,
    pub properties: LikePropertiesFact,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ReplicaIdentityFact {
    Default,
    Full,
    Nothing,
    UsingIndex(QualifiedName),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum PolicyCommand {
    All,
    Select,
    Insert,
    Update,
    Delete,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SearchPathTarget {
    Default,
    Schemas(Vec<String>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TimeoutSetting {
    Lock,
    Statement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TimeoutSettingValue {
    Default,
    Milliseconds(u64),
    Current,
    Invalid(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResetSettingTarget {
    All,
    SearchPath,
    LockTimeout,
    StatementTimeout,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum TypeCreationKind {
    Enum { variants: Vec<String> },
    Range { subtype: Option<String> },
    Composite { fields: Vec<CompositeFieldFact> },
    Base { element: Option<String> },
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct CompositeFieldFact {
    pub name: String,
    pub data_type: String,
}

/// A routine a view calls.
///
/// `argument_types` is populated only when every argument is a plain column
/// reference of the view's source, which is the one case where the signature
/// can be stated exactly.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RoutineReferenceFact {
    pub name: QualifiedName,
    pub argument_types: Option<Vec<String>>,
}

/// The types a view body casts to.
///
/// A view that merely selects a column of a type does not depend on that type:
/// PostgreSQL records the dependency from the cast, not the output column.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CastTypeReferenceFact {
    pub name: QualifiedName,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterViewAction {
    RenameTo {
        new_name: Ident,
    },
    OwnerTo {
        new_owner: RoleFact,
    },
    SetSchema {
        new_schema: String,
    },
    SetDefault {
        column: String,
        default: Option<ExprIr>,
    },
    DropDefault {
        column: String,
    },
    RenameColumn {
        from: Ident,
        to: Ident,
    },
    SetOptions {
        options: Vec<AttributeFact>,
    },
    ResetOptions {
        options: Vec<AttributeFact>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterMaterializedViewActionFact {
    RenameTo { new_name: Ident },
    SetSchema { new_schema: String },
    RenameColumn { from: Ident, to: Ident },
    SetTablespace { new_tablespace: Ident },
    SetAccessMethod { new_access_method: Ident },
    DependsOnExtension { extension_name: Ident },
    NoDependsOnExtension { extension_name: Ident },
    SetOptions { options: Vec<AttributeFact> },
    ResetOptions { options: Vec<AttributeFact> },
    ClusterOn { index_name: Ident },
    SetWithoutCluster,
    SetStorage { column: String, storage: String },
    SetCompression { column: String, compression: String },
    OwnerTo { new_owner: RoleFact },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterSchemaActionFact {
    RenameTo { new_name: Ident },
    OwnerTo { new_owner: RoleFact },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum StatementFact {
    CreateSchema {
        name: QualifiedName,
        if_not_exists: bool,
        authorization: Option<RoleFact>,
    },
    AlterSchema {
        name: QualifiedName,
        action: AlterSchemaActionFact,
    },
    DropSchema {
        names: Vec<QualifiedName>,
        if_exists: bool,
        cascade: bool,
    },
    CreateTable {
        name: QualifiedName,
        if_not_exists: bool,
        as_select: bool,
        persistence: PersistenceFact,
        on_commit: Option<OnCommitFact>,
        columns: Vec<ColumnFact>,
        foreign_keys: Vec<FkFact>,
        table_constraints: Vec<TableConstraintFact>,
        partition_by: Option<String>,
        /// Column keys extracted directly from the `PARTITION BY` node at
        /// visitor time — `(resolved_name, raw_spelling)` per key column.
        /// Empty when the key uses unsupported expressions (collation,
        /// op-class, expression keys) or when there is no partition clause.
        partition_keys: Vec<(String, String)>,
        partition_strategy: Option<String>,
        partition_of: Option<QualifiedName>,
        partition_bound: Option<String>,
        inherits: Vec<QualifiedName>,
        like_sources: Vec<LikeSourceFact>,
        of_type: Option<QualifiedName>,
        select_source: Option<QualifiedName>,
        select_outputs: Vec<SelectOutputFact>,
        select_projection_complete: bool,
    },
    CreateView {
        name: QualifiedName,
        or_replace: bool,
        depends_on: Vec<QualifiedName>,
        /// An explicit `v (a, b)` column list, which renames the outputs.
        column_list: Vec<String>,
        /// `WITH (...)` options plus a `WITH [LOCAL] CHECK OPTION` clause,
        /// which PostgreSQL folds into a `check_option` option.
        options: Vec<AttributeFact>,
        /// Whether the query is automatically updatable, reading every
        /// unqualified aggregate-named call as its built-in aggregate.
        updatability: ViewUpdatabilityFact,
        /// The same verdict when none of those calls is an aggregate.
        updatability_without_aggregates: ViewUpdatabilityFact,
        /// The unqualified aggregate-named calls the resolver must place
        /// against the routine search path to choose between the two verdicts.
        aggregate_candidates: Vec<AggregateCandidateFact>,
        select_outputs: Vec<SelectOutputFact>,
        select_projection_complete: bool,
        select_source: Option<QualifiedName>,
        /// The base relation's alias, or its name when no alias is written.
        select_source_name: Option<String>,
        routines: Vec<RoutineReferenceFact>,
        cast_types: Vec<CastTypeReferenceFact>,
    },
    AlterView {
        name: QualifiedName,
        action: AlterViewAction,
        if_exists: bool,
    },
    CreateMaterializedView {
        name: QualifiedName,
        depends_on: Vec<QualifiedName>,
        if_not_exists: bool,
        with_no_data: bool,
        /// An explicit `mv (a, b)` column list, which renames the outputs.
        column_list: Vec<String>,
        access_method: Option<String>,
        tablespace: Option<String>,
        options: Vec<AttributeFact>,
        select_outputs: Vec<SelectOutputFact>,
        select_projection_complete: bool,
        select_source: Option<QualifiedName>,
        routines: Vec<RoutineReferenceFact>,
        cast_types: Vec<CastTypeReferenceFact>,
    },
    AlterMaterializedView {
        name: QualifiedName,
        actions: Vec<AlterMaterializedViewActionFact>,
        if_exists: bool,
    },
    RefreshMaterializedView {
        name: QualifiedName,
        concurrently: bool,
        with_no_data: bool,
    },
    CreateIndex {
        name: QualifiedName,
        relation: QualifiedName,
        if_not_exists: bool,
        concurrently: bool,
        only: bool,
        using_method: Option<String>,
        predicate: IndexPredicate,
        unique: bool,
        nulls_not_distinct: bool,
        key_columns: Vec<String>,
        /// Aligned with key positions; `Some` is the parsed expression for an
        /// expression key and `None` for a plain column.
        key_expressions: Vec<Option<ExprIr>>,
        /// Aligned with key positions.
        key_orders: Vec<IndexOrder>,
        /// Aligned with key positions; `None` means the type's default.
        key_opclasses: Vec<Option<WrittenName>>,
        /// Aligned with key positions; `None` means the derived collation.
        key_collations: Vec<Option<WrittenName>>,
        included_columns: Vec<String>,
    },
    CreatePolicy {
        name: String,
        table: QualifiedName,
        permissive: bool,
        command: PolicyCommand,
        /// False when roles or policy expressions are present but not modeled.
        semantics_complete: bool,
    },
    DropPolicy {
        name: String,
        table: QualifiedName,
        if_exists: bool,
    },
    CreateTrigger {
        name: String,
        table: QualifiedName,
        function: Option<QualifiedName>,
        row_level: bool,
    },
    DropTrigger {
        name: String,
        table: QualifiedName,
        if_exists: bool,
    },
    AlterTrigger {
        name: String,
        table: QualifiedName,
        new_name: String,
    },
    AlterTable {
        name: QualifiedName,
        only: bool,
        actions: Vec<AlterTableActionFact>,
    },
    AlterIndex {
        name: QualifiedName,
        if_exists: bool,
        actions: Vec<AlterIndexActionFact>,
    },
    AlterIndexAllInTablespace {
        source_tablespace: Ident,
        target_tablespace: Ident,
    },
    CreateType(CreateTypeFact),
    AlterType(AlterTypeFact),
    CreateExtension(CreateExtensionFact),
    AlterExtension(AlterExtensionFact),
    DropExtension(DropExtensionFact),
    CreateDomain(CreateDomainFact),
    AlterDomain {
        name: QualifiedName,
        action: Option<AlterDomainActionFact>,
    },
    DropDomain {
        names: Vec<QualifiedName>,
        if_exists: bool,
        cascade: bool,
    },
    DropType {
        names: Vec<QualifiedName>,
        if_exists: bool,
        cascade: bool,
    },
    CreateSequence {
        name: QualifiedName,
        if_not_exists: bool,
        owned_by: Option<(QualifiedName, String)>,
        persistence: PersistenceFact,
        options: IdentitySequenceOptionsFact,
    },
    AlterSequence {
        name: QualifiedName,
        if_exists: bool,
        /// Every option the statement carries, in written order.
        options: Vec<SequenceOptionFact>,
        /// At most one statement form beyond the options.
        action: Option<AlterSequenceActionFact>,
    },
    DropSequence {
        names: Vec<QualifiedName>,
        if_exists: bool,
        cascade: bool,
    },
    DropTable {
        names: Vec<QualifiedName>,
        if_exists: bool,
        cascade: bool,
    },
    DropView {
        names: Vec<QualifiedName>,
        if_exists: bool,
        cascade: bool,
    },
    DropMaterializedView {
        names: Vec<QualifiedName>,
        if_exists: bool,
        cascade: bool,
    },
    DropIndex {
        names: Vec<QualifiedName>,
        if_exists: bool,
        concurrently: bool,
        cascade: bool,
    },
    Lock {
        targets: Vec<RelationTargetFact>,
        mode: LockModeFact,
        nowait: bool,
    },
    Truncate {
        targets: Vec<RelationTargetFact>,
        cascade: bool,
        restart_identity: bool,
    },
    SetSearchPath {
        target: SearchPathTarget,
        local: bool,
    },
    SetTimeout {
        setting: TimeoutSetting,
        value: TimeoutSettingValue,
        local: bool,
    },
    ResetSettings {
        target: ResetSettingTarget,
    },
    BeginTransaction,
    CommitTransaction,
    CommitAndChain,
    RollbackTransaction,
    RollbackAndChain,
    RollbackToSavepoint {
        name: String,
    },
    Savepoint {
        name: String,
    },
    ReleaseSavepoint {
        name: String,
    },
    PrepareTransaction {
        name: String,
    },
    SetTransaction,
    SetConstraints,
    OpaqueBlock,
    Execute,
    /// Parsed SQL that changes PostgreSQL metadata but no schema state modeled
    /// by safe-migrate, such as `COMMENT ON`.
    SchemaNeutralNoop,
    Reindex {
        target_kind: ReindexTargetKindFact,
        target_name: Option<QualifiedName>,
        concurrently: bool,
    },
    Vacuum {
        relation: Option<QualifiedName>,
        is_full: bool,
    },
    CreateFunction(CreateFunctionFact),
    AlterFunction(AlterFunctionFact),
    DropFunction(DropFunctionFact),
    CreateProcedure(CreateProcedureFact),
    AlterProcedure(AlterProcedureFact),
    DropProcedure(DropProcedureFact),
    CreateAggregate(CreateAggregateFact),
    AlterAggregate(AlterAggregateFact),
    DropAggregate(DropAggregateFact),
    CreatePublication(CreatePublicationFact),
    AlterPublication(AlterPublicationFact),
    DropPublication(DropPublicationFact),
    CreateSubscription(CreateSubscriptionFact),
    AlterSubscription(AlterSubscriptionFact),
    DropSubscription(DropSubscriptionFact),
    CreateRole(CreateRoleFact),
    AlterRole(AlterRoleFact),
    DropRole(DropRoleFact),
    Grant(GrantFact),
    Revoke(RevokeFact),
    CreateDatabase(CreateDatabaseFact),
    AlterDatabase(AlterDatabaseFact),
    DropDatabase(DropDatabaseFact),
    /// `SET [LOCAL] ROLE { rolename | NONE }` or
    /// `SET [LOCAL] SESSION AUTHORIZATION { rolename | DEFAULT }`.
    /// `role = None` means NONE / DEFAULT (restore the session default).
    /// `local = true` means the change is scoped to the current transaction.
    /// `is_session_auth = true` means SET SESSION AUTHORIZATION (which also
    /// updates the session-level default, unlike plain SET ROLE).
    SetRole {
        role: Option<RoleFact>,
        local: bool,
        is_session_auth: bool,
    },
}

/// A relation target whose `ONLY` modifier materially changes inheritance and
/// partition behavior.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RelationTargetFact {
    pub name: QualifiedName,
    pub only: bool,
}

/// Lifecycle form used by `ALTER TABLE ... DETACH PARTITION`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DetachPartitionMode {
    Immediate,
    Concurrently,
    Finalize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockModeFact {
    AccessShare,
    RowShare,
    RowExclusive,
    ShareUpdateExclusive,
    Share,
    ShareRowExclusive,
    Exclusive,
    AccessExclusive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuleEnableModeFact {
    Origin,
    Disabled,
    Replica,
    Always,
}

/// One `ALTER SEQUENCE` option.
///
/// PostgreSQL collects every option of the statement into one bag, rejects a
/// repeated option, and cross-checks the merged result, so the options are not
/// independent clauses.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SequenceOptionFact {
    As(String),
    Cache(i64),
    Cycle(bool),
    Increment(i64),
    Logged(bool),
    /// `None` is `NO MAXVALUE`.
    MaxValue(Option<i64>),
    /// `None` is `NO MINVALUE`.
    MinValue(Option<i64>),
    OwnedBy(Option<(QualifiedName, String)>),
    SequenceName(String),
    Start(i64),
    /// `None` is `RESTART` with no value, which resumes at the start value.
    Restart(Option<i64>),
}

/// The single statement form `ALTER SEQUENCE` takes alongside its options.
///
/// PostgreSQL parses ownership, rename, and schema changes as their own
/// statement kinds rather than as sequence options, so a statement carrying
/// more than one of them is not a form the server accepts.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterSequenceActionFact {
    OwnerTo(RoleFact),
    RenameTo(Ident),
    SetSchema(String),
}

// SET STATISTICS accepts an integer (-1..10000) or DEFAULT.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum StatisticsTarget {
    Default,
    Value(i32),
}

/// The index column `ALTER INDEX ... ALTER [COLUMN] c SET STATISTICS` names.
/// PostgreSQL accepts either a column name or a 1-based column number.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum IndexStatisticsColumn {
    Name(String),
    Number(i32),
}

impl std::fmt::Display for IndexStatisticsColumn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Name(name) => write!(f, "{name}"),
            Self::Number(number) => write!(f, "{number}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterIndexActionFact {
    RenameTo {
        new_name: Ident,
    },
    SetTablespace {
        new_tablespace: Ident,
    },
    AttachPartition {
        partition_name: QualifiedName,
    },
    DependsOnExtension {
        extension_name: Ident,
    },
    NoDependsOnExtension {
        extension_name: Ident,
    },
    SetStatistics {
        /// The index column the target applies to. PostgreSQL requires one:
        /// the bare `SET STATISTICS` form is a syntax error.
        column: IndexStatisticsColumn,
        target: StatisticsTarget,
    },
    SetOptions {
        options: Vec<AttributeFact>,
    },
    ResetOptions {
        options: Vec<AttributeFact>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateTypeFact {
    pub name: QualifiedName,
    pub kind: TypeCreationKind,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterTypeFact {
    pub name: QualifiedName,
    pub actions: Vec<AlterTypeActionFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterTypeActionFact {
    RenameTo {
        new_name: Ident,
    },
    SetSchema {
        new_schema: String,
    },
    AddValue {
        new_value: String,
        neighbor: Option<String>,
        before: bool,
    },
    RenameValue {
        old_value: String,
        new_value: String,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateExtensionFact {
    pub name: String,
    pub if_not_exists: bool,
    pub schema: Option<String>,
    pub version: Option<String>,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterExtensionFact {
    pub name: String,
    pub action: AlterExtensionActionFact,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterExtensionActionFact {
    Add(ExtensionMemberFact),
    Drop(ExtensionMemberFact),
    Update { version: Option<String> },
    SetSchema { new_schema: String },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropExtensionFact {
    pub names: Vec<String>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ExtensionMemberFact {
    Named {
        kind: crate::_internal::model::extension::ExtensionMemberKind,
        name: QualifiedName,
    },
    Routine {
        name: QualifiedName,
        params: Vec<String>,
    },
    Schema(String),
    Unmodeled(String),
}

#[derive(Clone, Debug, PartialEq, Default)]
pub(crate) enum RoleFact {
    #[default]
    Unknown,
    Named {
        name: String,
        via_legacy_group_syntax: bool,
    },
    CurrentUser,
    CurrentRole,
    SessionUser,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateRoleFact {
    pub name: String,
    pub inherits: bool,
    pub can_login: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterRoleFact {
    pub name: RoleFact,
    pub inherits: Option<bool>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropRoleFact {
    pub names: Vec<String>,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateFunctionFact {
    pub name: QualifiedName,
    pub or_replace: bool,
    pub params: Vec<ParamFact>,
    pub return_type: Option<RetTypeFact>,
    pub options: Vec<FuncOptionFact>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ParamFact {
    pub mode: ParamModeFact,
    pub name: Option<String>,
    pub ty: String,
    pub default: Option<ExprIr>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum ParamModeFact {
    In,
    Out,
    InOut,
    Variadic,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum RetTypeFact {
    Table(Vec<ColumnFact>),
    /// A single type. `setof` is kept apart from the type name because
    /// PostgreSQL stores it in `pg_proc.proretset` and refuses a replacement
    /// that changes it.
    Scalar {
        ty: String,
        setof: bool,
    },
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum FuncOptionFact {
    Language(String),
    Volatility(VolatilityKind),
    Security(SecurityKind),
    Strict(StrictKind),
    Leakproof(bool),
    Parallel(String),
    Cost,
    Rows,
    Reset(String),
    As {
        definition: Option<String>,
        obj_file: Option<String>,
        link_symbol: Option<String>,
    },
    Transform,
    Window,
    Support,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum VolatilityKind {
    Immutable,
    Stable,
    Volatile,
}
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum SecurityKind {
    Invoker,
    Definer,
}
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum StrictKind {
    Strict,
    CalledOnNull,
    ReturnsNullOnNull,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterFunctionFact {
    pub name: QualifiedName,
    pub params: Vec<String>,
    pub action: AlterFunctionAction,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterFunctionAction {
    Rename { from: String, to: String },
    OwnerChange(RoleFact),
    SchemaChange { new_schema: String },
    DependsOnExtension { extension: String },
    NoDependsOnExtension { extension: String },
    OptionsChange(Vec<FuncOptionFact>),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropFunctionFact {
    pub signatures: Vec<FunctionSigFact>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct FunctionSigFact {
    pub name: QualifiedName,
    pub params: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateProcedureFact {
    pub name: QualifiedName,
    pub or_replace: bool,
    pub params: Vec<ParamFact>,
    pub options: Vec<FuncOptionFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterProcedureFact {
    pub name: QualifiedName,
    pub params: Vec<String>,
    pub action: AlterFunctionAction,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropProcedureFact {
    pub signatures: Vec<FunctionSigFact>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateAggregateFact {
    pub name: QualifiedName,
    pub or_replace: bool,
    /// Every input parameter in declaration order: ordinary arguments first,
    /// then any `ORDER BY` arguments.
    pub params: Vec<ParamFact>,
    /// `pg_aggregate.aggkind`, decided by an `ORDER BY` clause and the
    /// `HYPOTHETICAL` attribute.
    pub kind: crate::_internal::model::aggregate::AggregateKind,
    /// `pg_aggregate.aggnumdirectargs`: how many of `params` are ordinary
    /// arguments rather than `ORDER BY` inputs.
    pub direct_count: usize,
    /// The `CREATE AGGREGATE` attribute list, which carries the transition
    /// functions, the state type, and the initial condition.
    pub definition: Vec<AggregateOptionFact>,
}

/// One `CREATE AGGREGATE` attribute, as the parser retained it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AggregateOptionFact {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterAggregateFact {
    pub name: QualifiedName,
    pub params: Vec<String>,
    pub action: AlterFunctionAction,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropAggregateFact {
    pub signatures: Vec<FunctionSigFact>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreatePublicationFact {
    pub name: String,
    pub scope: PublicationScope,
    pub params: Vec<AttributeFact>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum PublicationScope {
    AllTables { except: Vec<String> },
    Explicit(Vec<PublicationObjectFact>),
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum PublicationObjectFact {
    Table {
        name: QualifiedName,
        only: bool,
        include_partitions: bool,
        columns: Option<Vec<String>>,
        row_filter: Option<PublicationRowFilter>,
    },
    SchemaTables {
        schema: String,
        row_filter: Option<PublicationRowFilter>,
    },
    CurrentSchemaShorthand,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum PublicationRowFilter {
    Parsed(ExprIr),
    CatalogSql(String),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterPublicationFact {
    pub name: String,
    pub action: AlterPublicationActionFact,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterPublicationActionFact {
    AddObjects(Vec<PublicationObjectFact>),
    SetObjects(PublicationScope),
    DropObjects(Vec<PublicationObjectFact>),
    SetOptions(Vec<AttributeFact>),
    OwnerChange(RoleFact),
    Rename { to: String },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropPublicationFact {
    pub names: Vec<String>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateSubscriptionFact {
    pub name: Option<String>,
    pub connection: ConnectionTarget,
    pub publications: Vec<String>,
    pub params: Option<Vec<AttributeFact>>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum ConnectionTarget {
    Literal(Option<String>),
    Server(Option<String>),
    /// A synchronized subscription exists, but its connection string is never
    /// read from PostgreSQL or written to the cache.
    Redacted,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterSubscriptionFact {
    pub name: String,
    pub action: AlterSubscriptionActionFact,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SubscriptionPublicationMode {
    Set,
    Add,
    Drop,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterSubscriptionActionFact {
    SetConnection(ConnectionTarget),
    Publications {
        mode: SubscriptionPublicationMode,
        publications: Vec<String>,
        params: Vec<AttributeFact>,
    },
    RefreshPublication(Vec<AttributeFact>),
    SetEnabled(bool),
    SetOptions(Vec<AttributeFact>),
    SetServer(Option<String>),
    Skip(Vec<AttributeFact>),
    OwnerChange(RoleFact),
    Rename {
        to: String,
    },
}

impl AlterSubscriptionActionFact {
    /// The subscription options this action carries, whichever form it takes.
    /// Every one of them is gated on name and server version alike.
    pub(crate) fn params(&self) -> Option<&[AttributeFact]> {
        match self {
            Self::Publications { params, .. }
            | Self::RefreshPublication(params)
            | Self::SetOptions(params)
            | Self::Skip(params) => Some(params),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropSubscriptionFact {
    pub name: String,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GrantFact {
    pub privileges: PrivilegeSpec,
    pub target: GrantTarget,
    pub grantees: Vec<RoleFact>,
    pub with_grant_option: bool,
    pub role_options: Vec<RoleMembershipOptionFact>,
    pub granted_by: Option<RoleFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RevokeFact {
    pub grant_option_only: bool,
    pub role_option: Option<RoleMembershipOptionFact>,
    pub privileges: PrivilegeSpec,
    pub target: GrantTarget,
    pub revokees: Vec<RoleFact>,
    pub granted_by: Option<RoleFact>,
    pub cascade: bool,
}

/// Per-membership option supported by PostgreSQL 16+ role grants. The option
/// name and value are kept typed at extraction time so state transitions never
/// need to infer semantics from raw SQL text.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum RoleMembershipOptionFact {
    Admin(bool),
    Inherit(bool),
    Set(bool),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum PrivilegeSpec {
    All,
    List(Vec<PrivilegeFact>),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum PrivilegeFact {
    Select,
    Insert,
    Update,
    Delete,
    Truncate,
    References,
    Trigger,
    Maintain,
    Execute,
    Create,
    Temporary,
    AlterSystem,
    All,
    Named(String),
    RoleMembership(String),
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum GrantTarget {
    Tables(Vec<QualifiedName>),
    AllTablesInSchema(Vec<String>),
    Roles(Vec<String>),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ReindexTargetKindFact {
    Database,
    Schema,
    System,
    Table,
    Index,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateDatabaseFact {
    pub name: String,
    pub options: Vec<DatabaseOptionFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum DatabaseOptionFact {
    Owner(DatabaseOptionValue),
    Template(DatabaseOptionValue),
    Encoding(DatabaseOptionValue),
    Tablespace(DatabaseOptionValue),
    ConnectionLimit(DatabaseOptionValue),
    Named(String, DatabaseOptionValue),
    Unknown(DatabaseOptionValue),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum DatabaseOptionValue {
    Default,
    Literal(Option<String>),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterDatabaseFact {
    pub name: QualifiedName,
    pub action: AlterDatabaseAction,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterDatabaseAction {
    Rename { to: String },
    OwnerChange(RoleFact),
    TablespaceChange { new_tablespace: String },
    SetConfigParam { param: String },
    ResetConfigParam { param: Option<String> },
    RefreshCollationVersion,
    OptionChanges(Vec<DatabaseOptionFact>),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropDatabaseFact {
    pub name: QualifiedName,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct AttributeFact {
    pub name: String,
    /// The value as written and decoded, or `None` when the SQL wrote no value
    /// at all (a bare option, which PostgreSQL reads as `true`). An explicitly
    /// empty string is `Some("")`, kept apart from a missing value.
    pub value: Option<String>,
    /// The option's `namespace.name` namespace, when the SQL spelled one.
    /// Only relation options accept a namespace (`toast.`); PostgreSQL keeps it
    /// separate from the name, so the analyzer does too.
    #[serde(default)]
    pub namespace: Option<String>,
}

impl AttributeFact {
    /// The key PostgreSQL stores the option under: `namespace.name` when
    /// namespaced, otherwise the bare name.
    pub(crate) fn key(&self) -> String {
        match &self.namespace {
            Some(namespace) => format!("{namespace}.{}", self.name),
            None => self.name.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum ColumnGeneration {
    Ordinary,
    Serial,
    IdentityAlways,
    IdentityByDefault,
    GeneratedStored,
    GeneratedVirtual,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct IdentitySequenceOptionsFact {
    pub data_type: Option<String>,
    pub start_value: Option<i64>,
    pub increment: Option<i64>,
    pub min_value: Option<Option<i64>>,
    pub max_value: Option<Option<i64>>,
    pub cache_size: Option<i64>,
    pub cycle: Option<bool>,
    pub persistence: Option<bool>,
    pub sequence_name: Option<QualifiedName>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ColumnFact {
    pub name: String,
    pub ty: Option<String>,
    pub not_null: bool,
    pub is_primary_key: bool,
    pub primary_key_constraint_name: Option<String>,
    pub is_unique: bool,
    pub unique_constraint_name: Option<String>,
    pub default: Option<ExprIr>,
    pub generation: ColumnGeneration,
    pub identity_sequence: Option<IdentitySequenceOptionsFact>,
    pub generated_expr: Option<ExprIr>,
    #[serde(default)]
    pub generated_expr_sql: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SelectOutputFact {
    AllColumns,
    Column {
        source_name: String,
        output_name: String,
    },
}

/// An argument of an unqualified aggregate-named call, typed as far as the
/// visitor can see. `Unknown` matches any overload, like a bare literal.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AggregateArgumentFact {
    /// A bare column reference on the view's source relation.
    Column(String),
    /// A field selection, keeping the base so the resolver can distinguish a
    /// source-qualified column from a field of a composite column.
    Field {
        base: Box<AggregateArgumentFact>,
        field: String,
    },
    Typed(String),
    /// The written argument carries PostgreSQL's `VARIADIC` keyword, so it is
    /// matched against the variadic parameter's array type, not its element.
    Variadic(Box<AggregateArgumentFact>),
    Unknown,
}

/// A clause PostgreSQL accepts only on an aggregate call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AggregateOnlyClauseFact {
    Distinct,
    Filter,
    OrderBy,
    WithinGroup,
}

impl AggregateOnlyClauseFact {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Distinct => "DISTINCT",
            Self::Filter => "FILTER",
            Self::OrderBy => "ORDER BY",
            Self::WithinGroup => "WITHIN GROUP",
        }
    }
}

/// A column reference inside an aggregate argument, with its written
/// qualifier when one was given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AggregateReferenceFact {
    pub qualifier: Option<String>,
    pub name: String,
}

/// One range-variable binding in a nested query's `FROM` clause.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AggregateBindingFact {
    pub alias: String,
    /// The relation named by the binding, or `None` for a subquery or table
    /// function whose columns the visitor cannot see.
    pub relation: Option<QualifiedName>,
}

/// One query level between a nested call and the view's target list.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AggregateScopeFact {
    pub bindings: Vec<AggregateBindingFact>,
    /// A `FROM` item whose columns are unknown, so an unqualified reference
    /// cannot be assumed local.
    pub unknown: bool,
}

/// An unqualified call whose written name is a built-in aggregate. A
/// same-named overload of matching argument types keeps it from being that
/// aggregate, so the resolver places it against the routine search path.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AggregateCandidateFact {
    pub name: String,
    /// The call was written as `pg_catalog.name`, so no search-path routine
    /// can take it back.
    pub explicit: bool,
    /// `count(*)`-style star form, which only an aggregate can accept.
    pub star: bool,
    /// A modifier PostgreSQL accepts only on an aggregate.
    pub aggregate_only_clause: Option<AggregateOnlyClauseFact>,
    pub arguments: Vec<AggregateArgumentFact>,
    /// The `ORDER BY` inputs of a `WITHIN GROUP` call, which PostgreSQL matches
    /// against the aggregate's ordered arguments.
    pub within_group: Vec<AggregateArgumentFact>,
    /// Whether the call sits inside a nested query. A top-level call is always
    /// at the view's own query level.
    pub nested: bool,
    /// Column references in the call arguments, including references under
    /// operators and casts.
    pub references: Vec<AggregateReferenceFact>,
    /// Query levels between a nested call and the view's target list, innermost
    /// first.
    pub scopes: Vec<AggregateScopeFact>,
    /// An argument contains a subquery whose own scope the visitor does not
    /// model.
    pub contains_subquery: bool,
}

impl AggregateCandidateFact {
    pub(crate) fn requires_aggregate(&self) -> bool {
        self.star || self.aggregate_only_clause.is_some()
    }

    pub(crate) fn invalid_call_message(&self) -> String {
        if self.star {
            return format!(
                "{}(*) specified, but {} is not an aggregate function",
                self.name, self.name
            );
        }
        match self.aggregate_only_clause {
            Some(clause) => format!(
                "{} specified, but {} is not an aggregate function",
                clause.label(),
                self.name
            ),
            None => format!("{} is not an aggregate function", self.name),
        }
    }
}

/// Whether PostgreSQL's `view_query_is_auto_updatable(query, true)` would
/// accept a view query, which `check_option` requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ViewUpdatabilityFact {
    /// Every syntactic check passed; the base relation's kind is still
    /// verified against the catalogue before the option is accepted.
    Updatable,
    /// PostgreSQL refuses the option, with this reason as its hint.
    NotUpdatable(crate::_internal::model::relation::ViewUpdatabilityReason),
    /// A target expression the analyzer cannot classify as a scalar function
    /// or an aggregate keeps the answer unknown rather than guessing.
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct FkFact {
    pub constraint_name: Option<String>,
    pub references: QualifiedName,
    pub from_columns: Vec<String>,
    pub to_columns: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum TableConstraintFact {
    PrimaryKey {
        constraint_name: Option<String>,
        columns: Vec<String>,
    },
    Unique {
        constraint_name: Option<String>,
        columns: Vec<String>,
    },
    Check {
        constraint_name: Option<String>,
        name_hint: Option<String>,
        definition: String,
        columns: Vec<String>,
        columns_complete: bool,
    },
    Exclude {
        constraint_name: Option<String>,
        columns: Vec<String>,
        columns_complete: bool,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateDomainFact {
    pub name: QualifiedName,
    pub base_type: String,
    pub collation: Option<WrittenName>,
    pub default: Option<DomainDefaultFact>,
    pub constraints: Vec<DomainConstraintFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DomainDefaultFact {
    pub expression: ExprIr,
    pub text: String,
    /// PostgreSQL folds a bare `NULL` (including casts of it) into "no
    /// default", so the fact keeps that distinction out of the expression.
    pub is_null: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DomainCheckFact {
    pub name: Option<String>,
    pub expression: ExprIr,
    pub expression_text: String,
    pub definition: String,
    pub not_valid: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum DomainConstraintFact {
    Check(DomainCheckFact),
    NotNull { name: Option<String> },
    Null,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterDomainActionFact {
    AddConstraint(DomainConstraintFact),
    DropConstraint {
        name: String,
        if_exists: bool,
        cascade: bool,
    },
    DropDefault,
    DropNotNull,
    OwnerChange(RoleFact),
    RenameConstraint {
        old_name: String,
        new_name: String,
    },
    RenameTo {
        new_name: Ident,
    },
    SetDefault(DomainDefaultFact),
    SetNotNull,
    SetSchema {
        new_schema: String,
    },
    ValidateConstraint {
        name: String,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterTableActionFact {
    AddColumn {
        name: String,
        ty: Option<String>,
        if_not_exists: bool,
        not_null: bool,
        default: Option<ExprIr>,
        generation: ColumnGeneration,
        identity_sequence: Option<Box<IdentitySequenceOptionsFact>>,
        generated_expr: Option<ExprIr>,
        generated_expr_sql: Option<String>,
    },
    DropColumn {
        name: String,
        if_exists: bool,
        cascade: bool,
    },
    RenameColumn {
        from: Ident,
        to: Ident,
    },
    RenameTo {
        new_name: Ident,
    },
    AddForeignKey {
        constraint_name: Option<String>,
        references: QualifiedName,
        from_columns: Vec<String>,
        to_columns: Vec<String>,
        not_valid: bool,
    },
    AlterConstraint {
        name: Option<String>,
        deferrable: bool,
    },
    RenameConstraint {
        old_name: String,
        new_name: String,
    },
    DropConstraint {
        name: String,
        if_exists: bool,
        cascade: bool,
    },
    AddCheckConstraint {
        constraint_name: Option<String>,
        definition: String,
        columns: Vec<String>,
        columns_complete: bool,
        not_valid: bool,
    },
    AddUniqueConstraint {
        constraint_name: Option<String>,
        columns: Vec<String>,
        using_index: Option<QualifiedName>,
    },
    AddPrimaryKeyConstraint {
        constraint_name: Option<String>,
        columns: Vec<String>,
        using_index: Option<QualifiedName>,
    },
    AddExcludeConstraint {
        constraint_name: Option<String>,
        columns: Vec<String>,
        columns_complete: bool,
    },
    SetNotNull {
        column: String,
    },
    DropNotNull {
        column: String,
    },
    SetType {
        column: String,
        ty: String,
        has_using: bool,
    },
    SetDefault {
        column: String,
        default: Option<ExprIr>,
    },
    SetExpression {
        column: String,
        expr: ExprIr,
        expression_sql: String,
    },
    SetOptions {
        column: String,
        attributes: Vec<AttributeFact>,
    },
    ResetOptions {
        column: String,
        attributes: Vec<AttributeFact>,
    },
    SetTableOptions {
        attributes: Vec<AttributeFact>,
    },
    ResetTableOptions {
        attributes: Vec<AttributeFact>,
    },
    Inherit {
        column: String,
        parent: QualifiedName,
    },
    NoInherit {
        column: String,
        parent: QualifiedName,
    },
    ValidateConstraint {
        constraint_name: String,
    },
    DisableTrigger {
        trigger_name: Option<String>,
    },
    EnableTrigger {
        trigger_name: Option<String>,
    },
    AttachPartition {
        child: QualifiedName,
        strategy: Option<String>,
        bound: Option<String>,
    },
    DetachPartition {
        child: QualifiedName,
        mode: DetachPartitionMode,
    },
    SetStorage {
        column: String,
        mode: String,
    },
    SetCompression {
        column: String,
        method: Option<String>,
    },
    SetStatistics {
        column: String,
        target: Option<i32>,
    },
    DropExpression {
        column: String,
        if_exists: bool,
    },
    SetAccessMethod {
        access_method: Option<String>,
    },
    ClusterOn {
        index: QualifiedName,
    },
    SetWithoutCluster,
    InheritTable {
        parent: QualifiedName,
    },
    NoInheritTable {
        parent: QualifiedName,
    },
    OfType {
        type_name: QualifiedName,
    },
    NotOf,
    MergePartitions {
        parent: QualifiedName,
    },
    SplitPartition,
    SetSchema {
        new_schema: String,
    },
    SetTablespace {
        tablespace: String,
    },
    SetLogged,
    SetUnlogged,
    OwnerTo {
        new_owner: RoleFact,
    },
    ReplicaIdentity {
        option: ReplicaIdentityFact,
    },
    ForceRls,
    NoForceRls,
    EnableRls,
    DisableRls,
    EnableAlwaysTrigger {
        trigger_name: Option<String>,
    },
    EnableReplicaTrigger {
        trigger_name: Option<String>,
    },
    SetRuleMode {
        rule_name: Option<String>,
        mode: RuleEnableModeFact,
    },
}
