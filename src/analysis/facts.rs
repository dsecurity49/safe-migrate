// FILE: src/analysis/facts.rs
use crate::analysis::expr_ir::ExprIr;
use crate::ast::identifiers::{Ident, QualifiedName};

#[derive(Clone, Debug, PartialEq)]
pub enum PersistenceFact {
    Permanent,
    Temporary,
    Unlogged,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PolicyCommand {
    All,
    Select,
    Insert,
    Update,
    Delete,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SearchPathTarget {
    Default,
    Schemas(Vec<String>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum TypeCreationKind {
    Enum { variants: Vec<String> },
    Range,
    Composite,
    Base,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AlterViewAction {
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
        options: Vec<String>,
    },
    ResetOptions {
        options: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum StatementFact {
    CreateSchema {
        name: QualifiedName,
        if_not_exists: bool,
    },
    AlterSchema {
        name: QualifiedName,
        new_name: Option<Ident>,
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
        columns: Vec<ColumnFact>,
        foreign_keys: Vec<FkFact>,
        table_constraints: Vec<TableConstraintFact>,
        partition_by: Option<String>,
        partition_of: Option<QualifiedName>,
        partition_type: Option<String>,
    },
    CreateView {
        name: QualifiedName,
        or_replace: bool,
        depends_on: Vec<QualifiedName>,
    },
    AlterView {
        name: QualifiedName,
        action: AlterViewAction,
    },
    CreateMaterializedView {
        name: QualifiedName,
        depends_on: Vec<QualifiedName>,
    },
    AlterMaterializedView {
        name: QualifiedName,
        new_name: Option<Ident>,
    },
    RefreshMaterializedView {
        name: QualifiedName,
        concurrently: bool,
    },
    CreateIndex {
        name: QualifiedName,
        relation: QualifiedName,
        if_not_exists: bool,
        concurrently: bool,
        using_method: Option<String>,
        has_predicate: bool,
        unique: bool, // Added for CreateIndexFact
    },
    CreatePolicy {
        name: String,
        table: QualifiedName,
        permissive: bool,
        command: PolicyCommand,
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
    },
    DropTrigger {
        name: String,
        table: QualifiedName,
        if_exists: bool,
    },
    AlterTable {
        name: QualifiedName,
        actions: Vec<AlterTableActionFact>,
    },
    AlterIndex {
        name: QualifiedName,
        actions: Vec<AlterIndexActionFact>,
    },
    CreateType(CreateTypeFact),
    AlterType(AlterTypeFact),
    CreateDomain {
        name: QualifiedName,
        base_type: String,
    },
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
    },
    AlterSequence {
        name: QualifiedName,
        owned_by: Option<(QualifiedName, String)>,
    },
    DropSequence {
        names: Vec<QualifiedName>,
        if_exists: bool,
        cascade: bool,
    },
    DropTable {
        name: QualifiedName,
        if_exists: bool,
        cascade: bool,
    },
    DropView {
        name: QualifiedName,
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
    },
    SetSearchPath {
        target: SearchPathTarget,
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

#[derive(Clone, Debug, PartialEq)]
pub enum AlterIndexActionFact {
    RenameTo { new_name: Ident },
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateTypeFact {
    pub name: QualifiedName,
    pub kind: TypeCreationKind,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterTypeFact {
    pub name: QualifiedName,
    pub actions: Vec<AlterTypeActionFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AlterTypeActionFact {
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

#[derive(Clone, Debug, PartialEq, Default)]
pub enum RoleFact {
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
pub struct CreateRoleFact {
    pub name: String,
    pub inherits: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterRoleFact {
    pub name: RoleFact,
    pub inherits: Option<bool>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropRoleFact {
    pub names: Vec<String>,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateFunctionFact {
    pub name: QualifiedName,
    pub or_replace: bool,
    pub params: Vec<ParamFact>,
    pub return_type: Option<RetTypeFact>,
    pub options: Vec<FuncOptionFact>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ParamFact {
    pub mode: ParamModeFact,
    pub name: Option<String>,
    pub ty: String,
    pub default: Option<ExprIr>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ParamModeFact {
    In,
    Out,
    InOut,
    Variadic,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum RetTypeFact {
    Table(Vec<ColumnFact>),
    Scalar(String),
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum FuncOptionFact {
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
pub enum VolatilityKind {
    Immutable,
    Stable,
    Volatile,
}
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SecurityKind {
    Invoker,
    Definer,
}
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum StrictKind {
    Strict,
    CalledOnNull,
    ReturnsNullOnNull,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterFunctionFact {
    pub name: QualifiedName,
    pub params: Vec<String>,
    pub action: AlterFunctionAction,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AlterFunctionAction {
    Rename { from: String, to: String },
    OwnerChange(RoleFact),
    SchemaChange { new_schema: String },
    DependsOnExtension { extension: String },
    NoDependsOnExtension { extension: String },
    OptionsChange(Vec<FuncOptionFact>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropFunctionFact {
    pub signatures: Vec<FunctionSigFact>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FunctionSigFact {
    pub name: QualifiedName,
    pub params: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateProcedureFact {
    pub name: QualifiedName,
    pub or_replace: bool,
    pub params: Vec<ParamFact>,
    pub options: Vec<FuncOptionFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterProcedureFact {
    pub name: QualifiedName,
    pub params: Vec<String>,
    pub action: AlterFunctionAction,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropProcedureFact {
    pub signatures: Vec<FunctionSigFact>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreatePublicationFact {
    pub name: String,
    pub scope: PublicationScope,
    pub params: Vec<AttributeFact>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum PublicationScope {
    AllTables { except: Vec<String> },
    Explicit(Vec<PublicationObjectFact>),
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum PublicationObjectFact {
    Table {
        name: QualifiedName,
        only: bool,
        include_partitions: bool,
        columns: Option<Vec<String>>,
        row_filter: Option<ExprIr>,
    },
    SchemaTables {
        schema: String,
        row_filter: Option<ExprIr>,
    },
    CurrentSchemaShorthand,
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterPublicationFact {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropPublicationFact {
    pub names: Vec<String>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateSubscriptionFact {
    pub name: Option<String>,
    pub connection: ConnectionTarget,
    pub publications: Vec<String>,
    pub params: Option<Vec<AttributeFact>>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ConnectionTarget {
    Literal(Option<String>),
    Server(Option<String>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterSubscriptionFact {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropSubscriptionFact {
    pub name: String,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GrantFact {
    pub privileges: PrivilegeSpec,
    pub target: GrantTarget,
    pub grantees: Vec<RoleFact>,
    pub with_grant_option: bool,
    pub granted_by: Option<RoleFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RevokeFact {
    pub grant_option_only: bool,
    pub privileges: PrivilegeSpec,
    pub target: GrantTarget,
    pub revokees: Vec<RoleFact>,
    pub granted_by: Option<RoleFact>,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PrivilegeSpec {
    All,
    List(Vec<PrivilegeFact>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum PrivilegeFact {
    Select,
    Insert,
    Update,
    Delete,
    Truncate,
    References,
    Trigger,
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
pub enum GrantTarget {
    Tables(Vec<QualifiedName>),
    AllTablesInSchema(Vec<String>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateDatabaseFact {
    pub name: String,
    pub options: Vec<DatabaseOptionFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DatabaseOptionFact {
    Owner(DatabaseOptionValue),
    Template(DatabaseOptionValue),
    Encoding(DatabaseOptionValue),
    Tablespace(DatabaseOptionValue),
    ConnectionLimit(DatabaseOptionValue),
    Named(String, DatabaseOptionValue),
    Unknown(DatabaseOptionValue),
}

#[derive(Clone, Debug, PartialEq)]
pub enum DatabaseOptionValue {
    Default,
    Literal(Option<String>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterDatabaseFact {
    pub name: QualifiedName,
    pub action: AlterDatabaseAction,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AlterDatabaseAction {
    Rename { to: String },
    OwnerChange(RoleFact),
    TablespaceChange { new_tablespace: String },
    SetConfigParam { param: String },
    ResetConfigParam { param: Option<String> },
    RefreshCollationVersion,
    OptionChanges(Vec<DatabaseOptionFact>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropDatabaseFact {
    pub name: QualifiedName,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AttributeFact {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ColumnFact {
    pub name: String,
    pub ty: Option<String>,
    pub not_null: bool,
    pub is_primary_key: bool,
    pub primary_key_constraint_name: Option<String>,
    pub is_unique: bool,
    pub unique_constraint_name: Option<String>,
    pub default: Option<ExprIr>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FkFact {
    pub constraint_name: Option<String>,
    pub references: QualifiedName,
    pub from_columns: Vec<String>,
    pub to_columns: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TableConstraintFact {
    PrimaryKey {
        constraint_name: Option<String>,
        columns: Vec<String>,
    },
    Unique {
        constraint_name: Option<String>,
        columns: Vec<String>,
    },
    Check,
    Exclude,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AlterDomainActionFact {
    AddConstraint,
    DropConstraint,
    DropDefault,
    DropNotNull,
    OwnerChange,
    RenameConstraint,
    RenameTo,
    SetDefault,
    SetNotNull,
    SetSchema,
    ValidateConstraint,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AlterTableActionFact {
    AddColumn {
        name: String,
        ty: Option<String>,
        if_not_exists: bool,
        not_null: bool,
        default: Option<ExprIr>,
    },
    DropColumn {
        name: String,
        if_exists: bool,
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
    },
    AddCheckConstraint {
        constraint_name: Option<String>,
        not_valid: bool,
    },
    AddUniqueConstraint {
        constraint_name: Option<String>,
        using_index: Option<QualifiedName>,
    },
    AddPrimaryKeyConstraint {
        constraint_name: Option<String>,
        using_index: Option<QualifiedName>,
    },
    AddExcludeConstraint {
        constraint_name: Option<String>,
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
    },
    SetOptions {
        column: String,
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
    },
    DetachPartition {
        child: QualifiedName,
    },
    SetStorage {
        column: String,
    },
    SetAccessMethod,
    ClusterOn {
        index: String,
    },
    InheritTable {
        parent: QualifiedName,
    },
    NoInheritTable {
        parent: QualifiedName,
    },
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
        option: String,
    },
    ForceRls,
    EnableRls,
    DisableRls,
    EnableAlwaysTrigger {
        trigger_name: Option<String>,
    },
    EnableReplicaTrigger {
        trigger_name: Option<String>,
    },
}
