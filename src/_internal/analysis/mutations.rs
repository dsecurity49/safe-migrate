use crate::_internal::analysis::expr_ir::ExprIr;
use crate::_internal::analysis::facts::{
    LockModeFact, ResetSettingTarget, SearchPathTarget, TableConstraintFact, TimeoutSetting,
    TimeoutSettingValue,
};
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::types::TypeKind;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum PersistenceMutation {
    Permanent,
    Temporary,
    Unlogged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OnCommitMutation {
    PreserveRows,
    DeleteRows,
    Drop,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ReplicaIdentityMutation {
    Default,
    Full,
    Nothing,
    UsingIndex(ObjectId),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Mutation {
    CreateSchema(CreateSchemaMutation),
    AlterSchema(AlterSchemaMutation),
    DropSchema(DropSchemaMutation),
    CreateTable(CreateTable),
    CreateView(CreateView),
    CreateMaterializedView(CreateMaterializedView),
    RefreshMaterializedView(RefreshMaterializedViewMutation),
    CreateIndex(CreateIndex),
    CreatePolicy(CreatePolicyMutation),
    DropPolicy(DropPolicyMutation),
    CreateTrigger(CreateTriggerMutation),
    DropTrigger(DropTriggerMutation),
    RenameTrigger(RenameTriggerMutation),
    AlterTable(AlterTable),
    CreateType(CreateTypeMutation),
    AlterType(AlterTypeMutation),
    RenameType(Rename),
    CreateDomain(CreateDomainMutation),
    AlterDomain(AlterDomainMutation),
    DropDomain(DropDomainMutation),
    DropType(DropTypeMutation),
    CreateSequence(CreateSequenceMutation),
    AlterSequence(AlterSequenceMutation),
    DropSequence(DropSequenceMutation),
    Rename(Rename),
    DropTable(DropTable),
    DropView(DropViewMutation),
    DropMaterializedView(DropMaterializedViewMutation),
    DropIndex(DropIndex),
    LockTable(LockTableMutation),
    Truncate(TruncateMutation),
    ChangeRelationOwner {
        id: ObjectId,
        new_owner: crate::_internal::analysis::facts::RoleFact,
    },
    SearchPath(SearchPathChange),
    TimeoutSetting(TimeoutSettingChange),
    ResetSettings(ResetSettingTarget),
    /// Statement-scoped no-op evaluated after real mutations so timeout
    /// rules do not report on statements PostgreSQL would not execute.
    CheckTimeouts,
    BeginTransaction,
    CommitTransaction,
    CommitAndChain,
    RollbackTransaction,
    RollbackAndChain,
    RollbackToSavepoint(RollbackToSavepointMutation),
    Savepoint(SavepointMutation),
    ReleaseSavepoint(ReleaseSavepointMutation),
    CreateFunction(CreateFunctionMutation),
    AlterFunction(AlterFunctionMutation),
    DropFunction(DropFunctionMutation),
    CreateProcedure(CreateProcedureMutation),
    AlterProcedure(AlterProcedureMutation),
    DropProcedure(DropProcedureMutation),
    CreateAggregate(CreateAggregateMutation),
    AlterAggregate(AlterAggregateMutation),
    DropAggregate(DropAggregateMutation),
    CreatePublication(CreatePublicationMutation),
    AlterPublication(AlterPublicationMutation),
    DropPublication(DropPublicationMutation),
    CreateSubscription(CreateSubscriptionMutation),
    AlterSubscription(AlterSubscriptionMutation),
    DropSubscription(DropSubscriptionMutation),
    CreateRole(CreateRoleMutation),
    AlterRole(AlterRoleMutation),
    DropRole(DropRoleMutation),
    Grant(GrantMutation),
    Revoke(RevokeMutation),
    CreateDatabase(CreateDatabaseMutation),
    AlterDatabase(AlterDatabaseMutation),
    DropDatabase(DropDatabaseMutation),
    /// Produced by `SET [LOCAL] ROLE` and `SET [LOCAL] SESSION AUTHORIZATION`.
    /// `role = None` means ROLE NONE / SESSION AUTHORIZATION DEFAULT.
    /// `local = true` means the active value expires at transaction end.
    SwitchRole {
        role: Option<crate::_internal::analysis::facts::RoleFact>,
        local: bool,
        is_session_auth: bool,
    },
    Opaque(OpaqueMutation),
    Vacuum {
        table_id: Option<ObjectId>,
        is_full: bool,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RelationTargetMutation {
    pub id: ObjectId,
    pub only: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LockTableMutation {
    pub targets: Vec<RelationTargetMutation>,
    pub mode: LockModeFact,
    pub nowait: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct TruncateMutation {
    pub targets: Vec<RelationTargetMutation>,
    pub cascade: bool,
    pub restart_identity: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateSchemaMutation {
    pub name: String,
    pub if_not_exists: bool,
    pub authorization: Option<crate::_internal::analysis::facts::RoleFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterSchemaMutation {
    Rename {
        old_name: String,
        new_name: String,
    },
    OwnerTo {
        name: String,
        new_owner: crate::_internal::analysis::facts::RoleFact,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropSchemaMutation {
    pub names: Vec<String>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreatePolicyMutation {
    pub name: String,
    pub table: ObjectId,
    pub permissive: bool,
    pub command: crate::_internal::analysis::facts::PolicyCommand,
    pub semantics_complete: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropPolicyMutation {
    pub name: String,
    pub table: ObjectId,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateTriggerMutation {
    pub name: String,
    pub table: ObjectId,
    pub function_id: ObjectId,
    pub row_level: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropTriggerMutation {
    pub name: String,
    pub table: ObjectId,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RenameTriggerMutation {
    pub name: String,
    pub table: ObjectId,
    pub new_name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropViewMutation {
    pub ids: Vec<ObjectId>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropMaterializedViewMutation {
    pub ids: Vec<ObjectId>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateMaterializedView {
    pub id: ObjectId,
    pub depends_on: Vec<ObjectId>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RefreshMaterializedViewMutation {
    pub id: ObjectId,
    pub concurrently: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateSequenceMutation {
    pub id: ObjectId,
    pub if_not_exists: bool,
    pub owned_by: Option<(ObjectId, String)>,
    pub persistence: crate::_internal::model::sequence::SequencePersistence,
    pub options: IdentitySequenceOptionsMutation,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterSequenceMutation {
    pub id: ObjectId,
    pub if_exists: bool,
    pub action: AlterSequenceActionMutation,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterSequenceActionMutation {
    OwnedBy(Option<(ObjectId, String)>),
    OwnerTo(crate::_internal::analysis::facts::RoleFact),
    RenameTo(ObjectId),
    SetSchema(ObjectId),
    Other,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropSequenceMutation {
    pub ids: Vec<ObjectId>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateDomainMutation {
    pub id: ObjectId,
    pub base_type: String,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterDomainMutation {
    pub id: ObjectId,
    pub action: Option<crate::_internal::analysis::facts::AlterDomainActionFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropDomainMutation {
    pub ids: Vec<ObjectId>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropTypeMutation {
    pub ids: Vec<ObjectId>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateTypeMutation {
    pub id: ObjectId,
    pub kind: TypeKind,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterTypeMutation {
    pub id: ObjectId,
    pub action: AlterTypeActionMutation,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterTypeActionMutation {
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
pub(crate) struct CreateTable {
    pub id: ObjectId,
    pub if_not_exists: bool,
    pub as_select: bool,
    pub as_select_columns_known: bool,
    pub persistence: PersistenceMutation,
    pub on_commit: Option<OnCommitMutation>,
    pub columns: Vec<ColumnMutation>,
    pub foreign_keys: Vec<FkMutation>,
    pub table_constraints: Vec<TableConstraintFact>,
    pub partition_by: Option<String>,
    pub partition_strategy: Option<String>,
    pub partition_of: Option<ObjectId>,
    pub partition_bound: Option<String>,
    pub inherits: Vec<ObjectId>,
    /// Source tables and the supported column-property selection for `LIKE`.
    /// Object-producing options (constraints, indexes, and identity) remain
    /// rejected until their complete lifecycles are represented.
    pub like_sources: Vec<LikeSourceMutation>,
    pub of_type: Option<ObjectId>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LikeSourceMutation {
    pub relation: ObjectId,
    pub properties: crate::_internal::analysis::facts::LikePropertiesFact,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ColumnMutation {
    pub name: String,
    pub ty: Option<String>,
    pub type_modifier: Option<i32>,
    pub not_null: bool,
    pub is_primary_key: bool,
    pub primary_key_constraint_name: Option<String>,
    pub is_unique: bool,
    pub unique_constraint_name: Option<String>,
    pub default: Option<ExprIr>,
    pub generation: crate::_internal::analysis::facts::ColumnGeneration,
    pub identity_sequence: Option<IdentitySequenceOptionsMutation>,
    pub generated_expr: Option<ExprIr>,
    pub generated_expr_sql: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct IdentitySequenceOptionsMutation {
    pub data_type: Option<String>,
    pub start_value: Option<i64>,
    pub increment: Option<i64>,
    pub min_value: Option<Option<i64>>,
    pub max_value: Option<Option<i64>>,
    pub cache_size: Option<i64>,
    pub cycle: Option<bool>,
    pub persistence: Option<bool>,
    pub sequence_name: Option<ObjectId>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct FkMutation {
    pub constraint_name: Option<String>,
    pub to_table: ObjectId,
    pub from_columns: Vec<String>,
    pub to_columns: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateView {
    pub id: ObjectId,
    pub or_replace: bool,
    pub depends_on: Vec<ObjectId>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateIndex {
    pub id: ObjectId,
    pub table: ObjectId,
    pub if_not_exists: bool,
    pub concurrently: bool,
    pub using_method: Option<String>,
    pub has_predicate: bool,
    pub unique: bool,
    pub key_columns: Vec<String>,
    pub included_columns: Vec<String>,
    pub has_expression_keys: bool,
    pub has_default_sort_order: bool,
    pub has_default_opclasses: bool,
    pub has_default_collations: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterTable {
    pub id: ObjectId,
    pub only: bool,
    pub action: AlterTableActionMutation,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Rename {
    pub old_id: ObjectId,
    pub new_id: ObjectId,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropTable {
    pub ids: Vec<ObjectId>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropIndex {
    pub ids: Vec<ObjectId>,
    pub if_exists: bool,
    pub concurrently: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SearchPathChange {
    pub target: SearchPathTarget,
    pub local: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct TimeoutSettingChange {
    pub setting: TimeoutSetting,
    pub value: TimeoutSettingValue,
    pub local: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SavepointMutation {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ReleaseSavepointMutation {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RollbackToSavepointMutation {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateFunctionMutation {
    pub id: ObjectId,
    pub or_replace: bool,
    pub params: Vec<crate::_internal::analysis::facts::ParamFact>,
    pub return_type: Option<crate::_internal::analysis::facts::RetTypeFact>,
    pub options: Vec<crate::_internal::analysis::facts::FuncOptionFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterFunctionMutation {
    pub id: ObjectId,
    pub action: crate::_internal::analysis::facts::AlterFunctionAction,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropFunctionMutation {
    pub signatures: Vec<crate::_internal::analysis::facts::FunctionSigFact>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateProcedureMutation {
    pub id: ObjectId,
    pub or_replace: bool,
    pub params: Vec<crate::_internal::analysis::facts::ParamFact>,
    pub options: Vec<crate::_internal::analysis::facts::FuncOptionFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterProcedureMutation {
    pub id: ObjectId,
    pub action: crate::_internal::analysis::facts::AlterFunctionAction,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropProcedureMutation {
    pub signatures: Vec<crate::_internal::analysis::facts::FunctionSigFact>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateAggregateMutation {
    pub id: ObjectId,
    pub or_replace: bool,
    pub params: Vec<crate::_internal::analysis::facts::ParamFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterAggregateMutation {
    pub id: ObjectId,
    pub action: crate::_internal::analysis::facts::AlterFunctionAction,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropAggregateMutation {
    pub signatures: Vec<crate::_internal::analysis::facts::FunctionSigFact>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreatePublicationMutation {
    pub name: String,
    pub scope: crate::_internal::analysis::facts::PublicationScope,
    pub params: Vec<crate::_internal::analysis::facts::AttributeFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterPublicationMutation {
    pub name: String,
    pub action: crate::_internal::analysis::facts::AlterPublicationActionFact,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropPublicationMutation {
    pub names: Vec<String>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateSubscriptionMutation {
    pub name: Option<String>,
    pub connection: crate::_internal::analysis::facts::ConnectionTarget,
    pub publications: Vec<String>,
    pub params: Option<Vec<crate::_internal::analysis::facts::AttributeFact>>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterSubscriptionMutation {
    pub name: String,
    pub action: crate::_internal::analysis::facts::AlterSubscriptionActionFact,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropSubscriptionMutation {
    pub name: String,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateRoleMutation {
    pub name: String,
    pub inherits: bool,
    pub can_login: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterRoleMutation {
    pub name: crate::_internal::analysis::facts::RoleFact,
    pub inherits: Option<bool>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropRoleMutation {
    pub names: Vec<String>,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ResolvedGrantTarget {
    Tables(Vec<ObjectId>),
    AllTablesInSchema(Vec<String>),
    Roles(Vec<ObjectId>),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GrantMutation {
    pub privileges: crate::_internal::analysis::facts::PrivilegeSpec,
    pub target: ResolvedGrantTarget,
    pub grantees: Vec<crate::_internal::analysis::facts::RoleFact>,
    pub with_grant_option: bool,
    pub role_options: Vec<crate::_internal::analysis::facts::RoleMembershipOptionFact>,
    pub granted_by: Option<crate::_internal::analysis::facts::RoleFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RevokeMutation {
    pub grant_option_only: bool,
    pub role_option: Option<crate::_internal::analysis::facts::RoleMembershipOptionFact>,
    pub privileges: crate::_internal::analysis::facts::PrivilegeSpec,
    pub target: ResolvedGrantTarget,
    pub revokees: Vec<crate::_internal::analysis::facts::RoleFact>,
    pub granted_by: Option<crate::_internal::analysis::facts::RoleFact>,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CreateDatabaseMutation {
    pub name: String,
    pub options: Vec<crate::_internal::analysis::facts::DatabaseOptionFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AlterDatabaseMutation {
    pub id: ObjectId,
    pub action: crate::_internal::analysis::facts::AlterDatabaseAction,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DropDatabaseMutation {
    pub id: ObjectId,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum OpaqueMutation {
    /// Squawk accepted the statement but safe-migrate has no typed extractor
    /// for it. Treating it as a no-op would leave later analysis falsely exact.
    UnsupportedStatement,
    DoBlock,
    Execute,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "reserved for dynamic SQL extracted from procedural bodies"
        )
    )]
    DynamicSql,
    PrepareTransaction,
    SetTransaction,
    SetConstraints,
    #[expect(dead_code, reason = "reserved for opaque resolver collisions")]
    StateCollision(String),
    #[expect(dead_code, reason = "reserved for unresolved typed references")]
    UnresolvedReference {
        object_kind: crate::_internal::report::violations::ObjectKind,
        object_name: String,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlterTableActionMutation {
    AddColumn {
        name: String,
        ty: Option<String>,
        if_not_exists: bool,
        not_null: bool,
        default: Option<ExprIr>,
        depends_on: Option<(ObjectId, String)>,
        generation: crate::_internal::analysis::facts::ColumnGeneration,
        identity_sequence: Option<IdentitySequenceOptionsMutation>,
        generated_expr: Option<ExprIr>,
        generated_expr_sql: Option<String>,
    },
    DropColumn {
        name: String,
        if_exists: bool,
        cascade: bool,
    },
    RenameColumn {
        from: String,
        to: String,
    },
    AddForeignKey {
        constraint_name: Option<String>,
        to_table: ObjectId,
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
        using_index: Option<ObjectId>,
    },
    AddPrimaryKeyConstraint {
        constraint_name: Option<String>,
        columns: Vec<String>,
        using_index: Option<ObjectId>,
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
    SetGeneratedExpression {
        column: String,
        expr: ExprIr,
        expression_sql: String,
    },
    SetColumnOptions {
        column: String,
        attributes: Vec<crate::_internal::analysis::facts::AttributeFact>,
    },
    ResetColumnOptions {
        column: String,
        names: Vec<String>,
    },
    SetTableOptions {
        attributes: Vec<crate::_internal::analysis::facts::AttributeFact>,
    },
    ResetTableOptions {
        names: Vec<String>,
    },
    AlterColumnInheritance,
    PartitionReshape,
    ValidateConstraint {
        constraint_name: String,
    },
    DisableTrigger {
        trigger_name: Option<String>,
    },
    EnableTrigger {
        trigger_name: Option<String>,
    },
    SetTriggerMode {
        trigger_name: Option<String>,
        mode: crate::_internal::model::trigger::TriggerEnableMode,
    },
    AttachPartition {
        child: ObjectId,
        strategy: Option<String>,
        bound: Option<String>,
    },
    DetachPartition {
        child: ObjectId,
        mode: crate::_internal::analysis::facts::DetachPartitionMode,
    },
    InheritTable {
        parent: ObjectId,
    },
    NoInheritTable {
        parent: ObjectId,
    },
    SetOfType {
        type_id: Option<ObjectId>,
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
    DropGeneratedExpression {
        column: String,
        if_exists: bool,
    },
    SetAccessMethod {
        access_method: Option<String>,
    },
    SetTablespace {
        tablespace: String,
    },
    SetPersistence {
        persistence: crate::_internal::model::relation::Persistence,
    },
    SetCluster {
        index: Option<ObjectId>,
    },
    SetRowSecurity {
        enabled: bool,
    },
    SetForceRowSecurity {
        enabled: bool,
    },
    SetReplicaIdentity {
        option: ReplicaIdentityMutation,
    },
    SetRuleMode {
        rule_name: Option<String>,
        mode: crate::_internal::model::relation::RuleEnableMode,
    },
    OwnerTo {
        new_owner: crate::_internal::analysis::facts::RoleFact,
    },
}
