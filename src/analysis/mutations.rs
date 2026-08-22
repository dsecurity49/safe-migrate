use crate::analysis::expr_ir::ExprIr;
use crate::analysis::facts::{
    ResetSettingTarget, SearchPathTarget, TableConstraintFact, TimeoutSetting, TimeoutSettingValue,
};
use crate::ast::identifiers::ObjectId;
use crate::model::types::TypeKind;

#[derive(Clone, Debug, PartialEq)]
pub enum PersistenceMutation {
    Permanent,
    Temporary,
    Unlogged,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Mutation {
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
    ChangeRelationOwner {
        id: ObjectId,
        new_owner: crate::analysis::facts::RoleFact,
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
        role: Option<crate::analysis::facts::RoleFact>,
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
pub struct CreateSchemaMutation {
    pub name: String,
    pub if_not_exists: bool,
    pub authorization: Option<crate::analysis::facts::RoleFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AlterSchemaMutation {
    Rename {
        old_name: String,
        new_name: String,
    },
    OwnerTo {
        name: String,
        new_owner: crate::analysis::facts::RoleFact,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropSchemaMutation {
    pub names: Vec<String>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreatePolicyMutation {
    pub name: String,
    pub table: ObjectId,
    pub permissive: bool,
    pub command: crate::analysis::facts::PolicyCommand,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropPolicyMutation {
    pub name: String,
    pub table: ObjectId,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateTriggerMutation {
    pub name: String,
    pub table: ObjectId,
    pub function_id: ObjectId,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropTriggerMutation {
    pub name: String,
    pub table: ObjectId,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RenameTriggerMutation {
    pub name: String,
    pub table: ObjectId,
    pub new_name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropViewMutation {
    pub ids: Vec<ObjectId>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropMaterializedViewMutation {
    pub ids: Vec<ObjectId>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateMaterializedView {
    pub id: ObjectId,
    pub depends_on: Vec<ObjectId>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RefreshMaterializedViewMutation {
    pub id: ObjectId,
    pub concurrently: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateSequenceMutation {
    pub id: ObjectId,
    pub if_not_exists: bool,
    pub owned_by: Option<(ObjectId, String)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterSequenceMutation {
    pub id: ObjectId,
    pub if_exists: bool,
    pub action: AlterSequenceActionMutation,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AlterSequenceActionMutation {
    OwnedBy(Option<(ObjectId, String)>),
    OwnerTo(crate::analysis::facts::RoleFact),
    RenameTo(ObjectId),
    SetSchema(ObjectId),
    Other,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropSequenceMutation {
    pub ids: Vec<ObjectId>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateDomainMutation {
    pub id: ObjectId,
    pub base_type: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterDomainMutation {
    pub id: ObjectId,
    pub action: Option<crate::analysis::facts::AlterDomainActionFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropDomainMutation {
    pub ids: Vec<ObjectId>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropTypeMutation {
    pub ids: Vec<ObjectId>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateTypeMutation {
    pub id: ObjectId,
    pub kind: TypeKind,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterTypeMutation {
    pub id: ObjectId,
    pub action: AlterTypeActionMutation,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AlterTypeActionMutation {
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
pub struct CreateTable {
    pub id: ObjectId,
    pub if_not_exists: bool,
    pub as_select: bool,
    pub persistence: PersistenceMutation,
    pub columns: Vec<ColumnMutation>,
    pub foreign_keys: Vec<FkMutation>,
    pub table_constraints: Vec<TableConstraintFact>,
    pub partition_by: Option<String>,
    pub partition_of: Option<ObjectId>,
    pub partition_type: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ColumnMutation {
    pub name: String,
    pub ty: Option<String>,
    pub not_null: bool,
    pub is_primary_key: bool,
    pub primary_key_constraint_name: Option<String>,
    pub is_unique: bool,
    pub unique_constraint_name: Option<String>,
    pub default: Option<ExprIr>,
    pub generation: crate::analysis::facts::ColumnGeneration,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FkMutation {
    pub constraint_name: Option<String>,
    pub to_table: ObjectId,
    pub from_columns: Vec<String>,
    pub to_columns: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateView {
    pub id: ObjectId,
    pub or_replace: bool,
    pub depends_on: Vec<ObjectId>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateIndex {
    pub id: ObjectId,
    pub table: ObjectId,
    pub if_not_exists: bool,
    pub concurrently: bool,
    pub using_method: Option<String>,
    pub has_predicate: bool,
    pub unique: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterTable {
    pub id: ObjectId,
    pub action: AlterTableActionMutation,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Rename {
    pub old_id: ObjectId,
    pub new_id: ObjectId,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropTable {
    pub id: ObjectId,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropIndex {
    pub id: ObjectId,
    pub if_exists: bool,
    pub concurrently: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SearchPathChange {
    pub target: SearchPathTarget,
    pub local: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TimeoutSettingChange {
    pub setting: TimeoutSetting,
    pub value: TimeoutSettingValue,
    pub local: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SavepointMutation {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReleaseSavepointMutation {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RollbackToSavepointMutation {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateFunctionMutation {
    pub id: ObjectId,
    pub or_replace: bool,
    pub params: Vec<crate::analysis::facts::ParamFact>,
    pub return_type: Option<crate::analysis::facts::RetTypeFact>,
    pub options: Vec<crate::analysis::facts::FuncOptionFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterFunctionMutation {
    pub id: ObjectId,
    pub action: crate::analysis::facts::AlterFunctionAction,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropFunctionMutation {
    pub signatures: Vec<crate::analysis::facts::FunctionSigFact>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateProcedureMutation {
    pub id: ObjectId,
    pub or_replace: bool,
    pub params: Vec<crate::analysis::facts::ParamFact>,
    pub options: Vec<crate::analysis::facts::FuncOptionFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterProcedureMutation {
    pub id: ObjectId,
    pub action: crate::analysis::facts::AlterFunctionAction,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropProcedureMutation {
    pub signatures: Vec<crate::analysis::facts::FunctionSigFact>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreatePublicationMutation {
    pub name: String,
    pub scope: crate::analysis::facts::PublicationScope,
    pub params: Vec<crate::analysis::facts::AttributeFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterPublicationMutation {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropPublicationMutation {
    pub names: Vec<String>,
    pub if_exists: bool,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateSubscriptionMutation {
    pub name: Option<String>,
    pub connection: crate::analysis::facts::ConnectionTarget,
    pub publications: Vec<String>,
    pub params: Option<Vec<crate::analysis::facts::AttributeFact>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterSubscriptionMutation {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropSubscriptionMutation {
    pub name: String,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateRoleMutation {
    pub name: String,
    pub inherits: bool,
    pub can_login: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterRoleMutation {
    pub name: crate::analysis::facts::RoleFact,
    pub inherits: Option<bool>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropRoleMutation {
    pub names: Vec<String>,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ResolvedGrantTarget {
    Tables(Vec<ObjectId>),
    AllTablesInSchema(Vec<String>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct GrantMutation {
    pub privileges: crate::analysis::facts::PrivilegeSpec,
    pub target: ResolvedGrantTarget,
    pub grantees: Vec<crate::analysis::facts::RoleFact>,
    pub with_grant_option: bool,
    pub granted_by: Option<crate::analysis::facts::RoleFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RevokeMutation {
    pub grant_option_only: bool,
    pub privileges: crate::analysis::facts::PrivilegeSpec,
    pub target: ResolvedGrantTarget,
    pub revokees: Vec<crate::analysis::facts::RoleFact>,
    pub granted_by: Option<crate::analysis::facts::RoleFact>,
    pub cascade: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateDatabaseMutation {
    pub name: String,
    pub options: Vec<crate::analysis::facts::DatabaseOptionFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterDatabaseMutation {
    pub id: ObjectId,
    pub action: crate::analysis::facts::AlterDatabaseAction,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropDatabaseMutation {
    pub id: ObjectId,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum OpaqueMutation {
    /// Squawk accepted the statement but safe-migrate has no typed extractor
    /// for it. Treating it as a no-op would leave later analysis falsely exact.
    UnsupportedStatement,
    DoBlock,
    Execute,
    DynamicSql,
    PrepareTransaction,
    SetTransaction,
    SetConstraints,
    StateCollision(String),
    UnresolvedReference {
        object_kind: crate::report::violations::ObjectKind,
        object_name: String,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum AlterTableActionMutation {
    AddColumn {
        name: String,
        ty: Option<String>,
        if_not_exists: bool,
        not_null: bool,
        default: Option<ExprIr>,
        depends_on: Option<(ObjectId, String)>,
        generation: crate::analysis::facts::ColumnGeneration,
    },
    DropColumn {
        name: String,
        if_exists: bool,
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
    },
    AddCheckConstraint {
        constraint_name: Option<String>,
        not_valid: bool,
    },
    AddUniqueConstraint {
        constraint_name: Option<String>,
        using_index: Option<ObjectId>,
    },
    AddPrimaryKeyConstraint {
        constraint_name: Option<String>,
        using_index: Option<ObjectId>,
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
        child: ObjectId,
        strategy: Option<String>,
    },
    DetachPartition {
        child: ObjectId,
    },
    SetStorage {
        column: String,
    },
    SetAccessMethod,
    OwnerTo {
        new_owner: crate::analysis::facts::RoleFact,
    },
    Opaque,
}
