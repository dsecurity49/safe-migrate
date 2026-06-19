// FILE: ./src/analysis/mutations.rs

use crate::analysis::expr_ir::ExprIr;
use crate::ast::identifiers::ObjectId;

#[derive(Clone, Debug, PartialEq)]
pub enum PersistenceMutation {
    Permanent,
    Temporary,
    Unlogged,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Mutation {
    CreateTable(CreateTable),
    CreateView(CreateView),
    CreateMaterializedView(CreateMaterializedView),
    RefreshMaterializedView(RefreshMaterializedViewMutation),
    CreateIndex(CreateIndex),
    CreatePolicy(CreatePolicyMutation),
    DropPolicy(DropPolicyMutation),
    CreateTrigger(CreateTriggerMutation),
    DropTrigger(DropTriggerMutation),
    AlterTable(AlterTable),
    CreateType(CreateTypeMutation),
    AlterType(AlterTypeMutation),
    CreateDomain(CreateDomainMutation),
    AlterDomain(AlterDomainMutation),
    DropDomain(DropDomainMutation),
    CreateSequence(CreateSequenceMutation),
    AlterSequence(AlterSequenceMutation),
    DropSequence(DropSequenceMutation),
    Rename(Rename),
    DropTable(DropTable),
    DropView(DropViewMutation),
    DropMaterializedView(DropMaterializedViewMutation),
    DropIndex(DropIndex),
    SearchPath(SearchPathChange),
    BeginTransaction,
    CommitTransaction,
    RollbackTransaction,
    RollbackToSavepoint(RollbackToSavepointMutation),
    Savepoint(SavepointMutation),
    ReleaseSavepoint(ReleaseSavepointMutation),
    Opaque(OpaqueMutation),
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreatePolicyMutation {
    pub name: String,
    pub table: ObjectId,
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
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropTriggerMutation {
    pub name: String,
    pub table: ObjectId,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropViewMutation {
    pub ids: Vec<ObjectId>,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropMaterializedViewMutation {
    pub ids: Vec<ObjectId>,
    pub if_exists: bool,
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
    pub owned_by: Option<(ObjectId, String)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropSequenceMutation {
    pub ids: Vec<ObjectId>,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateDomainMutation {
    pub id: ObjectId,
    pub base_type: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterDomainMutation {
    pub id: ObjectId,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropDomainMutation {
    pub ids: Vec<ObjectId>,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateTypeMutation {
    pub id: ObjectId,
    pub is_enum: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterTypeMutation {
    pub id: ObjectId,
    pub action: AlterTypeActionMutation,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AlterTypeActionMutation {
    AddValue { new_value: String },
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateTable {
    pub id: ObjectId,
    pub if_not_exists: bool,
    pub as_select: bool,
    pub persistence: PersistenceMutation,
    pub columns: Vec<ColumnMutation>,
    pub foreign_keys: Vec<FkMutation>,
    pub table_constraints: Vec<crate::analysis::facts::TableConstraintFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ColumnMutation {
    pub name: String,
    pub ty: Option<String>,
    pub not_null: bool,
    pub is_primary_key: bool,
    pub default: Option<ExprIr>,
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
    pub schemas: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SavepointMutation { pub name: String }

#[derive(Clone, Debug, PartialEq)]
pub struct ReleaseSavepointMutation { pub name: String }

#[derive(Clone, Debug, PartialEq)]
pub struct RollbackToSavepointMutation { pub name: String }

#[derive(Clone, Debug, PartialEq)]
pub enum OpaqueMutation { DoBlock, Execute, DynamicSql }

#[derive(Clone, Debug, PartialEq)]
pub enum AlterTableActionMutation {
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
    RenameColumn { from: String, to: String },
    AddForeignKey {
        constraint_name: Option<String>,
        to_table: ObjectId,
        from_columns: Vec<String>,
        to_columns: Vec<String>,
        not_valid: bool,
    },
    AlterConstraint {
        name: String,
        deferrable: bool,
    },
    DropConstraint {
        name: String,
    },
    AddCheckConstraint {
        not_valid: bool,
    },
    AddUniqueConstraint,
    AddPrimaryKeyConstraint,
    AddExcludeConstraint,
    SetNotNull { column: String },
    DropNotNull { column: String },
    SetType { column: String, ty: String },
    SetDefault { column: String, default: Option<ExprIr> },
    ValidateConstraint { constraint_name: String },
    AttachPartition { child: ObjectId },
    DetachPartition { child: ObjectId },
    SetStorage { column: String },
    SetAccessMethod,
}
