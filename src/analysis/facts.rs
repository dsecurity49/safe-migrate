// FILE: ./src/analysis/facts.rs

use crate::analysis::expr_ir::ExprIr;
use crate::ast::identifiers::{Ident, QualifiedName};

#[derive(Clone, Debug, PartialEq)]
pub enum PersistenceFact {
    Permanent,
    Temporary,
    Unlogged,
}

#[derive(Clone, Debug, PartialEq)]
pub enum StatementFact {
    CreateTable {
        name: QualifiedName,
        if_not_exists: bool,
        as_select: bool,
        persistence: PersistenceFact,
        columns: Vec<ColumnFact>,
        foreign_keys: Vec<FkFact>,
        table_constraints: Vec<TableConstraintFact>,
    },
    CreateView {
        name: QualifiedName,
        or_replace: bool,
        depends_on: Vec<QualifiedName>,
    },
    CreateMaterializedView {
        name: QualifiedName,
        depends_on: Vec<QualifiedName>,
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
    },
    CreatePolicy {
        name: String,
        table: QualifiedName,
    },
    DropPolicy {
        name: String,
        table: QualifiedName,
        if_exists: bool,
    },
    CreateTrigger {
        name: String,
        table: QualifiedName,
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
    },
    DropDomain {
        names: Vec<QualifiedName>,
        if_exists: bool,
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
    },
    DropTable {
        name: QualifiedName,
        if_exists: bool,
        cascade: bool,
    },
    DropView {
        names: Vec<QualifiedName>,
        if_exists: bool,
    },
    DropMaterializedView {
        names: Vec<QualifiedName>,
        if_exists: bool,
    },
    DropIndex {
        names: Vec<QualifiedName>,
        if_exists: bool,
        concurrently: bool,
    },
    SetSearchPath {
        schemas: Vec<String>,
    },
    BeginTransaction,
    CommitTransaction,
    RollbackTransaction,
    RollbackToSavepoint { name: String },
    Savepoint { name: String },
    ReleaseSavepoint { name: String },
    OpaqueBlock,
    Execute,
    Vacuum { is_full: bool },
}

#[derive(Clone, Debug, PartialEq)]
pub enum AlterIndexActionFact {
    RenameTo { new_name: Ident },
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateTypeFact {
    pub name: QualifiedName,
    pub is_enum: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AlterTypeFact {
    pub name: QualifiedName,
    pub actions: Vec<AlterTypeActionFact>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AlterTypeActionFact {
    AddValue { new_value: String },
}

#[derive(Clone, Debug, PartialEq)]
pub struct ColumnFact {
    pub name: String,
    pub ty: Option<String>,
    pub not_null: bool,
    pub is_primary_key: bool,
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
    PrimaryKey { columns: Vec<String> },
    Unique { columns: Vec<String> },
    Check,
    Exclude,
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
    SetType { column: String, ty: String, has_using: bool },
    SetDefault { column: String, default: Option<ExprIr> },
    ValidateConstraint { constraint_name: String },
    AttachPartition { child: QualifiedName },
    DetachPartition { child: QualifiedName },
    SetStorage { column: String },
    SetAccessMethod,
}
