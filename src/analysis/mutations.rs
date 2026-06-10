use crate::analysis::expr_ir::ExprIr;
use crate::ast::identifiers::ObjectId;

#[derive(Clone, Debug, PartialEq)]
pub enum Mutation {
    CreateTable(CreateTable),
    CreateView(CreateView),
    CreateIndex(CreateIndex),
    AlterTable(AlterTable),
    Rename(Rename),
    DropTable(DropTable),
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
pub struct CreateTable {
    pub id: ObjectId,
    pub if_not_exists: bool,
    pub columns: Vec<ColumnMutation>,
    pub foreign_keys: Vec<FkMutation>,
    /// Bug 9: carry table-level constraints through to apply() so PK columns
    /// are marked not_null even when the column definition omits the keyword.
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
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropIndex {
    pub id: ObjectId,
    pub if_exists: bool,
    /// True if CONCURRENTLY was present.
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
    /// Bug 11: added not_null field — previously hardcoded false in apply(),
    /// so NOT NULL constraints on ADD COLUMN were silently discarded.
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
    /// Bug 10: added constraint_name field — previously a synthetic __fk__...
    /// placeholder was always used, making VALIDATE CONSTRAINT by real name
    /// impossible to match.
    AddForeignKey {
        /// The authored constraint name, or None if the SQL omitted CONSTRAINT <name>.
        constraint_name: Option<String>,
        to_table: ObjectId,
        from_columns: Vec<String>,
        to_columns: Vec<String>,
        not_valid: bool,
    },
    /// ADD CONSTRAINT ... CHECK (expr)
    AddCheckConstraint {
        not_valid: bool,
    },
    /// ADD CONSTRAINT ... UNIQUE
    AddUniqueConstraint,
    /// ADD CONSTRAINT ... PRIMARY KEY
    AddPrimaryKeyConstraint,
    SetNotNull { column: String },
    DropNotNull { column: String },
    SetType { column: String, ty: String },
    SetDefault { column: String, default: Option<ExprIr> },
    ValidateConstraint { constraint_name: String },
}
