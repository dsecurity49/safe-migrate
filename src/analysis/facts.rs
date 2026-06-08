use crate::analysis::expr_ir::ExprIr;
use crate::ast::identifiers::QualifiedName;

// ─────────────────────────────────────────────
// StatementFact — pure syntactic IR
//
// INVARIANT: Every field here uses QualifiedName,
// never ObjectId. Resolution into ObjectId happens
// exclusively in the Resolver.
// ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum StatementFact {
    // ── Schema definition ─────────────────────

    CreateTable {
        name: QualifiedName,
        if_not_exists: bool,
        columns: Vec<ColumnFact>,
        foreign_keys: Vec<FkFact>,
    },

    CreateView {
        name: QualifiedName,
        or_replace: bool,
    },

    CreateIndex {
        name: QualifiedName,
        relation: QualifiedName,
        if_not_exists: bool,
        concurrently: bool,
    },

    // ── Schema mutation ───────────────────────

    AlterTable {
        name: QualifiedName,
        actions: Vec<AlterTableActionFact>,
    },

    // ── Schema removal ────────────────────────

    DropTable {
        name: QualifiedName,
        if_exists: bool,
    },

    DropIndex {
        names: Vec<QualifiedName>,
        if_exists: bool,
    },

    // ── Session state ─────────────────────────

    SetSearchPath {
        schemas: Vec<String>,
    },

    // ── Transaction control ───────────────────

    BeginTransaction,
    CommitTransaction,

    /// Plain ROLLBACK — rolls back the entire transaction.
    RollbackTransaction,

    /// ROLLBACK TO SAVEPOINT name — partial rollback.
    RollbackToSavepoint {
        name: String,
    },

    Savepoint {
        name: String,
    },

    ReleaseSavepoint {
        name: String,
    },

    // ── Opaque / procedural ───────────────────

    OpaqueBlock,
    Execute,
}

// ─────────────────────────────────────────────
// ColumnFact
// ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct ColumnFact {
    pub name: String,
    pub ty: Option<String>,
    pub not_null: bool,
    pub is_primary_key: bool,
    /// Default expression extracted from DefaultConstraint::expr().
    /// None if no DEFAULT was specified or extraction failed.
    /// Used by VolatileDefaultRule to replace the type-heuristic.
    pub default: Option<ExprIr>,
}

// ─────────────────────────────────────────────
// FkFact
// ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct FkFact {
    pub references: QualifiedName,
    pub from_columns: Vec<String>,
    pub to_columns: Vec<String>,
}

// ─────────────────────────────────────────────
// AlterTableActionFact
// ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum AlterTableActionFact {
    /// ADD COLUMN
    AddColumn {
        name: String,
        ty: Option<String>,
        if_not_exists: bool,
        /// Default expression from AddColumn::constraints() →
        /// ColumnConstraint::DefaultConstraint → DefaultConstraint::expr().
        /// None if no DEFAULT was specified.
        default: Option<ExprIr>,
    },

    /// DROP COLUMN
    DropColumn {
        name: String,
        if_exists: bool,
    },

    /// RENAME COLUMN old TO new
    RenameColumn {
        from: String,
        to: String,
    },

    /// RENAME TO new_name (table rename)
    RenameTo {
        new_name: String,
    },

    /// ADD CONSTRAINT FOREIGN KEY
    AddForeignKey {
        references: QualifiedName,
        from_columns: Vec<String>,
        to_columns: Vec<String>,
        not_valid: bool,
    },

    /// ALTER COLUMN name SET NOT NULL
    SetNotNull {
        column: String,
    },

    /// ALTER COLUMN name DROP NOT NULL
    DropNotNull {
        column: String,
    },

    /// ALTER COLUMN name SET DATA TYPE ty
    SetType {
        column: String,
        ty: String,
    },

    /// ALTER COLUMN name SET DEFAULT expr
    /// From AlterColumnOption::SetDefault → SetDefault::expr()
    SetDefault {
        column: String,
        /// The new default expression. None if extraction failed.
        default: Option<ExprIr>,
    },

    /// ALTER TABLE name VALIDATE CONSTRAINT constraint_name
    /// From AlterTableAction::ValidateConstraint → ValidateConstraint::name_ref()
    /// Used to clear pending_validation entries in state.
    ValidateConstraint {
        constraint_name: String,
    },
}
