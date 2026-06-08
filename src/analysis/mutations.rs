use crate::analysis::expr_ir::ExprIr;
use crate::ast::identifiers::ObjectId;

// ─────────────────────────────────────────────
// Mutation — resolved canonical state changes
//
// INVARIANT: Every field uses ObjectId, never
// QualifiedName. By the time a Mutation exists,
// the Resolver has already applied search_path
// expansion and produced a fully qualified id.
//
// INVARIANT: Rules are evaluated against these
// mutations BEFORE state.apply() is called.
// Rules are read-only — they never produce or
// modify mutations.
// ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum Mutation {
    // ── Schema definition ─────────────────────
    CreateTable(CreateTable),
    CreateView(CreateView),
    CreateIndex(CreateIndex),

    // ── Schema mutation ───────────────────────
    AlterTable(AlterTable),
    Rename(Rename),

    // ── Schema removal ────────────────────────
    DropTable(DropTable),
    DropIndex(DropIndex),

    // ── Session state ─────────────────────────
    SearchPath(SearchPathChange),

    // ── Transaction control ───────────────────
    BeginTransaction,
    CommitTransaction,
    RollbackTransaction,
    RollbackToSavepoint(RollbackToSavepointMutation),
    Savepoint(SavepointMutation),
    ReleaseSavepoint(ReleaseSavepointMutation),

    // ── Opaque / procedural ───────────────────
    Opaque(OpaqueMutation),
}

// ── Schema definition structs ─────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct CreateTable {
    pub id: ObjectId,
    pub if_not_exists: bool,
    pub columns: Vec<ColumnMutation>,
    pub foreign_keys: Vec<FkMutation>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ColumnMutation {
    pub name: String,
    pub ty: Option<String>,
    pub not_null: bool,
    pub is_primary_key: bool,
    /// Default expression for this column.
    /// Used by VolatileDefaultRule — replaces the type-string heuristic.
    /// None if no DEFAULT was specified or ExprVisitor extraction failed.
    pub default: Option<ExprIr>,
}

/// A foreign key edge carried inside a CreateTable or AlterTable mutation.
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

// ── Schema mutation structs ───────────────────

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

// ── Schema removal structs ────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct DropTable {
    pub id: ObjectId,
    pub if_exists: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DropIndex {
    pub id: ObjectId,
    pub if_exists: bool,
}

// ── Session state structs ─────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct SearchPathChange {
    pub schemas: Vec<String>,
}

// ── Transaction control structs ───────────────

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

// ── Opaque execution enum ─────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum OpaqueMutation {
    DoBlock,
    Execute,
    DynamicSql,
}

// ── Column-level action enum ──────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum AlterTableActionMutation {
    AddColumn {
        name: String,
        ty: Option<String>,
        if_not_exists: bool,
        /// Default expression, resolved from the AST via ExprVisitor.
        /// None if no DEFAULT was specified.
        default: Option<ExprIr>,
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
        to_table: ObjectId,
        from_columns: Vec<String>,
        to_columns: Vec<String>,
        not_valid: bool,
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
    },
    /// ALTER COLUMN name SET DEFAULT expr
    SetDefault {
        column: String,
        default: Option<ExprIr>,
    },
    /// ALTER TABLE name VALIDATE CONSTRAINT constraint_name
    /// Clears the matching entry from state.local.pending_validation.
    ValidateConstraint {
        /// The constraint name as it appears in the SQL — unresolved.
        /// Matched against pending_validation entries by string equality.
        constraint_name: String,
    },
}
