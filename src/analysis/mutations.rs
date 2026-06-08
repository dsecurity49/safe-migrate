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
}

/// A foreign key edge carried inside a CreateTable or AlterTable mutation.
/// Both column lists are now populated where squawk exposes them
/// (table-level ForeignKeyConstraint via handwritten from_columns()/to_columns()).
/// Both are empty for column-level ReferencesConstraint.
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

/// A table-level rename — old identity from AlterTable::relation_name(),
/// new name from RenameTo::name().
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

/// ROLLBACK TO SAVEPOINT name — partial rollback to a named frame.
/// Distinct from RollbackTransaction (full rollback).
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
//
// Carried inside AlterTable::action.
// state.apply() converts this into a ColumnAction
// (model layer) before calling
// RelationState::apply_column_action().

#[derive(Clone, Debug, PartialEq)]
pub enum AlterTableActionMutation {
    AddColumn {
        name: String,
        ty: Option<String>,
        if_not_exists: bool,
    },
    DropColumn {
        name: String,
        if_exists: bool,
    },
    /// RENAME COLUMN old TO new — both names from handwritten RenameColumn accessors.
    RenameColumn {
        from: String,
        to: String,
    },
    /// ADD CONSTRAINT FOREIGN KEY — includes both column lists where available.
    /// not_valid: skipped table scan, needs VALIDATE CONSTRAINT later.
    AddForeignKey {
        to_table: ObjectId,
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
}
