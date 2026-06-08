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
    /// Distinct from RollbackTransaction so state.apply() can
    /// replay only the undo log up to the named savepoint frame.
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
}

// ─────────────────────────────────────────────
// FkFact — now includes both column lists.
// from_columns: source columns on this table.
// to_columns:   target columns on referenced table.
// Both may be empty for column-level ReferencesConstraint
// (which only specifies the target table).
// ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct FkFact {
    /// The referenced (target) table path.
    pub references: QualifiedName,
    /// Source columns on this table.
    /// Populated from ForeignKeyConstraint::from_columns() (handwritten).
    /// Empty for column-level ReferencesConstraint.
    pub from_columns: Vec<String>,
    /// Target columns on the referenced table.
    /// Populated from ForeignKeyConstraint::to_columns() (handwritten).
    /// Empty for column-level ReferencesConstraint.
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
    },

    /// DROP COLUMN
    DropColumn {
        name: String,
        if_exists: bool,
    },

    /// RENAME COLUMN old TO new
    /// from: RenameColumn::from() → NameRef
    /// to:   RenameColumn::to()   → NameRef
    RenameColumn {
        from: String,
        to: String,
    },

    /// RENAME TO new_name (table rename)
    /// new_name: RenameTo::name()
    /// old name comes from the enclosing AlterTable::relation_name()
    RenameTo {
        new_name: String,
    },

    /// ADD CONSTRAINT — FK only for now.
    /// not_valid: true if NOT VALID was present (skips table scan,
    /// requires subsequent VALIDATE CONSTRAINT).
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
}
