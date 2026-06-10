use crate::analysis::expr_ir::ExprIr;
use crate::ast::identifiers::QualifiedName;

// ─────────────────────────────────────────────
// StatementFact — pure syntactic IR
// ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum StatementFact {
    // ── Schema definition ─────────────────────

    CreateTable {
        name: QualifiedName,
        if_not_exists: bool,
        columns: Vec<ColumnFact>,
        foreign_keys: Vec<FkFact>,
        /// Table-level constraints (PK, UNIQUE, CHECK) from CREATE TABLE (...).
        /// Foreign keys are kept separate in `foreign_keys` for historical reasons.
        /// Bug 9: was missing entirely — these constraints were silently dropped.
        table_constraints: Vec<TableConstraintFact>,
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
        /// True if CONCURRENTLY was present.
        /// DROP INDEX without CONCURRENTLY takes AccessExclusiveLock.
        concurrently: bool,
    },

    // ── Session state ─────────────────────────

    SetSearchPath {
        schemas: Vec<String>,
    },

    // ── Transaction control ───────────────────

    BeginTransaction,
    CommitTransaction,
    RollbackTransaction,
    RollbackToSavepoint { name: String },
    Savepoint { name: String },
    ReleaseSavepoint { name: String },

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
// TableConstraintFact
//
// Table-level constraints extracted from
// CREATE TABLE (...). These are distinct from:
//   - column-level inline constraints (ColumnFact)
//   - ALTER TABLE ADD CONSTRAINT (AlterTableActionFact)
//
// Bug 9: previously these were silently dropped in
// extract_table_body() — only FK constraints were
// forwarded, all others hit the `_ => None` arm.
// ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum TableConstraintFact {
    /// PRIMARY KEY (col1, col2, ...)
    /// Columns named here are implicitly NOT NULL per SQL spec §11.7.
    PrimaryKey { columns: Vec<String> },
    /// UNIQUE (col1, col2, ...)
    Unique { columns: Vec<String> },
    /// CHECK (expr)
    /// Expression is not modelled — we only need to know the constraint exists
    /// for now (future: extract expression for volatility checking in defaults).
    Check,
}

// ─────────────────────────────────────────────
// AlterTableActionFact
// ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum AlterTableActionFact {
    /// Bug 11: added `not_null` field — was missing, apply() always stored
    /// not_null=false for ADD COLUMN regardless of the NOT NULL constraint.
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
        from: String,
        to: String,
    },
    RenameTo {
        new_name: String,
    },

    // ── ADD CONSTRAINT variants ───────────────

    /// Bug 10: added `constraint_name` field — was missing, so VALIDATE CONSTRAINT
    /// could never match the synthetic `__fk__...` placeholder inserted by apply().
    AddForeignKey {
        /// The constraint name as written in SQL, e.g. `ADD CONSTRAINT fk_orders FOREIGN KEY ...`
        /// `None` when the SQL omits the CONSTRAINT name clause.
        constraint_name: Option<String>,
        references: QualifiedName,
        from_columns: Vec<String>,
        to_columns: Vec<String>,
        not_valid: bool,
    },

    /// ADD CONSTRAINT ... CHECK (expr)
    /// not_valid: true skips scan of existing rows.
    /// Without NOT VALID on a live table this is a full table scan
    /// with ShareLock held for the duration.
    AddCheckConstraint {
        not_valid: bool,
    },

    /// ADD CONSTRAINT ... UNIQUE (columns)
    /// Always takes AccessExclusiveLock.
    /// Safe pattern: CREATE UNIQUE INDEX CONCURRENTLY first,
    /// then ADD CONSTRAINT ... USING INDEX.
    AddUniqueConstraint,

    /// ADD CONSTRAINT ... PRIMARY KEY (columns)
    /// Always takes AccessExclusiveLock.
    AddPrimaryKeyConstraint,

    // ── Column-level mutations ─────────────────

    SetNotNull { column: String },
    DropNotNull { column: String },
    SetType { column: String, ty: String },
    SetDefault { column: String, default: Option<ExprIr> },
    ValidateConstraint { constraint_name: String },
}
