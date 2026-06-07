use crate::ast::identifiers::QualifiedName;

// ─────────────────────────────────────────────
// StatementFact — pure syntactic IR
//
// INVARIANT: Every field here uses QualifiedName,
// never ObjectId. Resolution into ObjectId happens
// exclusively in the Resolver. The visitor that
// produces these facts has no knowledge of
// search_path or schema context.
// ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum StatementFact {
    // ── Schema definition ─────────────────────

    CreateTable {
        name: QualifiedName,
        if_not_exists: bool,
        /// Columns extracted from TableArgList.
        /// Empty vec means no column info could be extracted (e.g. CTAS).
        columns: Vec<ColumnFact>,
        /// Foreign key constraints extracted from TableArgList.
        /// Includes both column-level (ReferencesConstraint) and
        /// table-level (ForeignKeyConstraint) FKs.
        foreign_keys: Vec<FkFact>,
    },

    /// A CREATE VIEW statement.
    CreateView {
        name: QualifiedName,
        or_replace: bool,
    },

    CreateIndex {
        /// The index's own name (from name(), not path()).
        name: QualifiedName,
        /// The parent table (from relation_name().path()).
        relation: QualifiedName,
        if_not_exists: bool,
        /// True if CONCURRENTLY was present — from concurrently_token().is_some()
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

    /// DropIndex carries a Vec because one DROP INDEX statement can
    /// name multiple indexes (squawk's DropIndex::paths() is plural).
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
    RollbackTransaction,

    /// SAVEPOINT name
    Savepoint {
        name: String,
    },

    /// RELEASE SAVEPOINT name
    ReleaseSavepoint {
        name: String,
    },

    // ── Opaque / procedural ───────────────────

    /// DO $$ ... $$ block — untraceable, taints confidence.
    OpaqueBlock,

    /// EXECUTE stmt — dynamic SQL, taints confidence.
    Execute,
}

// ─────────────────────────────────────────────
// ColumnFact — a single column definition
// extracted from a Column node inside a
// TableArgList. Pure syntax — no resolution.
// ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct ColumnFact {
    /// From Column::name() → Name::ident_token()
    pub name: String,
    /// From Column::ty() → Type::syntax().text()
    /// None if the AST node had no type child.
    pub ty: Option<String>,
    /// True if a NotNullConstraint was found in Column::constraints()
    pub not_null: bool,
    /// True if a PrimaryKeyConstraint was found in Column::constraints()
    pub is_primary_key: bool,
}

// ─────────────────────────────────────────────
// FkFact — a foreign key reference extracted
// from either:
//   - a column-level ReferencesConstraint
//     (inside Column::constraints())
//   - a table-level ForeignKeyConstraint
//     (inside TableArg::TableConstraint)
// ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct FkFact {
    /// The referenced (target) table path.
    /// From ReferencesConstraint::table() or ForeignKeyConstraint::path()
    pub references: QualifiedName,
}

// ─────────────────────────────────────────────
// AlterTableActionFact — column-level syntactic
// mutations extracted from AlterTableAction enum
// variants by the visitor.
// ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum AlterTableActionFact {
    /// ADD COLUMN — name from AddColumn::name(), type from AddColumn::ty()
    AddColumn {
        name: String,
        /// Raw type text from ty().syntax().text(). None if the AST node
        /// had no type child (shouldn't happen in valid SQL, but we handle it).
        ty: Option<String>,
        if_not_exists: bool,
    },

    /// DROP COLUMN — name from DropColumn::name_ref()
    DropColumn {
        name: String,
        if_exists: bool,
    },
}
