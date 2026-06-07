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
    },

    /// A CREATE VIEW statement.
    /// Kept separate from CreateTable so the resolver can insert a
    /// ViewEdge into the dependency graph rather than a plain relation.
    CreateView {
        name: QualifiedName,
        /// OR REPLACE — treated as idempotency signal, same as if_not_exists
        or_replace: bool,
    },

    CreateIndex {
        /// The index's own name (from name(), not path()).
        name: QualifiedName,
        /// The parent table (from relation_name().path()).
        relation: QualifiedName,
        if_not_exists: bool,
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
