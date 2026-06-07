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
}

/// A resolved CREATE VIEW mutation.
/// The resolver will attempt to populate `depends_on` by inspecting
/// the view query for table references. Initially this may be empty
/// until query analysis is implemented.
#[derive(Clone, Debug, PartialEq)]
pub struct CreateView {
    pub id: ObjectId,
    pub or_replace: bool,
    /// Tables/views this view depends on — populated by query analysis.
    /// Empty Vec is valid during early implementation phases.
    pub depends_on: Vec<ObjectId>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateIndex {
    pub id: ObjectId,
    pub table: ObjectId,
    pub if_not_exists: bool,
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

/// One entry per index named in the DROP INDEX statement.
/// squawk's DropIndex::paths() is plural so one statement
/// can produce multiple DropIndex mutations.
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
// The state.apply() layer converts this into a
// ColumnAction (model layer) before calling
// RelationState::apply_column_action().

#[derive(Clone, Debug, PartialEq)]
pub enum AlterTableActionMutation {
    AddColumn {
        name: String,
        /// Raw type string from the AST (e.g. "text", "integer", "uuid").
        /// None only if the AST node had no type child.
        ty: Option<String>,
        if_not_exists: bool,
    },
    DropColumn {
        name: String,
        if_exists: bool,
    },
}
