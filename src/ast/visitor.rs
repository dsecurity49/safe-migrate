use crate::analysis::expr_ir::ExprIr;
use crate::analysis::expr_visitor::ExprVisitor;
use crate::analysis::facts::{
    AlterTableActionFact, ColumnFact, FkFact, StatementFact, TableConstraintFact,
};
use crate::ast::identifiers::QualifiedName;
use squawk_syntax::ast::{
    AstNode, AlterColumnOption, AlterTable, AlterTableAction, Column, ColumnConstraint,
    ConfigValue, Constraint, CreateIndex, CreateTable, CreateTableAs, CreateView, DropIndex,
    DropTable, Path, PathSegment, ReleaseSavepoint, Rollback, Savepoint, Set, Stmt, TableArg,
    TableConstraint,
};

pub struct AstVisitor;

impl AstVisitor {
    pub fn extract(stmt: &Stmt) -> Option<StatementFact> {
        match stmt {
            Stmt::CreateTable(node)      => Self::extract_create_table(node),
            Stmt::CreateTableAs(node)    => Self::extract_create_table_as(node),
            Stmt::CreateView(node)       => Self::extract_create_view(node),
            Stmt::CreateIndex(node)      => Self::extract_create_index(node),
            Stmt::AlterTable(node)       => Self::extract_alter_table(node),
            Stmt::DropTable(node)        => Self::extract_drop_table(node),
            Stmt::DropIndex(node)        => Self::extract_drop_index(node),
            Stmt::Set(node)              => Self::extract_set(node),
            Stmt::Begin(_)               => Some(StatementFact::BeginTransaction),
            Stmt::Commit(_)              => Some(StatementFact::CommitTransaction),
            Stmt::Rollback(node)         => Some(Self::extract_rollback(node)),
            Stmt::Savepoint(node)        => Self::extract_savepoint(node),
            Stmt::ReleaseSavepoint(node) => Self::extract_release_savepoint(node),
            Stmt::Do(_)                  => Some(StatementFact::OpaqueBlock),
            Stmt::Execute(_)             => Some(StatementFact::Execute),
            _                            => None,
        }
    }

    // ── CREATE TABLE ──────────────────────────────────────────────────

    fn extract_create_table(node: &CreateTable) -> Option<StatementFact> {
        let path = node.path()?;
        let name = Self::path_to_qualified_name(&path)?;
        let if_not_exists = node.if_not_exists().is_some();

        // Bug 9: extract_table_body now returns three vecs; previously returned two,
        // silently dropping all table-level PK/UNIQUE/CHECK constraints.
        let (columns, foreign_keys, table_constraints) = node
            .table_arg_list()
            .map(|tal| Self::extract_table_body(tal.args()))
            .unwrap_or_else(|| (Vec::new(), Vec::new(), Vec::new()));

        Some(StatementFact::CreateTable {
            name,
            if_not_exists,
            columns,
            foreign_keys,
            table_constraints,
        })
    }

    fn extract_create_table_as(node: &CreateTableAs) -> Option<StatementFact> {
        let path = node.path()?;
        Some(StatementFact::CreateTable {
            name: Self::path_to_qualified_name(&path)?,
            if_not_exists: node.if_not_exists().is_some(),
            columns: Vec::new(),
            foreign_keys: Vec::new(),
            // CREATE TABLE AS has no column list; columns unknown until SELECT executes.
            table_constraints: Vec::new(),
        })
    }

    // ── Table body extraction ─────────────────────────────────────────

    /// Returns (columns, foreign_keys, table_constraints).
    ///
    /// Bug 9: previously returned (columns, foreign_keys) and the
    /// `TableArg::TableConstraint` arm only forwarded FK constraints.
    /// PK, UNIQUE, and CHECK constraints hit `_ => None` and were dropped.
    fn extract_table_body(
        args: impl Iterator<Item = TableArg>,
    ) -> (Vec<ColumnFact>, Vec<FkFact>, Vec<TableConstraintFact>) {
        let mut columns: Vec<ColumnFact> = Vec::new();
        let mut foreign_keys: Vec<FkFact> = Vec::new();
        let mut table_constraints: Vec<TableConstraintFact> = Vec::new();

        for arg in args {
            match arg {
                TableArg::Column(col) => {
                    // Bug 12: pass the column's name into extract_column_fk_facts
                    // so that from_columns is populated for inline FK constraints.
                    // Previously from_columns was always Vec::new().
                    for fk in Self::extract_column_fk_facts(&col) {
                        foreign_keys.push(fk);
                    }
                    if let Some(fact) = Self::extract_column_fact(&col) {
                        columns.push(fact);
                    }
                }
                TableArg::TableConstraint(tc) => {
                    if let Some(fk) = Self::extract_table_fk_fact(&tc) {
                        foreign_keys.push(fk);
                    }
                    // Bug 9: previously only FKs were extracted; now extract all.
                    if let Some(tc_fact) = Self::extract_table_constraint_fact(&tc) {
                        table_constraints.push(tc_fact);
                    }
                }
                TableArg::LikeClause(_) => {}
            }
        }

        (columns, foreign_keys, table_constraints)
    }

    fn extract_column_fact(col: &Column) -> Option<ColumnFact> {
        // Bug 3: use Name::text() directly instead of .ident_token()?.text().
        // Name and NameRef both expose .text() without going through the token.
        let name = col
            .name()
            .map(|n| n.text().to_string())?;

        let ty = col.ty().map(|t| t.syntax().text().to_string());

        let mut not_null = false;
        let mut is_primary_key = false;
        let mut default: Option<ExprIr> = None;

        for constraint in col.constraints() {
            match constraint {
                ColumnConstraint::NotNullConstraint(_) => not_null = true,
                ColumnConstraint::PrimaryKeyConstraint(_) => {
                    is_primary_key = true;
                    not_null = true;
                }
                ColumnConstraint::DefaultConstraint(dc) => {
                    default = dc.expr().map(ExprVisitor::convert);
                }
                _ => {}
            }
        }

        Some(ColumnFact { name, ty, not_null, is_primary_key, default })
    }

    /// Extract FK facts from inline column-level REFERENCES constraints.
    ///
    /// Bug 12: the owning column IS the referencing column for an inline FK,
    /// so from_columns must be populated with the column's own name.
    /// Previously from_columns was always Vec::new().
    fn extract_column_fk_facts(col: &Column) -> Vec<FkFact> {
        // Bug 3: use Name::text() directly.
        let col_name: Option<String> = col.name().map(|n| n.text().to_string());

        let mut facts = Vec::new();
        for constraint in col.constraints() {
            if let ColumnConstraint::ReferencesConstraint(rc) = constraint {
                if let Some(path) = rc.table() {
                    if let Some(references) = Self::path_to_qualified_name(&path) {
                        facts.push(FkFact {
                            references,
                            // Bug 12 fix: the referencing column is this column.
                            from_columns: col_name.iter().cloned().collect(),
                            to_columns: Vec::new(),
                        });
                    }
                }
            }
        }
        facts
    }

    fn extract_table_fk_fact(tc: &TableConstraint) -> Option<FkFact> {
        if let TableConstraint::ForeignKeyConstraint(fkc) = tc {
            let path = fkc.path()?;
            let references = Self::path_to_qualified_name(&path)?;

            let from_columns = fkc
                .from_columns()
                .map(|cl| Self::extract_column_list_names(cl))
                .unwrap_or_default();

            let to_columns = fkc
                .to_columns()
                .map(|cl| Self::extract_column_list_names(cl))
                .unwrap_or_default();

            Some(FkFact { references, from_columns, to_columns })
        } else {
            None
        }
    }

    /// Extract non-FK table constraints (PK, UNIQUE, CHECK).
    ///
    /// Bug 9: this function did not exist — the TableConstraint arm in
    /// extract_table_body had no equivalent for non-FK constraints.
    ///
    /// VERIFY before compiling: PrimaryKeyConstraint and UniqueConstraint
    /// column-list accessor names. Pattern should match ForeignKeyConstraint
    /// which uses from_columns(). Grep squawk.rs for PrimaryKeyConstraint
    /// and UniqueConstraint in the manual extension block (~38k–39k line range).
    /// Expected: `pkc.columns() -> Option<ColumnList>` and
    ///           `uc.columns()  -> Option<ColumnList>`.
    fn extract_table_constraint_fact(tc: &TableConstraint) -> Option<TableConstraintFact> {
        match tc {
            TableConstraint::PrimaryKeyConstraint(pkc) => {
                let columns = pkc
                    .column_list()
                    .map(|cl| Self::extract_column_list_names(cl))
                    .unwrap_or_default();
                Some(TableConstraintFact::PrimaryKey { columns })
            }
            TableConstraint::UniqueConstraint(uc) => {
                let columns = uc
                    .column_list()
                    .map(|cl| Self::extract_column_list_names(cl))
                    .unwrap_or_default();
                Some(TableConstraintFact::Unique { columns })
            }
            TableConstraint::CheckConstraint(_) => {
                Some(TableConstraintFact::Check)
            }
            // ForeignKeyConstraint is handled separately in extract_table_fk_fact.
            _ => None,
        }
    }

    /// Extract column names from a ColumnList node.
    /// Bug 3: use NameRef::text() directly instead of .ident_token()?.text().
    fn extract_column_list_names(cl: squawk_syntax::ast::ColumnList) -> Vec<String> {
        cl.columns()
            .filter_map(|col| {
                col.name_ref().map(|n| n.text().to_string())
            })
            .collect()
    }

    // ── CREATE VIEW ───────────────────────────────────────────────────

    fn extract_create_view(node: &CreateView) -> Option<StatementFact> {
        let path = node.path()?;
        Some(StatementFact::CreateView {
            name: Self::path_to_qualified_name(&path)?,
            or_replace: node.or_replace().is_some(),
        })
    }

    // ── CREATE INDEX ──────────────────────────────────────────────────

    fn extract_create_index(node: &CreateIndex) -> Option<StatementFact> {
        // Bug 3: use Name::text() directly.
        let index_name_str = node
            .name()?
            .text()
            .to_string();

        let relation_path = node.relation_name()?.path()?;

        Some(StatementFact::CreateIndex {
            name: QualifiedName::new(None, index_name_str),
            relation: Self::path_to_qualified_name(&relation_path)?,
            if_not_exists: node.if_not_exists().is_some(),
            concurrently: node.concurrently_token().is_some(),
        })
    }

    // ── ALTER TABLE ───────────────────────────────────────────────────

    fn extract_alter_table(node: &AlterTable) -> Option<StatementFact> {
        let path = node.relation_name()?.path()?;
        let table_name = Self::path_to_qualified_name(&path)?;
        let mut actions = Vec::new();

        for action in node.actions() {
            match action {
                AlterTableAction::AddColumn(add) => {
                    // Bug 3: use Name::text() directly.
                    if let Some(name) = add.name().map(|n| n.text().to_string()) {
                        // Bug 11: scan constraints for NOT NULL and PRIMARY KEY.
                        // AddColumn::constraints() returns AstChildren<Constraint>
                        // (table-level Constraint enum, not ColumnConstraint).
                        let mut not_null = false;
                        let mut default = None;

                        for c in add.constraints() {
                            match c {
                                Constraint::NotNullConstraint(_) => {
                                    not_null = true;
                                }
                                Constraint::PrimaryKeyConstraint(_) => {
                                    // Inline PK on ADD COLUMN implies NOT NULL.
                                    not_null = true;
                                }
                                Constraint::DefaultConstraint(dc) => {
                                    default = dc.expr().map(ExprVisitor::convert);
                                }
                                _ => {}
                            }
                        }

                        actions.push(AlterTableActionFact::AddColumn {
                            name,
                            ty: add.ty().map(|t| t.syntax().text().to_string()),
                            if_not_exists: add.if_not_exists().is_some(),
                            not_null,
                            default,
                        });
                    }
                }

                AlterTableAction::DropColumn(drop) => {
                    // Bug 3: use NameRef::text() directly.
                    if let Some(name) = drop.name_ref().map(|n| n.text().to_string()) {
                        actions.push(AlterTableActionFact::DropColumn {
                            name,
                            if_exists: drop.if_exists().is_some(),
                        });
                    }
                }

                // RENAME COLUMN old TO new
                // Uses handwritten from() / to() accessors returning Option<NameRef>.
                AlterTableAction::RenameColumn(rc) => {
                    // Bug 3: use NameRef::text() directly.
                    let from = rc.from().map(|n| n.text().to_string());
                    let to   = rc.to().map(|n| n.text().to_string());
                    if let (Some(from), Some(to)) = (from, to) {
                        actions.push(AlterTableActionFact::RenameColumn { from, to });
                    }
                }

                // RENAME TO new_table_name
                AlterTableAction::RenameTo(rt) => {
                    // Bug 3: use Name::text() directly.
                    if let Some(new_name) = rt.name().map(|n| n.text().to_string()) {
                        actions.push(AlterTableActionFact::RenameTo { new_name });
                    }
                }

                AlterTableAction::AddConstraint(ac) => {
                    if let Some(fact) = Self::extract_add_constraint_fact(&ac) {
                        actions.push(fact);
                    }
                }

                AlterTableAction::AlterColumn(alter_col) => {
                    // Bug 3: use NameRef::text() directly.
                    let col_name = match alter_col.name_ref().map(|n| n.text().to_string()) {
                        Some(name) => name,
                        None => continue,
                    };
                    if let Some(opt) = alter_col.option() {
                        if let Some(fact) = Self::extract_alter_column_option(col_name, opt) {
                            actions.push(fact);
                        }
                    }
                }

                // VALIDATE CONSTRAINT constraint_name
                AlterTableAction::ValidateConstraint(vc) => {
                    // Bug 3: use NameRef::text() directly.
                    if let Some(constraint_name) = vc.name_ref().map(|n| n.text().to_string()) {
                        actions.push(AlterTableActionFact::ValidateConstraint { constraint_name });
                    }
                }

                _ => {}
            }
        }

        Some(StatementFact::AlterTable { name: table_name, actions })
    }

    fn extract_alter_column_option(
        col_name: String,
        opt: AlterColumnOption,
    ) -> Option<AlterTableActionFact> {
        match opt {
            AlterColumnOption::SetNotNull(_) => {
                Some(AlterTableActionFact::SetNotNull { column: col_name })
            }
            AlterColumnOption::DropNotNull(_) => {
                Some(AlterTableActionFact::DropNotNull { column: col_name })
            }
            AlterColumnOption::SetType(st) => {
                let ty = st.ty()?.syntax().text().to_string();
                Some(AlterTableActionFact::SetType { column: col_name, ty })
            }
            AlterColumnOption::SetDefault(sd) => {
                let default = sd.expr().map(ExprVisitor::convert);
                Some(AlterTableActionFact::SetDefault { column: col_name, default })
            }
            _ => None,
        }
    }

    /// Extract an AddForeignKey fact from an AddConstraint action.
    /// Also extracts CHECK, UNIQUE, and PK constraint facts.
    ///
    /// Bug 10: extracts the constraint name from the inner constraint node.
    ///
    /// AddConstraint has no name accessor of its own — confirmed by grep:
    /// its impl block only has constraint(), not_valid(), deferrable options,
    /// enforced(), no_inherit(), and token accessors. The CONSTRAINT <name>
    /// clause is parsed as a ConstraintName child of each inner constraint node
    /// (ForeignKeyConstraint, UniqueConstraint, PrimaryKeyConstraint, etc.).
    ///
    /// Accessor chain: inner.constraint_name() -> Option<ConstraintName>
    ///                 .and_then(|cn| cn.name())  -> Option<Name>
    ///                 .map(|n| n.text())          -> &str
    fn extract_add_constraint_fact(
        ac: &squawk_syntax::ast::AddConstraint,
    ) -> Option<AlterTableActionFact> {
        let constraint = ac.constraint()?;
        let not_valid = ac.not_valid().is_some();

        match constraint {
            Constraint::ForeignKeyConstraint(fkc) => {
                // Bug 10: constraint name lives on the inner FK node.
                let constraint_name = fkc
                    .constraint_name()
                    .and_then(|cn| cn.name())
                    .map(|n| n.text().to_string());
                let path = fkc.path()?;
                let references = Self::path_to_qualified_name(&path)?;
                let from_columns = fkc
                    .from_columns()
                    .map(|cl| Self::extract_column_list_names(cl))
                    .unwrap_or_default();
                let to_columns = fkc
                    .to_columns()
                    .map(|cl| Self::extract_column_list_names(cl))
                    .unwrap_or_default();
                Some(AlterTableActionFact::AddForeignKey {
                    constraint_name,
                    references,
                    from_columns,
                    to_columns,
                    not_valid,
                })
            }
            Constraint::CheckConstraint(_) => {
                Some(AlterTableActionFact::AddCheckConstraint { not_valid })
            }
            Constraint::UniqueConstraint(uc) => {
                // Constraint name extracted from inner node — same pattern as FK.
                let _constraint_name = uc
                    .constraint_name()
                    .and_then(|cn| cn.name())
                    .map(|n| n.text().to_string());
                Some(AlterTableActionFact::AddUniqueConstraint)
            }
            Constraint::PrimaryKeyConstraint(pkc) => {
                let _constraint_name = pkc
                    .constraint_name()
                    .and_then(|cn| cn.name())
                    .map(|n| n.text().to_string());
                Some(AlterTableActionFact::AddPrimaryKeyConstraint)
            }
            _ => None,
        }
    }

    // ── DROP TABLE ────────────────────────────────────────────────────

    fn extract_drop_table(node: &DropTable) -> Option<StatementFact> {
        let path = node.path()?;
        Some(StatementFact::DropTable {
            name: Self::path_to_qualified_name(&path)?,
            if_exists: node.if_exists().is_some(),
        })
    }

    // ── DROP INDEX ────────────────────────────────────────────────────

    fn extract_drop_index(node: &DropIndex) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node
            .paths()
            .filter_map(|p| Self::path_to_qualified_name(&p))
            .collect();

        if names.is_empty() { return None; }

        Some(StatementFact::DropIndex {
            names,
            if_exists: node.if_exists().is_some(),
            concurrently: node.concurrently_token().is_some(),
        })
    }

    // ── SET ───────────────────────────────────────────────────────────

    fn extract_set(node: &Set) -> Option<StatementFact> {
        let setting_name = node
            .path()
            .and_then(|p| p.segment())
            .and_then(|s| {
                // Bug 3: use segment_text which calls .text() directly.
                Self::segment_text(s)
            })
            .map(|t| t.to_lowercase())?;

        if setting_name != "search_path" { return None; }

        let schemas: Vec<String> = node
            .config_values()
            .filter_map(|cv| match cv {
                ConfigValue::NameRef(nr) => Some(nr.text().to_string()),
                ConfigValue::Literal(lit) => {
                    let raw = lit.syntax().text().to_string();
                    Some(raw.trim_matches('\'').trim_matches('"').to_string())
                }
            })
            .filter(|s| !s.is_empty())
            .collect();

        if schemas.is_empty() { return None; }

        Some(StatementFact::SetSearchPath { schemas })
    }

    // ── TRANSACTION ───────────────────────────────────────────────────

    fn extract_rollback(node: &Rollback) -> StatementFact {
        // Bug 3: use NameRef::text() directly.
        match node.name_ref().map(|n| n.text().to_string()) {
            Some(name) => StatementFact::RollbackToSavepoint { name },
            None       => StatementFact::RollbackTransaction,
        }
    }

    fn extract_savepoint(node: &Savepoint) -> Option<StatementFact> {
        // Bug 3: use Name::text() directly.
        let name = node.name().map(|n| n.text().to_string())?;
        Some(StatementFact::Savepoint { name })
    }

    fn extract_release_savepoint(node: &ReleaseSavepoint) -> Option<StatementFact> {
        // Bug 3: use NameRef::text() directly.
        let name = node.name_ref().map(|n| n.text().to_string())?;
        Some(StatementFact::ReleaseSavepoint { name })
    }

    // ── Path traversal helpers ────────────────────────────────────────

    fn path_to_qualified_name(path: &Path) -> Option<QualifiedName> {
        let name = Self::segment_text(path.segment()?)?;
        let schema = path
            .qualifier()
            .and_then(|q| q.segment())
            .and_then(|s| Self::segment_text(s));
        Some(QualifiedName::new(schema, name))
    }

    /// Extract the identifier text from a PathSegment.
    ///
    /// Bug 3: PathSegment is generated-only (no manual impl).
    /// name_ref() → Option<NameRef> and name() → Option<Name> both expose
    /// .text() directly — no .ident_token() indirection needed.
    ///
    /// name_ref() covers reference sites (most path segments in SQL statements).
    /// name() covers definition sites (CREATE TABLE name, CREATE INDEX name, etc.).
    /// We try name_ref() first (more common), then name().
    fn segment_text(segment: PathSegment) -> Option<String> {
        segment
            .name_ref()
            .map(|n| n.text().to_string())
            .or_else(|| segment.name().map(|n| n.text().to_string()))
    }
}
