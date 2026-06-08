use crate::analysis::expr_ir::ExprIr;
use crate::analysis::expr_visitor::ExprVisitor;
use crate::analysis::facts::{AlterTableActionFact, ColumnFact, FkFact, StatementFact};
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
            Stmt::CreateTable(node)    => Self::extract_create_table(node),
            Stmt::CreateTableAs(node)  => Self::extract_create_table_as(node),
            Stmt::CreateView(node)     => Self::extract_create_view(node),
            Stmt::CreateIndex(node)    => Self::extract_create_index(node),
            Stmt::AlterTable(node)     => Self::extract_alter_table(node),
            Stmt::DropTable(node)      => Self::extract_drop_table(node),
            Stmt::DropIndex(node)      => Self::extract_drop_index(node),
            Stmt::Set(node)            => Self::extract_set(node),
            Stmt::Begin(_)             => Some(StatementFact::BeginTransaction),
            Stmt::Commit(_)            => Some(StatementFact::CommitTransaction),
            // Rollback: plain ROLLBACK vs ROLLBACK TO SAVEPOINT name
            Stmt::Rollback(node)       => Some(Self::extract_rollback(node)),
            Stmt::Savepoint(node)      => Self::extract_savepoint(node),
            Stmt::ReleaseSavepoint(node) => Self::extract_release_savepoint(node),
            Stmt::Do(_)                => Some(StatementFact::OpaqueBlock),
            Stmt::Execute(_)           => Some(StatementFact::Execute),
            _                          => None,
        }
    }

    // ── CREATE TABLE ──────────────────────────────────────────────────

    fn extract_create_table(node: &CreateTable) -> Option<StatementFact> {
        let path = node.path()?;
        let name = Self::path_to_qualified_name(&path)?;
        let if_not_exists = node.if_not_exists().is_some();

        let (columns, foreign_keys) = node
            .table_arg_list()
            .map(|tal| Self::extract_table_body(tal.args()))
            .unwrap_or_default();

        Some(StatementFact::CreateTable { name, if_not_exists, columns, foreign_keys })
    }

    fn extract_create_table_as(node: &CreateTableAs) -> Option<StatementFact> {
        let path = node.path()?;
        Some(StatementFact::CreateTable {
            name: Self::path_to_qualified_name(&path)?,
            if_not_exists: node.if_not_exists().is_some(),
            columns: Vec::new(),
            foreign_keys: Vec::new(),
        })
    }

    // ── Table body extraction ─────────────────────────────────────────

    fn extract_table_body(
        args: impl Iterator<Item = TableArg>,
    ) -> (Vec<ColumnFact>, Vec<FkFact>) {
        let mut columns = Vec::new();
        let mut foreign_keys = Vec::new();

        for arg in args {
            match arg {
                TableArg::Column(col) => {
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
                }
                TableArg::LikeClause(_) => {}
            }
        }

        (columns, foreign_keys)
    }

    fn extract_column_fact(col: &Column) -> Option<ColumnFact> {
        let name = col
            .name()
            .and_then(|n| n.ident_token())
            .map(|t| t.text().to_string())?;

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
                // Extract default expression via ExprVisitor.
                // DefaultConstraint::expr() → Option<Expr> → ExprIr
                ColumnConstraint::DefaultConstraint(dc) => {
                    default = dc.expr().map(ExprVisitor::convert);
                }
                _ => {}
            }
        }

        Some(ColumnFact { name, ty, not_null, is_primary_key, default })
    }

    fn extract_column_fk_facts(col: &Column) -> Vec<FkFact> {
        let mut facts = Vec::new();
        for constraint in col.constraints() {
            if let ColumnConstraint::ReferencesConstraint(rc) = constraint {
                if let Some(path) = rc.table() {
                    if let Some(references) = Self::path_to_qualified_name(&path) {
                        // Column-level FK: no column list accessors available.
                        facts.push(FkFact {
                            references,
                            from_columns: Vec::new(),
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

            // Handwritten extensions: from_columns() and to_columns()
            // Both return Option<ColumnList> → AstChildren<Column> → name_ref()
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

    /// Extract column names from a ColumnList node.
    /// Each Column inside uses name_ref() (reference site).
    fn extract_column_list_names(cl: squawk_syntax::ast::ColumnList) -> Vec<String> {
        cl.columns()
            .filter_map(|col| {
                col.name_ref()
                    .and_then(|n| n.ident_token())
                    .map(|t| t.text().to_string())
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
        let index_name_str = node
            .name()?
            .ident_token()?
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
                    if let Some(name) = add.name().and_then(|n| n.ident_token()).map(|t| t.text().to_string()) {
                        // Extract default from column constraints on the ADD COLUMN node.
                        // AddColumn::constraints() returns AstChildren<Constraint> (table-level
                        // Constraint enum), not AstChildren<ColumnConstraint>.
                        let default = add.constraints()
                            .filter_map(|c| {
                                if let Constraint::DefaultConstraint(dc) = c {
                                    dc.expr().map(ExprVisitor::convert)
                                } else {
                                    None
                                }
                            })
                            .next();

                        actions.push(AlterTableActionFact::AddColumn {
                            name,
                            ty: add.ty().map(|t| t.syntax().text().to_string()),
                            if_not_exists: add.if_not_exists().is_some(),
                            default,
                        });
                    }
                }

                AlterTableAction::DropColumn(drop) => {
                    if let Some(name) = drop.name_ref().and_then(|n| n.ident_token()).map(|t| t.text().to_string()) {
                        actions.push(AlterTableActionFact::DropColumn {
                            name,
                            if_exists: drop.if_exists().is_some(),
                        });
                    }
                }

                // RENAME COLUMN old TO new
                // Uses handwritten from() / to() accessors.
                AlterTableAction::RenameColumn(rc) => {
                    let from = rc.from().and_then(|n| n.ident_token()).map(|t| t.text().to_string());
                    let to   = rc.to().and_then(|n| n.ident_token()).map(|t| t.text().to_string());
                    if let (Some(from), Some(to)) = (from, to) {
                        actions.push(AlterTableActionFact::RenameColumn { from, to });
                    }
                }

                // RENAME TO new_table_name
                // Old name comes from the enclosing AlterTable::relation_name()
                // which we already extracted as table_name above.
                AlterTableAction::RenameTo(rt) => {
                    if let Some(new_name) = rt.name().and_then(|n| n.ident_token()).map(|t| t.text().to_string()) {
                        actions.push(AlterTableActionFact::RenameTo { new_name });
                    }
                }

                // ADD CONSTRAINT — handle FK only; other constraint types deferred.
                AlterTableAction::AddConstraint(ac) => {
                    if let Some(fact) = Self::extract_add_constraint_fact(&ac) {
                        actions.push(fact);
                    }
                }

                // ALTER COLUMN — dispatch on AlterColumnOption variant
                AlterTableAction::AlterColumn(alter_col) => {
                    let col_name = match alter_col.name_ref().and_then(|n| n.ident_token()) {
                        Some(t) => t.text().to_string(),
                        None => continue,
                    };
                    if let Some(opt) = alter_col.option() {
                        if let Some(fact) = Self::extract_alter_column_option(col_name, opt) {
                            actions.push(fact);
                        }
                    }
                }

                // VALIDATE CONSTRAINT constraint_name
                // Clears pending NOT VALID entries from state.
                AlterTableAction::ValidateConstraint(vc) => {
                    if let Some(constraint_name) = vc.name_ref()
                        .and_then(|n| n.ident_token())
                        .map(|t| t.text().to_string())
                    {
                        actions.push(AlterTableActionFact::ValidateConstraint { constraint_name });
                    }
                }

                _ => {}
            }
        }

        Some(StatementFact::AlterTable { name: table_name, actions })
    }

    /// Dispatch on AlterColumnOption variants we care about.
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
            // SetDefault — wire ExprVisitor to extract the default expression.
            AlterColumnOption::SetDefault(sd) => {
                let default = sd.expr().map(ExprVisitor::convert);
                Some(AlterTableActionFact::SetDefault { column: col_name, default })
            }
            // AddGenerated, DropDefault, SetCompression, etc. — deferred.
            _ => None,
        }
    }

    /// Extract an AddForeignKey fact from an AddConstraint action.
    /// Returns None for non-FK constraints (CHECK, UNIQUE, PK — deferred).
    fn extract_add_constraint_fact(
        ac: &squawk_syntax::ast::AddConstraint,
    ) -> Option<AlterTableActionFact> {
        let constraint = ac.constraint()?;

        if let Constraint::ForeignKeyConstraint(fkc) = constraint {
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
                references,
                from_columns,
                to_columns,
                not_valid: ac.not_valid().is_some(),
            })
        } else {
            None
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
        })
    }

    // ── SET ───────────────────────────────────────────────────────────

    fn extract_set(node: &Set) -> Option<StatementFact> {
        let setting_name = node
            .path()
            .and_then(|p| p.segment())
            .and_then(|s| {
                s.name_ref()
                    .and_then(|n| n.ident_token())
                    .or_else(|| s.name().and_then(|n| n.ident_token()))
            })
            .map(|t| t.text().to_string().to_lowercase())?;

        if setting_name != "search_path" { return None; }

        let schemas: Vec<String> = node
            .config_values()
            .filter_map(|cv| match cv {
                ConfigValue::NameRef(nr) => nr.ident_token().map(|t| t.text().to_string()),
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

    /// ROLLBACK vs ROLLBACK TO SAVEPOINT name.
    /// Rollback::name_ref() is Some only for ROLLBACK TO SAVEPOINT.
    fn extract_rollback(node: &Rollback) -> StatementFact {
        match node.name_ref().and_then(|n| n.ident_token()).map(|t| t.text().to_string()) {
            Some(name) => StatementFact::RollbackToSavepoint { name },
            None       => StatementFact::RollbackTransaction,
        }
    }

    fn extract_savepoint(node: &Savepoint) -> Option<StatementFact> {
        let name = node
            .name()
            .and_then(|n| n.ident_token())
            .map(|t| t.text().to_string())?;
        Some(StatementFact::Savepoint { name })
    }

    /// RELEASE SAVEPOINT name — uses name_ref() not name().
    fn extract_release_savepoint(node: &ReleaseSavepoint) -> Option<StatementFact> {
        let name = node
            .name_ref()
            .and_then(|n| n.ident_token())
            .map(|t| t.text().to_string())?;
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

    fn segment_text(segment: PathSegment) -> Option<String> {
        segment
            .name_ref()
            .and_then(|n| n.ident_token())
            .or_else(|| segment.name().and_then(|n| n.ident_token()))
            .map(|t| t.text().to_string())
    }
}
