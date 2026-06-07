use crate::analysis::facts::{AlterTableActionFact, ColumnFact, FkFact, StatementFact};
use crate::ast::identifiers::QualifiedName;
use squawk_syntax::ast::{
    AstNode, AlterTable, AlterTableAction, Column, ColumnConstraint, ConfigValue, CreateIndex,
    CreateTable, CreateTableAs, CreateView, DropIndex, DropTable, Path, PathSegment,
    Savepoint, Set, Stmt, TableArg, TableConstraint,
};

pub struct AstVisitor;

impl AstVisitor {
    /// Top-level dispatch. Returns `None` for statements we do not
    /// need to simulate (e.g. GRANT, COMMENT ON, ANALYZE, etc.).
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
            Stmt::Rollback(_)          => Some(StatementFact::RollbackTransaction),
            Stmt::Savepoint(node)      => Self::extract_savepoint(node),
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

        // Extract columns and FK facts from the table body.
        // table_arg_list() returns None for tables with no body (rare but
        // possible with LIKE clauses only). Both vecs default to empty.
        let (columns, foreign_keys) = node
            .table_arg_list()
            .map(|tal| Self::extract_table_body(tal.args()))
            .unwrap_or_default();

        Some(StatementFact::CreateTable {
            name,
            if_not_exists,
            columns,
            foreign_keys,
        })
    }

    /// CREATE TABLE AS — no table body, so columns and foreign_keys are empty.
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

    /// Iterates TableArg children and extracts columns and FK facts.
    /// Returns (Vec<ColumnFact>, Vec<FkFact>).
    fn extract_table_body(
        args: impl Iterator<Item = TableArg>,
    ) -> (Vec<ColumnFact>, Vec<FkFact>) {
        let mut columns = Vec::new();
        let mut foreign_keys = Vec::new();

        for arg in args {
            match arg {
                // Column node — extract name, type, and per-column constraints.
                TableArg::Column(col) => {
                    if let Some(fact) = Self::extract_column_fact(&col) {
                        // Also collect column-level FK (ReferencesConstraint)
                        // from the column's constraint list.
                        for fk in Self::extract_column_fk_facts(&col) {
                            foreign_keys.push(fk);
                        }
                        columns.push(fact);
                    }
                }

                // Table-level constraint — look for ForeignKeyConstraint.
                TableArg::TableConstraint(tc) => {
                    if let Some(fk) = Self::extract_table_fk_fact(&tc) {
                        foreign_keys.push(fk);
                    }
                }

                // LIKE clause — not relevant for schema simulation.
                TableArg::LikeClause(_) => {}
            }
        }

        (columns, foreign_keys)
    }

    /// Extract a ColumnFact from a Column node.
    /// name() → Name → ident_token()
    /// ty()   → Type → syntax().text()  [requires AstNode in scope]
    fn extract_column_fact(col: &Column) -> Option<ColumnFact> {
        // Column name — always from name(), not name_ref() (definition site).
        let name = col
            .name()
            .and_then(|n| n.ident_token())
            .map(|t| t.text().to_string())?;

        // Data type — AstNode::syntax() gives us the raw text.
        let ty = col
            .ty()
            .map(|t| t.syntax().text().to_string());

        // Scan per-column constraints for NOT NULL and PRIMARY KEY.
        let mut not_null = false;
        let mut is_primary_key = false;

        for constraint in col.constraints() {
            match constraint {
                ColumnConstraint::NotNullConstraint(_) => not_null = true,
                ColumnConstraint::PrimaryKeyConstraint(_) => {
                    is_primary_key = true;
                    // PRIMARY KEY implies NOT NULL in PostgreSQL.
                    not_null = true;
                }
                // DefaultConstraint, UniqueConstraint, CheckConstraint,
                // ReferencesConstraint — handled separately or deferred.
                _ => {}
            }
        }

        Some(ColumnFact { name, ty, not_null, is_primary_key })
    }

    /// Extract FK facts from a column's ReferencesConstraint.
    /// A column can have at most one REFERENCES clause in valid SQL,
    /// but we return a Vec for uniformity with the table-level path.
    fn extract_column_fk_facts(col: &Column) -> Vec<FkFact> {
        let mut facts = Vec::new();

        for constraint in col.constraints() {
            if let ColumnConstraint::ReferencesConstraint(rc) = constraint {
                // ReferencesConstraint::table() → Option<Path>
                if let Some(path) = rc.table() {
                    if let Some(references) = Self::path_to_qualified_name(&path) {
                        facts.push(FkFact { references });
                    }
                }
            }
        }

        facts
    }

    /// Extract an FK fact from a table-level TableConstraint.
    /// Only ForeignKeyConstraint carries a target table path.
    fn extract_table_fk_fact(tc: &TableConstraint) -> Option<FkFact> {
        if let TableConstraint::ForeignKeyConstraint(fkc) = tc {
            // ForeignKeyConstraint::path() → Option<Path> (the target table)
            let path = fkc.path()?;
            let references = Self::path_to_qualified_name(&path)?;
            Some(FkFact { references })
        } else {
            None
        }
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
            // concurrently_token() is Some if CONCURRENTLY was present.
            concurrently: node.concurrently_token().is_some(),
        })
    }

    // ── ALTER TABLE ───────────────────────────────────────────────────

    fn extract_alter_table(node: &AlterTable) -> Option<StatementFact> {
        let path = node.relation_name()?.path()?;

        let mut actions = Vec::new();

        for action in node.actions() {
            match action {
                AlterTableAction::AddColumn(add) => {
                    let col_name = add
                        .name()
                        .and_then(|n| n.ident_token())
                        .map(|t| t.text().to_string());

                    if let Some(name) = col_name {
                        let ty = add
                            .ty()
                            .map(|t| t.syntax().text().to_string());

                        actions.push(AlterTableActionFact::AddColumn {
                            name,
                            ty,
                            if_not_exists: add.if_not_exists().is_some(),
                        });
                    }
                }

                AlterTableAction::DropColumn(drop) => {
                    let col_name = drop
                        .name_ref()
                        .and_then(|n| n.ident_token())
                        .map(|t| t.text().to_string());

                    if let Some(name) = col_name {
                        actions.push(AlterTableActionFact::DropColumn {
                            name,
                            if_exists: drop.if_exists().is_some(),
                        });
                    }
                }

                _ => {}
            }
        }

        Some(StatementFact::AlterTable {
            name: Self::path_to_qualified_name(&path)?,
            actions,
        })
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

        if names.is_empty() {
            return None;
        }

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

        if setting_name != "search_path" {
            return None;
        }

        let schemas: Vec<String> = node
            .config_values()
            .filter_map(|cv| match cv {
                ConfigValue::NameRef(nr) => {
                    nr.ident_token().map(|t| t.text().to_string())
                }
                ConfigValue::Literal(lit) => {
                    let raw = lit.syntax().text().to_string();
                    Some(raw.trim_matches('\'').trim_matches('"').to_string())
                }
            })
            .filter(|s| !s.is_empty())
            .collect();

        if schemas.is_empty() {
            return None;
        }

        Some(StatementFact::SetSearchPath { schemas })
    }

    // ── SAVEPOINT ─────────────────────────────────────────────────────

    fn extract_savepoint(node: &Savepoint) -> Option<StatementFact> {
        let name = node
            .name()
            .and_then(|n| n.ident_token())
            .map(|t| t.text().to_string())?;

        Some(StatementFact::Savepoint { name })
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
