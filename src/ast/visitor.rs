use crate::analysis::facts::{AlterTableActionFact, StatementFact};
use crate::ast::identifiers::QualifiedName;
use squawk_syntax::ast::{
    AstNode, AlterTable, AlterTableAction, ConfigValue, CreateIndex, CreateTable,
    CreateTableAs, CreateView, DropIndex, DropTable, Path, PathSegment,
    Savepoint, Set, Stmt,
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
        Some(StatementFact::CreateTable {
            name: Self::path_to_qualified_name(&path)?,
            if_not_exists: node.if_not_exists().is_some(),
        })
    }

    /// CREATE TABLE AS — treated as a plain CreateTable fact.
    /// The query body is not analysed yet; we register the table identity only.
    fn extract_create_table_as(node: &CreateTableAs) -> Option<StatementFact> {
        let path = node.path()?;
        Some(StatementFact::CreateTable {
            name: Self::path_to_qualified_name(&path)?,
            if_not_exists: node.if_not_exists().is_some(),
        })
    }

    // ── CREATE VIEW ───────────────────────────────────────────────────

    /// FIX C9: was emitting StatementFact::CreateTable — now correctly
    /// emits StatementFact::CreateView so the resolver inserts a ViewEdge.
    fn extract_create_view(node: &CreateView) -> Option<StatementFact> {
        let path = node.path()?;
        Some(StatementFact::CreateView {
            name: Self::path_to_qualified_name(&path)?,
            or_replace: node.or_replace().is_some(),
        })
    }

    // ── CREATE INDEX ──────────────────────────────────────────────────

    /// FIX C4: index name comes from name() not path().
    /// name() returns Option<Name>; extract via ident_token().
    fn extract_create_index(node: &CreateIndex) -> Option<StatementFact> {
        // Index name: Name node → ident_token → text
        let index_name_str = node
            .name()?
            .ident_token()?
            .text()
            .to_string();

        // Parent table: relation_name() → RelationName → path() → Path
        let relation_path = node.relation_name()?.path()?;

        Some(StatementFact::CreateIndex {
            name: QualifiedName::new(None, index_name_str),
            relation: Self::path_to_qualified_name(&relation_path)?,
            if_not_exists: node.if_not_exists().is_some(),
        })
    }

    // ── ALTER TABLE ───────────────────────────────────────────────────

    /// FIX C2+C5: use relation_name() singular; dispatch actions via
    /// typed AlterTableAction enum variants, not text search.
    fn extract_alter_table(node: &AlterTable) -> Option<StatementFact> {
        // FIX C3: relation_name() singular → RelationName → path()
        let path = node.relation_name()?.path()?;

        let mut actions = Vec::new();

        for action in node.actions() {
            match action {
                // FIX C5: typed cast — AddColumn::name() + ty() + if_not_exists()
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

                // FIX C5: typed cast — DropColumn::name_ref() not name()
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

                // All other AlterTableAction variants (RLS, triggers, rename,
                // tablespace, etc.) are not yet simulated. Ignored for now.
                _ => {}
            }
        }

        Some(StatementFact::AlterTable {
            name: Self::path_to_qualified_name(&path)?,
            actions,
        })
    }

    // ── DROP TABLE ────────────────────────────────────────────────────

    /// FIX C2: DropTable::path() is direct — no relation_names() step.
    fn extract_drop_table(node: &DropTable) -> Option<StatementFact> {
        let path = node.path()?;
        Some(StatementFact::DropTable {
            name: Self::path_to_qualified_name(&path)?,
            if_exists: node.if_exists().is_some(),
        })
    }

    // ── DROP INDEX ────────────────────────────────────────────────────

    /// FIX C7: DropIndex::paths() is plural — one statement can drop
    /// multiple indexes. We emit a single DropIndex fact with a Vec.
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

    /// FIX C6: use path() to check the setting name, config_values()
    /// to extract the schema list — not raw syntax text scanning.
    fn extract_set(node: &Set) -> Option<StatementFact> {
        // Check the setting name via path() → segment → name_ref → ident
        let setting_name = node
            .path()
            .and_then(|p| p.segment())
            .and_then(|s| {
                // PathSegment can expose either name() or name_ref()
                s.name_ref()
                    .and_then(|n| n.ident_token())
                    .or_else(|| s.name().and_then(|n| n.ident_token()))
            })
            .map(|t| t.text().to_string().to_lowercase())?;

        if setting_name != "search_path" {
            return None;
        }

        // Extract schemas from config_values() iterator.
        // Each ConfigValue is either a Literal (quoted string) or a NameRef
        // (unquoted identifier). Strip outer quotes from literals.
        let schemas: Vec<String> = node
            .config_values()
            .filter_map(|cv| match cv {
                ConfigValue::NameRef(nr) => {
                    nr.ident_token().map(|t| t.text().to_string())
                }
                ConfigValue::Literal(lit) => {
                    // Raw text includes surrounding quotes: 'public' → public
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
        // squawk exposes the savepoint name via name(), not name_ref().
        let name = node
            .name()
            .and_then(|n| n.ident_token())
            .map(|t| t.text().to_string())?;

        Some(StatementFact::Savepoint { name })
    }

    // ── Path traversal helper ─────────────────────────────────────────

    /// FIX C1: Path is a linked list, not a flat names() iterator.
    ///
    /// Structure for `public.users`:
    ///   Path {
    ///     qualifier: Some(Path { segment: PathSegment("public") }),
    ///     segment: PathSegment("users"),
    ///   }
    ///
    /// PathSegment exposes both name() (for definitions) and name_ref()
    /// (for references). We try name_ref() first since most references
    /// in ALTER/DROP are references, then fall back to name() for
    /// CREATE definitions where the segment is a new name.
    fn path_to_qualified_name(path: &Path) -> Option<QualifiedName> {
        let name = Self::segment_text(path.segment()?)?;

        let schema = path
            .qualifier()
            .and_then(|q| q.segment())
            .and_then(|s| Self::segment_text(s));

        Some(QualifiedName::new(schema, name))
    }

    /// Extract the text from a PathSegment, trying name_ref() first
    /// (references), then name() (definitions).
    fn segment_text(segment: PathSegment) -> Option<String> {
        segment
            .name_ref()
            .and_then(|n| n.ident_token())
            .or_else(|| segment.name().and_then(|n| n.ident_token()))
            .map(|t| t.text().to_string())
    }
}
