// FILE: src/ast/visitor.rs
use crate::analysis::facts::{
    AlterTableActionFact, ColumnFact, FkFact, StatementFact, TableConstraintFact, PersistenceFact,
    AlterIndexActionFact, AlterTypeActionFact, CreateTypeFact, AlterTypeFact
};
use crate::ast::identifiers::{Ident, QualifiedName};
use squawk_syntax::ast::{
    self, AstNode, AlterColumnOption, AlterTable, AlterTableAction, Column, ColumnConstraint,
    Constraint, CreateIndex, CreateTable, CreateTableAs, CreateView, DropIndex,
    DropTable, Path, PathSegment, Stmt, TableArg, TableConstraint,
    CreateSequence, AlterSequence, DropSequence, CreateMaterializedView,
    DropView, DropMaterializedView, AlterIndex, UsingMethod, WhereClause, RenameTo,
    AttachPartition, DetachPartition, AlterConstraint, Set, Rollback, Savepoint, ReleaseSavepoint,
    CreateType, AlterType, CreateDomain, AlterDomain, DropDomain, CreatePolicy, DropPolicy,
    CreateTrigger, DropTrigger, AddValue, Name, NameRef
};

pub struct AstVisitor;

impl AstVisitor {
    /// Safely resolves and trims an unquoted/quoted Name into a string
    /// following Postgres casing rules
    fn resolve_name(n: Name) -> String {
        Ident::new(n.text().to_string().trim_matches('"').to_string(), n.is_quoted()).resolve()
    }

    /// Safely resolves and trims an unquoted/quoted NameRef into a string
    /// following Postgres casing rules
    fn resolve_name_ref(nr: NameRef) -> String {
        Ident::new(nr.text().to_string().trim_matches('"').to_string(), nr.is_quoted()).resolve()
    }

    pub fn extract(stmt: &Stmt) -> Option<StatementFact> {
        let syntax = stmt.syntax();
        match stmt {
            Stmt::CreateTable(node)            => return Self::extract_create_table(node),
            Stmt::CreateTableAs(node)          => return Self::extract_create_table_as(node),
            Stmt::CreateView(node)             => return Self::extract_create_view(node),
            Stmt::CreateMaterializedView(node) => return Self::extract_create_materialized_view(node),
            Stmt::CreateIndex(node)            => return Self::extract_create_index(node),
            Stmt::AlterTable(node)             => return Self::extract_alter_table(node),
            Stmt::AlterIndex(node)             => return Self::extract_alter_index(node),
            Stmt::DropTable(node)              => return Self::extract_drop_table(node),
            Stmt::DropView(node)               => return Self::extract_drop_view(node),
            Stmt::DropMaterializedView(node)   => return Self::extract_drop_materialized_view(node),
            Stmt::DropIndex(node)              => return Self::extract_drop_index(node),
            Stmt::Set(node)                    => return Self::extract_set(node),
            Stmt::Begin(_)                     => return Some(StatementFact::BeginTransaction),
            Stmt::Commit(_)                    => return Some(StatementFact::CommitTransaction),
            Stmt::Rollback(node)               => return Some(Self::extract_rollback(node)),
            Stmt::Savepoint(node)              => return Some(Self::extract_savepoint(node)),
            Stmt::ReleaseSavepoint(node)       => return Some(Self::extract_release_savepoint(node)),
            Stmt::Vacuum(node)                 => return Some(StatementFact::Vacuum { is_full: node.is_full() }),
            _ => {}
        }

        // Dynamically Cast Syntax Nodes for unsupported edge cases
        if let Some(node) = CreateSequence::cast(syntax.clone()) { return Self::extract_create_sequence(&node); }
        if let Some(node) = AlterSequence::cast(syntax.clone()) { return Self::extract_alter_sequence(&node); }
        if let Some(node) = DropSequence::cast(syntax.clone()) { return Self::extract_drop_sequence(&node); }
        if let Some(node) = CreateType::cast(syntax.clone()) { return Self::extract_create_type(&node); }
        if let Some(node) = AlterType::cast(syntax.clone()) { return Self::extract_alter_type(&node); }
        if let Some(node) = CreateDomain::cast(syntax.clone()) { return Self::extract_create_domain(&node); }
        if let Some(node) = AlterDomain::cast(syntax.clone()) { return Self::extract_alter_domain(&node); }
        if let Some(node) = DropDomain::cast(syntax.clone()) { return Self::extract_drop_domain(&node); }
        if let Some(node) = CreatePolicy::cast(syntax.clone()) { return Self::extract_create_policy(&node); }
        if let Some(node) = DropPolicy::cast(syntax.clone()) { return Self::extract_drop_policy(&node); }
        if let Some(node) = CreateTrigger::cast(syntax.clone()) { return Self::extract_create_trigger(&node); }
        if let Some(node) = DropTrigger::cast(syntax.clone()) { return Self::extract_drop_trigger(&node); }

        // Absolute Fallbacks for dynamic blocks and mat-view refreshes
        let text = syntax.text().to_string();
        let upper = text.to_uppercase();

        if upper.starts_with("REFRESH MATERIALIZED VIEW") {
            let concurrently = upper.contains("CONCURRENTLY");
            let clean_name = text.split_whitespace().last().unwrap_or("").trim_matches(';');
            return Some(StatementFact::RefreshMaterializedView {
                name: QualifiedName::new(None, Ident::new(clean_name.to_string(), false)),
                concurrently
            });
        }

        if upper.starts_with("DO ") { return Some(StatementFact::OpaqueBlock); }
        if upper.starts_with("EXECUTE ") { return Some(StatementFact::Execute); }

        None
    }

    // ─────────────────────────────────────────────
    // Table Extractors
    // ─────────────────────────────────────────────

    fn extract_create_table(node: &CreateTable) -> Option<StatementFact> {
        let path = node.syntax().descendants().find_map(Path::cast)?;
        let name = Self::path_to_qualified_name(&path)?;

        let persistence = match node.persistence().map(|p| p.syntax().text().to_string().to_lowercase()).as_deref() {
            Some("temporary") | Some("temp") => PersistenceFact::Temporary,
            Some("unlogged") => PersistenceFact::Unlogged,
            _ => PersistenceFact::Permanent,
        };
        let (columns, foreign_keys, table_constraints) = node
            .table_arg_list()
            .map(|tal| Self::extract_table_body(tal.args()))
            .unwrap_or_else(|| (Vec::new(), Vec::new(), Vec::new()));
        Some(StatementFact::CreateTable {
            name,
            if_not_exists: node.if_not_exists().is_some(),
            as_select: false,
            persistence,
            columns,
            foreign_keys,
            table_constraints,
        })
    }

    fn extract_create_table_as(node: &CreateTableAs) -> Option<StatementFact> {
        let path = node.syntax().descendants().find_map(Path::cast)?;
        let persistence = match node.persistence().map(|p| p.syntax().text().to_string().to_lowercase()).as_deref() {
            Some("temporary") | Some("temp") => PersistenceFact::Temporary,
            Some("unlogged") => PersistenceFact::Unlogged,
            _ => PersistenceFact::Permanent,
        };
        Some(StatementFact::CreateTable {
            name: Self::path_to_qualified_name(&path)?,
            if_not_exists: node.if_not_exists().is_some(),
            as_select: true,
            persistence,
            columns: Vec::new(),
            foreign_keys: Vec::new(),
            table_constraints: Vec::new(),
        })
    }

    fn extract_drop_table(node: &DropTable) -> Option<StatementFact> {
        let path = node.syntax().descendants().find_map(Path::cast)?;
        Some(StatementFact::DropTable {
            name: Self::path_to_qualified_name(&path)?,
            if_exists: node.if_exists().is_some(),
            cascade: node.cascade_token().is_some(),
        })
    }

    fn extract_alter_table(node: &AlterTable) -> Option<StatementFact> {
        let path = node.syntax().descendants().find_map(Path::cast)?;
        let table_name = Self::path_to_qualified_name(&path)?;
        let mut actions = Vec::new();

        for action in node.actions() {
            if let Some(ap) = AttachPartition::cast(action.syntax().clone()) {
                if let Some(child_path) = ap.syntax().descendants().find_map(Path::cast) {
                    if let Some(child) = Self::path_to_qualified_name(&child_path) {
                        actions.push(AlterTableActionFact::AttachPartition { child });
                    }
                }
                continue;
            }
            if let Some(dp) = DetachPartition::cast(action.syntax().clone()) {
                if let Some(child_path) = dp.syntax().descendants().find_map(Path::cast) {
                    if let Some(child) = Self::path_to_qualified_name(&child_path) {
                        actions.push(AlterTableActionFact::DetachPartition { child });
                    }
                }
                continue;
            }
            if let Some(ac) = AlterConstraint::cast(action.syntax().clone()) {
                if let Some(name_ref) = ac.syntax().descendants().find_map(NameRef::cast) {
                    let name = Self::resolve_name_ref(name_ref);
                    let deferrable = ac.syntax().text().to_string().to_lowercase().contains("deferrable");
                    actions.push(AlterTableActionFact::AlterConstraint { name, deferrable });
                }
                continue;
            }

            match action {
                AlterTableAction::AddColumn(add) => {
                    if let Some(name) = add.name().map(Self::resolve_name) {
                        let mut not_null = false;
                        let mut default = None;
                        for c in add.constraints() {
                            match c {
                                Constraint::NotNullConstraint(_) => not_null = true,
                                Constraint::PrimaryKeyConstraint(_) => not_null = true,
                                Constraint::DefaultConstraint(dc) => default = dc.expr().map(crate::analysis::expr_visitor::ExprVisitor::convert),
                                _ => {}
                            }
                        }
                        actions.push(AlterTableActionFact::AddColumn { name, ty: add.ty().map(|t| t.syntax().text().to_string()), if_not_exists: add.if_not_exists().is_some(), not_null, default });
                    }
                }
                AlterTableAction::DropColumn(drop) => {
                    if let Some(name) = drop.name_ref().map(Self::resolve_name_ref) {
                        actions.push(AlterTableActionFact::DropColumn { name, if_exists: drop.if_exists().is_some() });
                    }
                }
                AlterTableAction::RenameColumn(rc) => {
                    let from_ident = rc.from().map(|nr| Ident::new(nr.text().to_string().trim_matches('"').to_string(), nr.is_quoted()))
                        .or_else(|| rc.syntax().descendants().find_map(NameRef::cast).map(|nr| Ident::new(nr.text().to_string().trim_matches('"').to_string(), nr.is_quoted())));

                    let to_ident = rc.to().map(|nr| Ident::new(nr.text().to_string().trim_matches('"').to_string(), nr.is_quoted()))
                        .or_else(|| rc.syntax().descendants().find_map(Name::cast).map(|n| Ident::new(n.text().to_string().trim_matches('"').to_string(), n.is_quoted())));

                    if let (Some(from), Some(to)) = (from_ident, to_ident) {
                        actions.push(AlterTableActionFact::RenameColumn { from, to });
                    }
                }
                AlterTableAction::RenameTo(rt) => {
                    if let Some(new_name) = rt.name() {
                        actions.push(AlterTableActionFact::RenameTo {
                            new_name: Ident::new(new_name.text().to_string().trim_matches('"').to_string(), new_name.is_quoted())
                        });
                    }
                }
                AlterTableAction::AddConstraint(ac) => {
                    if let Some(fact) = Self::extract_add_constraint_fact(&ac) { actions.push(fact); }
                }
                AlterTableAction::DropConstraint(dc) => {
                    if let Some(name) = dc.name_ref().map(Self::resolve_name_ref) {
                        actions.push(AlterTableActionFact::DropConstraint { name });
                    }
                }
                AlterTableAction::AlterColumn(alter_col) => {
                    if let Some(nr) = alter_col.name_ref() {
                        let col_name = Self::resolve_name_ref(nr);
                        if let Some(opt) = alter_col.option() {
                            if let Some(fact) = Self::extract_alter_column_option(col_name, opt) { actions.push(fact); }
                        }
                    }
                }
                AlterTableAction::ValidateConstraint(vc) => {
                    if let Some(constraint_name) = vc.syntax().descendants().find_map(NameRef::cast).map(Self::resolve_name_ref) {
                        actions.push(AlterTableActionFact::ValidateConstraint { constraint_name });
                    }
                }
                _ => {}
            }
        }
        Some(StatementFact::AlterTable { name: table_name, actions })
    }

    fn extract_table_body(args: impl Iterator<Item = TableArg>) -> (Vec<ColumnFact>, Vec<FkFact>, Vec<TableConstraintFact>) {
        let mut columns = Vec::new();
        let mut foreign_keys = Vec::new();
        let mut table_constraints = Vec::new();
        for arg in args {
            match arg {
                TableArg::Column(col) => {
                    for fk in Self::extract_column_fk_facts(&col) { foreign_keys.push(fk); }
                    if let Some(fact) = Self::extract_column_fact(&col) { columns.push(fact); }
                }
                TableArg::TableConstraint(tc) => {
                    if let Some(fk) = Self::extract_table_fk_fact(&tc) { foreign_keys.push(fk); }
                    if let Some(tc_fact) = Self::extract_table_constraint_fact(&tc) { table_constraints.push(tc_fact); }
                }
                _ => {}
            }
        }
        (columns, foreign_keys, table_constraints)
    }

    fn extract_column_fact(col: &Column) -> Option<ColumnFact> {
        let name = Self::resolve_name(col.name()?);
        let ty = col.ty().map(|t| t.syntax().text().to_string());
        let not_null = col.constraints().any(|c| matches!(c, ColumnConstraint::NotNullConstraint(_)));
        let is_primary_key = col.constraints().any(|c| matches!(c, ColumnConstraint::PrimaryKeyConstraint(_)));
        let default = col.constraints().find_map(|c| if let ColumnConstraint::DefaultConstraint(dc) = c { Some(crate::analysis::expr_visitor::ExprVisitor::convert(dc.expr()?)) } else { None });
        Some(ColumnFact { name, ty, not_null, is_primary_key, default })
    }

    fn extract_alter_column_option(col_name: String, opt: AlterColumnOption) -> Option<AlterTableActionFact> {
        let opt_text = opt.syntax().text().to_string().to_lowercase();
        if opt_text.starts_with("set storage") { return Some(AlterTableActionFact::SetStorage { column: col_name }); }

        match opt {
            AlterColumnOption::SetNotNull(_) => Some(AlterTableActionFact::SetNotNull { column: col_name }),
            AlterColumnOption::DropNotNull(_) => Some(AlterTableActionFact::DropNotNull { column: col_name }),
            AlterColumnOption::SetType(st) => {
                let has_using = st.syntax().text().to_string().to_lowercase().contains("using ");
                Some(AlterTableActionFact::SetType { 
                    column: col_name, 
                    ty: st.ty()?.syntax().text().to_string(),
                    has_using 
                })
            },
            AlterColumnOption::SetDefault(sd) => Some(AlterTableActionFact::SetDefault { column: col_name, default: sd.expr().map(crate::analysis::expr_visitor::ExprVisitor::convert) }),
            _ => None,
        }
    }

    fn extract_add_constraint_fact(ac: &squawk_syntax::ast::AddConstraint) -> Option<AlterTableActionFact> {
        let constraint = ac.constraint()?;
        let not_valid = ac.not_valid().is_some();
        match constraint {
            Constraint::ForeignKeyConstraint(fkc) => {
                let constraint_name = fkc.constraint_name().and_then(|cn| cn.name()).map(Self::resolve_name);
                let path = fkc.syntax().descendants().find_map(Path::cast)?;
                let references = Self::path_to_qualified_name(&path)?;
                Some(AlterTableActionFact::AddForeignKey {
                    constraint_name,
                    references,
                    from_columns: fkc.from_columns().map(Self::extract_column_list_names).unwrap_or_default(),
                    to_columns: fkc.to_columns().map(Self::extract_column_list_names).unwrap_or_default(),
                    not_valid,
                })
            }
            Constraint::CheckConstraint(_) => Some(AlterTableActionFact::AddCheckConstraint { not_valid }),
            Constraint::UniqueConstraint(_) => Some(AlterTableActionFact::AddUniqueConstraint),
            Constraint::PrimaryKeyConstraint(_) => Some(AlterTableActionFact::AddPrimaryKeyConstraint),
            _ => None,
        }
    }

    fn extract_table_constraint_fact(tc: &TableConstraint) -> Option<TableConstraintFact> {
        match tc {
            TableConstraint::PrimaryKeyConstraint(pkc) => Some(TableConstraintFact::PrimaryKey { columns: Self::extract_column_list_names(pkc.column_list()?) }),
            TableConstraint::UniqueConstraint(uc) => Some(TableConstraintFact::Unique { columns: Self::extract_column_list_names(uc.column_list()?) }),
            TableConstraint::CheckConstraint(_) => Some(TableConstraintFact::Check),
            _ => None,
        }
    }

    fn extract_column_fk_facts(col: &Column) -> Vec<FkFact> {
        let col_name = col.name().map(Self::resolve_name);
        col.constraints().filter_map(|c| {
            if let ColumnConstraint::ReferencesConstraint(rc) = c {
                let ref_path = rc.syntax().descendants().find_map(Path::cast)?;
                Some(FkFact {
                    constraint_name: None,
                    references: Self::path_to_qualified_name(&ref_path)?,
                    from_columns: col_name.iter().cloned().collect(),
                    to_columns: Vec::new()
                })
            } else { None }
        }).collect()
    }

    fn extract_table_fk_fact(tc: &TableConstraint) -> Option<FkFact> {
        if let TableConstraint::ForeignKeyConstraint(fkc) = tc {
            let constraint_name = fkc.constraint_name().and_then(|cn| cn.name()).map(Self::resolve_name);
            let path = fkc.syntax().descendants().find_map(Path::cast)?;
            let references = Self::path_to_qualified_name(&path)?;
            let from_columns = fkc.from_columns().map(Self::extract_column_list_names).unwrap_or_default();
            let to_columns = fkc.to_columns().map(Self::extract_column_list_names).unwrap_or_default();
            Some(FkFact { constraint_name, references, from_columns, to_columns })
        } else { None }
    }

    fn extract_column_list_names(cl: ast::ColumnList) -> Vec<String> {
        cl.columns().filter_map(|col| col.name_ref().map(Self::resolve_name_ref)).collect()
    }

    // ─────────────────────────────────────────────
    // Index Extractors
    // ─────────────────────────────────────────────

    fn extract_create_index(node: &CreateIndex) -> Option<StatementFact> {
        let name = node.syntax().descendants().find_map(Name::cast)?;
        let index_ident = Ident::new(name.text().to_string().trim_matches('"').to_string(), name.is_quoted());
        let relation_path = node.syntax().descendants().find_map(Path::cast)?;

        let using_method = node.syntax().descendants()
            .find_map(UsingMethod::cast)
            .map(|um| um.syntax().text().to_string().to_lowercase().replace("using", "").trim().to_string());
        let has_predicate = node.syntax().descendants().any(|d| WhereClause::can_cast(d.kind()));

        Some(StatementFact::CreateIndex {
            name: QualifiedName::new(None, index_ident),
            relation: Self::path_to_qualified_name(&relation_path)?,
            if_not_exists: node.if_not_exists().is_some(),
            concurrently: node.concurrently_token().is_some(),
            using_method,
            has_predicate,
        })
    }

    fn extract_alter_index(node: &AlterIndex) -> Option<StatementFact> {
        let path = node.syntax().descendants().find_map(Path::cast)?;
        let name = Self::path_to_qualified_name(&path)?;
        let mut actions = Vec::new();

        if let Some(rt) = node.syntax().descendants().find_map(RenameTo::cast) {
            if let Some(new_name) = rt.name() {
                actions.push(AlterIndexActionFact::RenameTo {
                    new_name: Ident::new(new_name.text().to_string().trim_matches('"').to_string(), new_name.is_quoted())
                });
            }
        }

        if actions.is_empty() { return None; }
        Some(StatementFact::AlterIndex { name, actions })
    }

    fn extract_drop_index(node: &DropIndex) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node.syntax().children().filter_map(Path::cast).filter_map(|p| Self::path_to_qualified_name(&p)).collect();
        if names.is_empty() { return None; }
        Some(StatementFact::DropIndex { names, if_exists: node.if_exists().is_some(), concurrently: node.concurrently_token().is_some() })
    }

    // ─────────────────────────────────────────────
    // View Extractors
    // ─────────────────────────────────────────────

    fn extract_create_view(node: &CreateView) -> Option<StatementFact> {
        let path = node.syntax().descendants().find_map(Path::cast)?;
        Some(StatementFact::CreateView {
            name: Self::path_to_qualified_name(&path)?,
            or_replace: node.syntax().text().to_string().to_lowercase().contains("or replace"),
            depends_on: Self::extract_view_dependencies(node.syntax())
        })
    }

    fn extract_create_materialized_view(node: &CreateMaterializedView) -> Option<StatementFact> {
        let path = node.syntax().descendants().find_map(Path::cast)?;
        Some(StatementFact::CreateMaterializedView {
            name: Self::path_to_qualified_name(&path)?,
            depends_on: Self::extract_view_dependencies(node.syntax())
        })
    }

    fn extract_drop_view(node: &DropView) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node.syntax().children().filter_map(Path::cast).filter_map(|p| Self::path_to_qualified_name(&p)).collect();
        if names.is_empty() { return None; }
        Some(StatementFact::DropView { names, if_exists: node.if_exists().is_some() })
    }

    fn extract_drop_materialized_view(node: &DropMaterializedView) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node.syntax().children().filter_map(Path::cast).filter_map(|p| Self::path_to_qualified_name(&p)).collect();
        if names.is_empty() { return None; }
        Some(StatementFact::DropMaterializedView { names, if_exists: node.if_exists().is_some() })
    }

    fn extract_view_dependencies(syntax: &squawk_syntax::SyntaxNode) -> Vec<QualifiedName> {
        let mut depends_on = Vec::new();
        let text = syntax.text().to_string();
        let tokens: Vec<&str> = text.split_whitespace().collect();

        let mut i = 0;
        while i < tokens.len() {
            let upper = tokens[i].to_uppercase();
            if upper == "FROM" || upper == "JOIN" {
                if i + 1 < tokens.len() {
                    let table_str = tokens[i + 1].trim_matches(';');
                    let parts: Vec<&str> = table_str.split('.').collect();
                    let is_quoted = table_str.contains('"');
                    let clean_part = |s: &str| s.trim_matches('"').to_string();
                    if parts.len() == 1 {
                        depends_on.push(QualifiedName::new(None, Ident::new(clean_part(parts[0]), is_quoted)));
                    } else if parts.len() >= 2 {
                        depends_on.push(QualifiedName::new(
                            Some(Ident::new(clean_part(parts[0]), is_quoted)),
                            Ident::new(clean_part(parts[1]), is_quoted)
                        ));
                    }
                }
            }
            i += 1;
        }
        depends_on
    }

    // ─────────────────────────────────────────────
    // Sequence Extractors
    // ─────────────────────────────────────────────

    fn extract_create_sequence(node: &CreateSequence) -> Option<StatementFact> {
        let path = node.syntax().descendants().find_map(Path::cast)?;
        let name = Self::path_to_qualified_name(&path)?;
        Some(StatementFact::CreateSequence { name, if_not_exists: node.syntax().text().to_string().to_lowercase().contains("if not exists"), owned_by: Self::extract_owned_by(node.syntax()) })
    }

    fn extract_alter_sequence(node: &AlterSequence) -> Option<StatementFact> {
        let path = node.syntax().descendants().find_map(Path::cast)?;
        let name = Self::path_to_qualified_name(&path)?;
        Some(StatementFact::AlterSequence { name, owned_by: Self::extract_owned_by(node.syntax()) })
    }

    fn extract_drop_sequence(node: &DropSequence) -> Option<StatementFact> {
        let names = node.syntax().children().filter_map(Path::cast).filter_map(|p| Self::path_to_qualified_name(&p)).collect();
        Some(StatementFact::DropSequence { names, if_exists: node.syntax().text().to_string().to_lowercase().contains("if exists") })
    }

    fn extract_owned_by(node: &squawk_syntax::SyntaxNode) -> Option<(QualifiedName, String)> {
        let text = node.text().to_string().to_lowercase();
        if let Some(idx) = text.find("owned by ") {
            let target = text[idx + 9..].split_whitespace().next()?.trim_end_matches(';');
            let parts: Vec<&str> = target.split('.').collect();
            if parts.len() == 2 {
                return Some((QualifiedName::new(None, Ident::new(parts[0].to_string(), false)), parts[1].to_string()));
            }
        }
        None
    }

    // ─────────────────────────────────────────────
    // Type & Domain Extractors
    // ─────────────────────────────────────────────

    fn extract_create_domain(node: &CreateDomain) -> Option<StatementFact> {
        let path = node.syntax().descendants().find_map(Path::cast)?;
        Some(StatementFact::CreateDomain { name: Self::path_to_qualified_name(&path)?, base_type: "<domain>".to_string() })
    }

    fn extract_alter_domain(node: &AlterDomain) -> Option<StatementFact> {
        let path = node.syntax().descendants().find_map(Path::cast)?;
        Some(StatementFact::AlterDomain { name: Self::path_to_qualified_name(&path)? })
    }

    fn extract_drop_domain(node: &DropDomain) -> Option<StatementFact> {
        let names = node.syntax().children().filter_map(Path::cast).filter_map(|p| Self::path_to_qualified_name(&p)).collect();
        Some(StatementFact::DropDomain { names, if_exists: node.syntax().text().to_string().to_lowercase().contains("if exists") })
    }

    fn extract_create_type(node: &CreateType) -> Option<StatementFact> {
        let path = node.syntax().descendants().find_map(Path::cast)?;
        Some(StatementFact::CreateType(CreateTypeFact {
            name: Self::path_to_qualified_name(&path)?,
            is_enum: node.syntax().text().to_string().to_lowercase().contains("enum"),
        }))
    }

    fn extract_alter_type(node: &AlterType) -> Option<StatementFact> {
        let path = node.syntax().descendants().find_map(Path::cast)?;
        let name = Self::path_to_qualified_name(&path)?;
        let mut actions = Vec::new();
        for child in node.syntax().children() {
            if let Some(av) = child.descendants().find_map(AddValue::cast) {
                if let Some(lit) = av.literal() {
                    actions.push(AlterTypeActionFact::AddValue { new_value: lit.syntax().text().to_string().trim_matches('\'').to_string() });
                }
            }
        }
        Some(StatementFact::AlterType(AlterTypeFact { name, actions }))
    }

    // ─────────────────────────────────────────────
    // Policy & Trigger Extractors
    // ─────────────────────────────────────────────

    fn extract_create_policy(node: &CreatePolicy) -> Option<StatementFact> {
        let name = Self::resolve_name(node.syntax().descendants().find_map(Name::cast)?);
        let path = node.syntax().descendants().find_map(Path::cast)?;
        let table = Self::path_to_qualified_name(&path)?;
        Some(StatementFact::CreatePolicy { name, table })
    }

    fn extract_drop_policy(node: &DropPolicy) -> Option<StatementFact> {
        let paths: Vec<_> = node.syntax().descendants().filter_map(Path::cast).collect();
        let table = Self::path_to_qualified_name(paths.last()?)?;
        let text = node.syntax().text().to_string();
        let name = Self::extract_name_before_on(&text)?;
        Some(StatementFact::DropPolicy { name, table, if_exists: text.to_lowercase().contains("if exists") })
    }

    fn extract_create_trigger(node: &CreateTrigger) -> Option<StatementFact> {
        let name = Self::resolve_name(node.syntax().descendants().find_map(Name::cast)?);
        let path = node.syntax().descendants().find_map(Path::cast)?;
        let table = Self::path_to_qualified_name(&path)?;
        Some(StatementFact::CreateTrigger { name, table })
    }

    fn extract_drop_trigger(node: &DropTrigger) -> Option<StatementFact> {
        let paths: Vec<_> = node.syntax().descendants().filter_map(Path::cast).collect();
        let table = Self::path_to_qualified_name(paths.last()?)?;
        let text = node.syntax().text().to_string();
        let name = Self::extract_name_before_on(&text)?;
        Some(StatementFact::DropTrigger { name, table, if_exists: text.to_lowercase().contains("if exists") })
    }

    fn extract_name_before_on(text: &str) -> Option<String> {
        let upper = text.to_uppercase();
        let on_idx = upper.find(" ON ")?;
        let before_on = &text[..on_idx];
        let raw_name = before_on.split_whitespace().last()?;
        Some(Ident::new(raw_name.trim_matches('"').to_string(), raw_name.starts_with('"')).resolve())
    }

    // ─────────────────────────────────────────────
    // Transaction & Environment Extractors
    // ─────────────────────────────────────────────

    fn extract_set(node: &Set) -> Option<StatementFact> {
        let setting_name = node.syntax().descendants().find_map(NameRef::cast)?.text().to_lowercase();
        if setting_name != "search_path" { return None; }
        let schemas: Vec<String> = node.syntax().descendants().filter_map(NameRef::cast)
            .filter(|nr| nr.text().to_lowercase() != "search_path")
            .map(Self::resolve_name_ref).collect();
        Some(StatementFact::SetSearchPath { schemas })
    }

    fn extract_rollback(node: &Rollback) -> StatementFact {
        match node.name_ref().map(|n| n.text().to_string()) {
            Some(name) => StatementFact::RollbackToSavepoint { name },
            None       => StatementFact::RollbackTransaction,
        }
    }

    fn extract_savepoint(node: &Savepoint) -> StatementFact {
        StatementFact::Savepoint { name: node.name().map(|n| n.text().to_string()).unwrap_or_default() }
    }

    fn extract_release_savepoint(node: &ReleaseSavepoint) -> StatementFact {
        StatementFact::ReleaseSavepoint { name: node.name_ref().map(|n| n.text().to_string()).unwrap_or_default() }
    }

    // ─────────────────────────────────────────────
    // Identifier Helpers
    // ─────────────────────────────────────────────

    fn segment_ident(segment: PathSegment) -> Option<Ident> {
        if let Some(nr) = segment.syntax().descendants().find_map(NameRef::cast) {
            Some(Ident::new(nr.text().to_string().trim_matches('"').to_string(), nr.is_quoted()))
        } else if let Some(n) = segment.syntax().descendants().find_map(Name::cast) {
            Some(Ident::new(n.text().to_string().trim_matches('"').to_string(), n.is_quoted()))
        } else { None }
    }

    fn path_to_qualified_name(path: &Path) -> Option<QualifiedName> {
        let segments: Vec<PathSegment> = path.syntax().descendants().filter_map(PathSegment::cast).collect();
        if segments.is_empty() { return None; }

        if segments.len() >= 2 {
            let schema = Self::segment_ident(segments[0].clone());
            let name = Self::segment_ident(segments[1].clone())?;
            Some(QualifiedName::new(schema, name))
        } else {
            let name = Self::segment_ident(segments[0].clone())?;
            Some(QualifiedName::new(None, name))
        }
    }
}
