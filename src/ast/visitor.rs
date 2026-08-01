// FILE: src/ast/visitor.rs
use crate::analysis::expr_ir::ExprIr;
use crate::analysis::facts::{
    AlterIndexActionFact, AlterTableActionFact, AlterTypeActionFact, AlterTypeFact, ColumnFact,
    CreateTypeFact, FkFact, PersistenceFact, SearchPathTarget, StatementFact, TableConstraintFact,
    TypeCreationKind,
};
use crate::ast::identifiers::{Ident, QualifiedName};
use squawk_syntax::ast::{
    AlterColumnOption, AlterConstraint, AlterDomain, AlterIndex, AlterSequence, AlterTable,
    AlterTableAction, AlterType, AstNode, AttachPartition, Column, ColumnConstraint, Constraint,
    CreateDatabase, CreateDomain, CreateIndex, CreateMaterializedView, CreatePolicy,
    CreateSequence, CreateTable, CreateTableAs, CreateTrigger, CreateType, CreateView, CteName,
    DetachPartition, DropDomain, DropIndex, DropMaterializedView, DropPolicy, DropSequence,
    DropTable, DropTrigger, DropType, DropView, Grant, Name, NameRef, Path, PathSegment,
    RelationNameRef, ReleaseSavepoint, Revoke, RevokeCommand, Rollback, Set, Stmt, TableArg,
    TableConstraint,
};
use squawk_syntax::{SyntaxKind, ast};

pub struct AstVisitor;

impl AstVisitor {
    fn resolve_name(n: Name) -> String {
        Self::identifier_from_name(n.text(), n.is_quoted()).resolve()
    }

    fn resolve_name_ref(nr: &NameRef) -> String {
        Self::identifier_from_name(nr.text(), nr.is_quoted()).resolve()
    }

    pub fn extract(stmt: &Stmt) -> Option<StatementFact> {
        let syntax = stmt.syntax();
        match stmt {
            Stmt::CreateTable(node) => return Self::extract_create_table(node),
            Stmt::CreateTableAs(node) => return Self::extract_create_table_as(node),
            Stmt::CreateView(node) => return Self::extract_create_view(node),
            Stmt::CreateMaterializedView(node) => {
                return Self::extract_create_materialized_view(node);
            }
            Stmt::CreateIndex(node) => return Self::extract_create_index(node),
            Stmt::AlterTable(node) => return Self::extract_alter_table(node),
            Stmt::AlterIndex(node) => return Self::extract_alter_index(node),
            Stmt::DropTable(node) => return Self::extract_drop_table(node),
            Stmt::DropView(node) => return Self::extract_drop_view(node),
            Stmt::DropMaterializedView(node) => return Self::extract_drop_materialized_view(node),
            Stmt::DropIndex(node) => return Self::extract_drop_index(node),
            Stmt::Set(node) => return Self::extract_set(node),
            Stmt::Grant(node) => return Self::extract_grant(node),
            Stmt::Revoke(node) => return Self::extract_revoke(node),
            Stmt::Begin(_) => return Some(StatementFact::BeginTransaction),
            Stmt::Commit(node) => {
                return Some(
                    if node.chain_token().is_some() && node.no_token().is_none() {
                        StatementFact::CommitAndChain
                    } else {
                        StatementFact::CommitTransaction
                    },
                );
            }
            Stmt::Rollback(node) => return Self::extract_rollback(node),
            Stmt::SavepointCreate(node) => return Some(Self::extract_savepoint(node)),
            Stmt::ReleaseSavepoint(node) => return Some(Self::extract_release_savepoint(node)),
            Stmt::Do(_) => return Some(StatementFact::OpaqueBlock),
            Stmt::Execute(_) => return Some(StatementFact::Execute),
            Stmt::Vacuum(node) => {
                let relation = if let Some(list) = node.table_and_columns_list() {
                    list.table_and_columnss()
                        .next()
                        .and_then(|tc| tc.table_relation_name())
                        .and_then(|rn| rn.table_name_ref())
                        .and_then(|tr| tr.path_ref())
                        .and_then(|path| Self::path_ref_to_qualified_name(&path))
                } else {
                    None
                };
                return Some(StatementFact::Vacuum {
                    relation,
                    is_full: node.is_full(),
                });
            }
            _ => {}
        }

        if let Some(node) = ast::CreateSchema::cast(syntax.clone()) {
            return Self::extract_create_schema(&node);
        }
        if let Some(node) = ast::AlterSchema::cast(syntax.clone()) {
            return Self::extract_alter_schema(&node);
        }
        if let Some(node) = ast::DropSchema::cast(syntax.clone()) {
            return Self::extract_drop_schema(&node);
        }

        if let Some(node) = ast::AlterView::cast(syntax.clone()) {
            return Self::extract_alter_view(&node);
        }
        if let Some(node) = ast::AlterMaterializedView::cast(syntax.clone()) {
            return Self::extract_alter_materialized_view(&node);
        }
        if let Some(node) = ast::Refresh::cast(syntax.clone()) {
            return Self::extract_refresh(&node);
        }

        if let Some(node) = CreateSequence::cast(syntax.clone()) {
            return Self::extract_create_sequence(&node);
        }
        if let Some(node) = AlterSequence::cast(syntax.clone()) {
            return Self::extract_alter_sequence(&node);
        }
        if let Some(node) = DropSequence::cast(syntax.clone()) {
            return Self::extract_drop_sequence(&node);
        }
        if let Some(node) = CreateType::cast(syntax.clone()) {
            return Self::extract_create_type(&node);
        }
        if let Some(node) = AlterType::cast(syntax.clone()) {
            return Self::extract_alter_type(&node);
        }
        if let Some(node) = CreateDomain::cast(syntax.clone()) {
            return Self::extract_create_domain(&node);
        }
        if let Some(node) = AlterDomain::cast(syntax.clone()) {
            return Self::extract_alter_domain(&node);
        }
        if let Some(node) = DropType::cast(syntax.clone()) {
            return Self::extract_drop_type(&node);
        }
        if let Some(node) = DropDomain::cast(syntax.clone()) {
            return Self::extract_drop_domain(&node);
        }
        if let Some(node) = CreatePolicy::cast(syntax.clone()) {
            return Self::extract_create_policy(&node);
        }
        if let Some(node) = DropPolicy::cast(syntax.clone()) {
            return Self::extract_drop_policy(&node);
        }
        if let Some(node) = CreateTrigger::cast(syntax.clone()) {
            return Self::extract_create_trigger(&node);
        }
        if let Some(node) = DropTrigger::cast(syntax.clone()) {
            return Self::extract_drop_trigger(&node);
        }

        if ast::PrepareTransaction::cast(syntax.clone()).is_some() {
            let name = syntax
                .descendants()
                .find_map(ast::Literal::cast)
                .map(|l| l.syntax().text().to_string().trim_matches('\'').to_string())
                .or_else(|| {
                    syntax
                        .descendants()
                        .find_map(Name::cast)
                        .map(Self::resolve_name)
                })
                .unwrap_or_default();
            return Some(StatementFact::PrepareTransaction { name });
        }
        if ast::SetTransaction::cast(syntax.clone()).is_some() {
            return Some(StatementFact::SetTransaction);
        }
        if ast::SetConstraints::cast(syntax.clone()).is_some() {
            return Some(StatementFact::SetConstraints);
        }

        if let Some(node) = ast::CreateFunction::cast(syntax.clone()) {
            return Self::extract_create_function(&node);
        }
        if let Some(node) = ast::AlterFunction::cast(syntax.clone()) {
            return Self::extract_alter_function(&node);
        }
        if let Some(node) = ast::DropFunction::cast(syntax.clone()) {
            return Self::extract_drop_function(&node);
        }
        if let Some(node) = ast::CreateProcedure::cast(syntax.clone()) {
            return Self::extract_create_procedure(&node);
        }
        if let Some(node) = ast::AlterProcedure::cast(syntax.clone()) {
            return Self::extract_alter_procedure(&node);
        }
        if let Some(node) = ast::DropProcedure::cast(syntax.clone()) {
            return Self::extract_drop_procedure(&node);
        }
        if let Some(node) = ast::CreatePublication::cast(syntax.clone()) {
            return Self::extract_create_publication(&node);
        }
        if let Some(node) = ast::AlterPublication::cast(syntax.clone()) {
            return Self::extract_alter_publication(&node);
        }
        if let Some(node) = ast::DropPublication::cast(syntax.clone()) {
            return Self::extract_drop_publication(&node);
        }
        if let Some(node) = ast::CreateSubscription::cast(syntax.clone()) {
            return Self::extract_create_subscription(&node);
        }
        if let Some(node) = ast::AlterSubscription::cast(syntax.clone()) {
            return Self::extract_alter_subscription(&node);
        }
        if let Some(node) = ast::DropSubscription::cast(syntax.clone()) {
            return Self::extract_drop_subscription(&node);
        }
        if let Some(node) = ast::CreateRole::cast(syntax.clone()) {
            return Self::extract_create_role(&node);
        }
        if let Some(node) = ast::AlterRole::cast(syntax.clone()) {
            return Self::extract_alter_role(&node);
        }
        if let Some(node) = ast::DropRole::cast(syntax.clone()) {
            return Self::extract_drop_role(&node);
        }
        if let Some(node) = CreateDatabase::cast(syntax.clone()) {
            return Self::extract_create_database(&node);
        }
        if let Some(node) = ast::AlterDatabase::cast(syntax.clone()) {
            return Self::extract_alter_database(&node);
        }
        if let Some(node) = ast::DropDatabase::cast(syntax.clone()) {
            return Self::extract_drop_database(&node);
        }

        None
    }

    fn extract_create_schema(node: &ast::CreateSchema) -> Option<StatementFact> {
        let name = match node.create_schema_target()? {
            ast::CreateSchemaTarget::NamedSchema(ns) => ns.schema()?.ident_token(),
            ast::CreateSchemaTarget::AuthorizationSchema(aus) => aus.role()?.ident_token(),
        }
        .map(|n| Self::identifier_from_token(n.text()))?;

        Some(StatementFact::CreateSchema {
            name: QualifiedName::new(None, name),
            if_not_exists: node.if_not_exists().is_some(),
        })
    }

    fn extract_alter_schema(node: &ast::AlterSchema) -> Option<StatementFact> {
        let nr = node.schema_ref()?.ident_token()?;
        let name = QualifiedName::new(None, Self::identifier_from_token(nr.text()));
        let new_name = node.alter_schema_action().and_then(|a| match a {
            ast::AlterSchemaAction::SchemaRenameTo(rt) => rt
                .schema()
                .and_then(|s| s.ident_token())
                .map(|n| Self::identifier_from_token(n.text())),
            _ => None,
        });
        Some(StatementFact::AlterSchema { name, new_name })
    }

    fn extract_drop_schema(node: &ast::DropSchema) -> Option<StatementFact> {
        // DROP SCHEMA uses NameRef nodes (bare identifiers), NOT Path nodes.
        // Squawk's DropSchema accessor exposes name_refs() for exactly this reason.
        let names: Vec<QualifiedName> = node
            .schema_refs()
            .filter_map(|r| r.ident_token())
            .map(|nr| QualifiedName::new(None, Self::identifier_from_token(nr.text())))
            .collect();

        if names.is_empty() {
            return None;
        }

        Some(StatementFact::DropSchema {
            names,
            if_exists: node.if_exists().is_some(),
            cascade: node.cascade_token().is_some(),
        })
    }

    fn extract_create_table(node: &CreateTable) -> Option<StatementFact> {
        let path = node.table_name()?.path()?;
        let name = Self::path_to_qualified_name(&path)?;

        let persistence = match node
            .persistence()
            .map(|p| p.syntax().text().to_string().to_lowercase())
            .as_deref()
        {
            Some("temporary") | Some("temp") => PersistenceFact::Temporary,
            Some("unlogged") => PersistenceFact::Unlogged,
            _ => PersistenceFact::Permanent,
        };

        let partition_by = node.partition_by().map(|p| p.syntax().text().to_string());
        let partition_of = node
            .partition_of()
            .and_then(|po| po.table_name_ref())
            .and_then(|t| t.path_ref())
            .and_then(|p| Self::path_ref_to_qualified_name(&p));
        let partition_type = node
            .partition_type()
            .map(|pt| pt.syntax().text().to_string());

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
            partition_by,
            partition_of,
            partition_type,
        })
    }

    fn extract_create_table_as(node: &CreateTableAs) -> Option<StatementFact> {
        let path = node.table_name()?.path()?;
        let persistence = match node
            .persistence()
            .map(|p| p.syntax().text().to_string().to_lowercase())
            .as_deref()
        {
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
            partition_by: None,
            partition_of: None,
            partition_type: None,
        })
    }

    fn extract_drop_table(node: &DropTable) -> Option<StatementFact> {
        let path = node
            .table_name_refs()
            .filter_map(|r| r.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .next()?;
        Some(StatementFact::DropTable {
            name: path,
            if_exists: node.if_exists().is_some(),
            cascade: node.cascade_token().is_some(),
        })
    }

    fn extract_alter_table(node: &AlterTable) -> Option<StatementFact> {
        let path = node.table_relation_name()?.table_name_ref()?.path_ref()?;
        let table_name = Self::path_ref_to_qualified_name(&path)?;
        let mut actions = Vec::new();

        for action in node.actions() {
            if let Some(ap) = AttachPartition::cast(action.syntax().clone()) {
                if let Some(child) = ap
                    .table_name_ref()
                    .and_then(|tn| tn.path_ref())
                    .and_then(|p| Self::path_ref_to_qualified_name(&p))
                {
                    actions.push(AlterTableActionFact::AttachPartition { child });
                }
                continue;
            }
            if let Some(dp) = DetachPartition::cast(action.syntax().clone()) {
                if let Some(child) = dp
                    .table_name_ref()
                    .and_then(|tn| tn.path_ref())
                    .and_then(|p| Self::path_ref_to_qualified_name(&p))
                {
                    actions.push(AlterTableActionFact::DetachPartition { child });
                }
                continue;
            }
            if let Some(ac) = AlterConstraint::cast(action.syntax().clone()) {
                let deferrable = ac.deferrable_constraint_option().is_some();
                actions.push(AlterTableActionFact::AlterConstraint {
                    name: None,
                    deferrable,
                });
                continue;
            }
            if let Some(rc) = ast::RenameConstraint::cast(action.syntax().clone()) {
                let old_name = rc
                    .syntax()
                    .descendants()
                    .find_map(NameRef::cast)
                    .map(|nr| Self::resolve_name_ref(&nr));
                let new_name = rc
                    .syntax()
                    .descendants()
                    .find_map(Name::cast)
                    .map(Self::resolve_name);
                if let (Some(old_name), Some(new_name)) = (old_name, new_name) {
                    actions.push(AlterTableActionFact::RenameConstraint { old_name, new_name });
                }
                continue;
            }

            match action {
                AlterTableAction::AddColumn(add) => {
                    if let Some(name) = add
                        .column_name()
                        .and_then(|n| n.ident_token())
                        .or_else(|| {
                            add.column_name().and_then(|cn| {
                                cn.syntax()
                                    .descendants_with_tokens()
                                    .filter_map(|e| e.into_token())
                                    .find(|t| t.kind() != SyntaxKind::WHITESPACE)
                            })
                        })
                        .map(|n| Self::resolve_identifier_token(n.text()))
                    {
                        let mut not_null = false;
                        let mut default = None;
                        for c in add.constraints() {
                            match c {
                                Constraint::NotNullConstraint(_) => not_null = true,
                                Constraint::PrimaryKeyConstraint(_) => not_null = true,
                                Constraint::DefaultConstraint(dc) => {
                                    default = dc
                                        .expr()
                                        .map(crate::analysis::expr_visitor::ExprVisitor::convert)
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
                    if let Some(name) = drop
                        .column_name_ref()
                        .and_then(|n| n.ident_token())
                        .or_else(|| {
                            drop.column_name_ref().and_then(|cnr| {
                                cnr.syntax()
                                    .descendants_with_tokens()
                                    .filter_map(|e| e.into_token())
                                    .find(|t| t.kind() != SyntaxKind::WHITESPACE)
                            })
                        })
                        .map(|n| Self::resolve_identifier_token(n.text()))
                    {
                        actions.push(AlterTableActionFact::DropColumn {
                            name,
                            if_exists: drop.if_exists().is_some(),
                        });
                    }
                }
                AlterTableAction::RenameColumn(rc) => {
                    let from_ident = rc
                        .column_name_ref()
                        .and_then(|nr| nr.ident_token())
                        .map(|nr| Self::identifier_from_token(nr.text()))
                        .or_else(|| {
                            rc.syntax()
                                .descendants()
                                .find_map(NameRef::cast)
                                .map(|nr| Self::identifier_from_name(nr.text(), nr.is_quoted()))
                        })
                        .or_else(|| {
                            rc.column_name_ref().and_then(|cnr| {
                                cnr.syntax()
                                    .descendants_with_tokens()
                                    .filter_map(|e| e.into_token())
                                    .find(|t| t.kind() != SyntaxKind::WHITESPACE)
                                    .map(|t| Self::identifier_from_token(t.text()))
                            })
                        });

                    let to_ident = rc
                        .column_name()
                        .and_then(|n| n.ident_token())
                        .map(|nr| Self::identifier_from_token(nr.text()))
                        .or_else(|| {
                            rc.syntax()
                                .descendants()
                                .find_map(Name::cast)
                                .map(|n| Self::identifier_from_name(n.text(), n.is_quoted()))
                        })
                        .or_else(|| {
                            rc.column_name().and_then(|cn| {
                                cn.syntax()
                                    .descendants_with_tokens()
                                    .filter_map(|e| e.into_token())
                                    .find(|t| t.kind() != SyntaxKind::WHITESPACE)
                                    .map(|t| Self::identifier_from_token(t.text()))
                            })
                        });

                    if let (Some(from), Some(to)) = (from_ident, to_ident) {
                        actions.push(AlterTableActionFact::RenameColumn { from, to });
                    }
                }
                AlterTableAction::TableRenameTo(rt) => {
                    if let Some(new_name) = rt
                        .table_name()
                        .and_then(|t| t.path())
                        .and_then(|p| Self::path_to_qualified_name(&p))
                    {
                        actions.push(AlterTableActionFact::RenameTo {
                            new_name: new_name.name,
                        });
                    }
                }
                AlterTableAction::AddConstraint(ac) => {
                    if let Some(fact) = Self::extract_add_constraint_fact(&ac) {
                        actions.push(fact);
                    }
                }
                AlterTableAction::DropConstraint(dc) => {
                    if let Some(name) = dc
                        .constraint_name_ref()
                        .and_then(|nr| nr.path_ref())
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                        .map(|qn| qn.name.resolve())
                    {
                        actions.push(AlterTableActionFact::DropConstraint { name });
                    }
                }
                AlterTableAction::AlterColumn(alter_col) => {
                    let col_ident = alter_col
                        .column_name_ref()
                        .and_then(|c| c.ident_token())
                        .map(|t| t.text().to_string())
                        .or_else(|| {
                            alter_col
                                .syntax()
                                .descendants()
                                .find_map(Name::cast)
                                .map(Self::resolve_name)
                        })
                        .or_else(|| {
                            alter_col.column_name_ref().and_then(|cnr| {
                                cnr.syntax()
                                    .descendants_with_tokens()
                                    .filter_map(|e| e.into_token())
                                    .find(|t| t.kind() != SyntaxKind::WHITESPACE)
                                    .map(|t| t.text().to_string())
                            })
                        });

                    if let Some(col_name) = col_ident
                        && let Some(opt) = alter_col.option()
                        && let Some(fact) = Self::extract_alter_column_option(col_name, opt)
                    {
                        actions.push(fact);
                    }
                }
                AlterTableAction::ValidateConstraint(vc) => {
                    if let Some(constraint_name) = vc
                        .syntax()
                        .descendants()
                        .find_map(NameRef::cast)
                        .map(|nr| Self::resolve_name_ref(&nr))
                    {
                        actions.push(AlterTableActionFact::ValidateConstraint { constraint_name });
                    }
                }
                AlterTableAction::SetAccessMethod(sam) => {
                    if sam.access_method_ref().is_some() {
                        actions.push(AlterTableActionFact::SetAccessMethod);
                    }
                }
                AlterTableAction::DisableTrigger(dt) => {
                    let trigger_name = dt
                        .trigger_ref()
                        .and_then(|tr| tr.ident_token())
                        .map(|n| Self::resolve_identifier_token(n.text()))
                        .or_else(|| {
                            if dt.all_token().is_some() {
                                Some("ALL".to_string())
                            } else {
                                None
                            }
                        })
                        .or_else(|| {
                            dt.syntax()
                                .descendants()
                                .find_map(NameRef::cast)
                                .map(|nr| Self::resolve_name_ref(&nr))
                        });
                    actions.push(AlterTableActionFact::DisableTrigger { trigger_name });
                }
                AlterTableAction::EnableTrigger(et) => {
                    let trigger_name = et
                        .trigger_ref()
                        .and_then(|tr| tr.ident_token())
                        .map(|n| Self::resolve_identifier_token(n.text()))
                        .or_else(|| {
                            if et.all_token().is_some() {
                                Some("ALL".to_string())
                            } else {
                                None
                            }
                        })
                        .or_else(|| {
                            et.syntax()
                                .descendants()
                                .find_map(NameRef::cast)
                                .map(|nr| Self::resolve_name_ref(&nr))
                        });
                    actions.push(AlterTableActionFact::EnableTrigger { trigger_name });
                }
                AlterTableAction::SetSchema(ss) => {
                    if let Some(nr) = ss.schema_ref().and_then(|sr| sr.ident_token()) {
                        actions.push(AlterTableActionFact::SetSchema {
                            new_schema: Self::resolve_identifier_token(nr.text()),
                        });
                    }
                }
                AlterTableAction::SetTablespace(st) => {
                    if let Some(token) = st.tablespace_ref().and_then(|tr| tr.ident_token()) {
                        let tablespace = Self::resolve_identifier_token(token.text());
                        actions.push(AlterTableActionFact::SetTablespace { tablespace });
                    }
                }
                AlterTableAction::OwnerTo(ot) => {
                    let owner = ot
                        .role_ref()
                        .and_then(|r| r.ident_token())
                        .map(|t| Self::resolve_identifier_token(t.text()))
                        .or_else(|| {
                            ot.syntax()
                                .descendants()
                                .find_map(squawk_syntax::ast::NameRef::cast)
                                .map(|nr| Self::resolve_name_ref(&nr))
                        })
                        .or_else(|| {
                            ot.role_ref().and_then(|r| {
                                if r.current_user_token().is_some() {
                                    Some("CURRENT_USER".to_string())
                                } else if r.current_role_token().is_some() {
                                    Some("CURRENT_ROLE".to_string())
                                } else {
                                    None
                                }
                            })
                        });
                    if let Some(new_owner) = owner {
                        actions.push(AlterTableActionFact::OwnerTo { new_owner });
                    }
                }
                AlterTableAction::SetLogged(_) => {
                    actions.push(AlterTableActionFact::SetLogged);
                }
                AlterTableAction::SetUnlogged(_) => {
                    actions.push(AlterTableActionFact::SetUnlogged);
                }
                AlterTableAction::ReplicaIdentity(ri) => {
                    let option = ri
                        .index_ref()
                        .and_then(|ir| ir.path_ref())
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                        .map(|qn| qn.name.resolve())
                        .or_else(|| {
                            if ri.default_token().is_some() {
                                Some("DEFAULT".to_string())
                            } else if ri.full_token().is_some() {
                                Some("FULL".to_string())
                            } else if ri.syntax().descendants().find_map(NameRef::cast).is_some() {
                                ri.syntax()
                                    .descendants()
                                    .find_map(NameRef::cast)
                                    .map(|nr| Self::resolve_name_ref(&nr))
                            } else {
                                Some("NOTHING".to_string())
                            }
                        })
                        .unwrap_or_default();
                    actions.push(AlterTableActionFact::ReplicaIdentity { option });
                }
                AlterTableAction::ClusterOn(co) => {
                    let index = co
                        .index_ref()
                        .and_then(|ir| ir.path_ref())
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                        .map(|qn| qn.name.resolve())
                        .or_else(|| {
                            co.syntax()
                                .descendants()
                                .find_map(NameRef::cast)
                                .map(|nr| Self::resolve_name_ref(&nr))
                        })
                        .unwrap_or_default();
                    actions.push(AlterTableActionFact::ClusterOn { index });
                }
                AlterTableAction::InheritTable(it) => {
                    if let Some(path) = it.table_name_ref().and_then(|t| t.path_ref())
                        && let Some(parent) = Self::path_ref_to_qualified_name(&path)
                    {
                        actions.push(AlterTableActionFact::InheritTable { parent });
                    }
                }
                AlterTableAction::NoInheritTable(nit) => {
                    if let Some(path) = nit.table_name_ref().and_then(|t| t.path_ref())
                        && let Some(parent) = Self::path_ref_to_qualified_name(&path)
                    {
                        actions.push(AlterTableActionFact::NoInheritTable { parent });
                    }
                }
                AlterTableAction::MergePartitions(mp) => {
                    if let Some(path) = mp.table_name().and_then(|t| t.path())
                        && let Some(parent) = Self::path_to_qualified_name(&path)
                    {
                        actions.push(AlterTableActionFact::MergePartitions { parent });
                    }
                }
                AlterTableAction::SplitPartition(_sp) => {
                    actions.push(AlterTableActionFact::SplitPartition);
                }
                AlterTableAction::ForceRls(_) => {
                    actions.push(AlterTableActionFact::ForceRls);
                }
                AlterTableAction::EnableRls(_) => {
                    actions.push(AlterTableActionFact::EnableRls);
                }
                AlterTableAction::DisableRls(_) => {
                    actions.push(AlterTableActionFact::DisableRls);
                }
                AlterTableAction::EnableAlwaysTrigger(eat) => {
                    let trigger_name = eat
                        .trigger_ref()
                        .and_then(|tr| tr.ident_token())
                        .map(|n| Self::resolve_identifier_token(n.text()))
                        .or_else(|| {
                            eat.syntax()
                                .descendants()
                                .find_map(NameRef::cast)
                                .map(|nr| Self::resolve_name_ref(&nr))
                        });
                    actions.push(AlterTableActionFact::EnableAlwaysTrigger { trigger_name });
                }
                AlterTableAction::EnableReplicaTrigger(ert) => {
                    let trigger_name = ert
                        .trigger_ref()
                        .and_then(|tr| tr.ident_token())
                        .map(|n| Self::resolve_identifier_token(n.text()))
                        .or_else(|| {
                            ert.syntax()
                                .descendants()
                                .find_map(NameRef::cast)
                                .map(|nr| Self::resolve_name_ref(&nr))
                        });
                    actions.push(AlterTableActionFact::EnableReplicaTrigger { trigger_name });
                }
                _ => {
                    let txt = action.syntax().text().to_string().to_lowercase();

                    if txt.contains("set storage") {
                        let parts: Vec<&str> = txt.split_whitespace().collect();
                        if let Some(idx) = parts.iter().position(|&p| p == "column")
                            && idx + 1 < parts.len()
                        {
                            let c_name = Self::resolve_identifier_token(parts[idx + 1]);
                            actions.push(AlterTableActionFact::SetStorage { column: c_name });
                        }
                    }
                }
            }
        }

        Some(StatementFact::AlterTable {
            name: table_name,
            actions,
        })
    }

    fn extract_table_body(
        args: impl Iterator<Item = TableArg>,
    ) -> (Vec<ColumnFact>, Vec<FkFact>, Vec<TableConstraintFact>) {
        let mut columns = Vec::new();
        let mut foreign_keys = Vec::new();
        let mut table_constraints = Vec::new();
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
                TableArg::LikeClause(like) => {
                    if let Some(path) = like.syntax().descendants().find_map(Path::cast)
                        && let Some(_parent) = Self::path_to_qualified_name(&path)
                    {
                        // In the future, we may need to track 'Like' clauses as a specific
                        // mutation fact to properly model schema dependency and inheritance.
                        // For now, we omit them from the core table creation facts as
                        // they do not create column definitions in the current AST.
                    }
                }
                TableArg::TableConstraint(tc) => {
                    if let Some(fk) = Self::extract_table_fk_fact(&tc) {
                        foreign_keys.push(fk);
                    }
                    if let Some(tc_fact) = Self::extract_table_constraint_fact(&tc) {
                        table_constraints.push(tc_fact);
                    }
                }
            }
        }
        (columns, foreign_keys, table_constraints)
    }

    fn extract_column_fact(col: &Column) -> Option<ColumnFact> {
        let name_token = col.name().and_then(|n| n.ident_token()).or_else(|| {
            col.syntax()
                .descendants_with_tokens()
                .filter_map(|e| e.into_token())
                .find(|t| t.kind() != SyntaxKind::WHITESPACE)
        })?;
        let name = Self::resolve_identifier_token(name_token.text());
        let ty = col.ty().map(|t| t.syntax().text().to_string());
        let not_null = col
            .constraints()
            .any(|c| matches!(c, ColumnConstraint::NotNullConstraint(_)));
        let primary_key_constraint_name = col.constraints().find_map(|constraint| {
            let ColumnConstraint::PrimaryKeyConstraint(primary_key) = constraint else {
                return None;
            };
            Some(
                primary_key
                    .constraint_name_clause()
                    .and_then(|clause| clause.constraint_name())
                    .and_then(|name| name.ident_token())
                    .map(|token| Self::resolve_identifier_token(token.text())),
            )
        });
        let is_primary_key = primary_key_constraint_name.is_some();
        let primary_key_constraint_name = primary_key_constraint_name.flatten();
        let unique_constraint_name = col.constraints().find_map(|constraint| {
            let ColumnConstraint::UniqueConstraint(unique) = constraint else {
                return None;
            };
            Some(
                unique
                    .constraint_name_clause()
                    .and_then(|clause| clause.constraint_name())
                    .and_then(|name| name.ident_token())
                    .map(|token| Self::resolve_identifier_token(token.text())),
            )
        });
        let is_unique = unique_constraint_name.is_some();
        let unique_constraint_name = unique_constraint_name.flatten();
        let default = col.constraints().find_map(|c| {
            if let ColumnConstraint::DefaultConstraint(dc) = c {
                Some(crate::analysis::expr_visitor::ExprVisitor::convert(
                    dc.expr()?,
                ))
            } else {
                None
            }
        });
        Some(ColumnFact {
            name,
            ty,
            not_null,
            is_primary_key,
            primary_key_constraint_name,
            is_unique,
            unique_constraint_name,
            default,
        })
    }

    fn extract_alter_column_option(
        col_name: String,
        opt: AlterColumnOption,
    ) -> Option<AlterTableActionFact> {
        match opt {
            AlterColumnOption::SetStorage(_) => {
                Some(AlterTableActionFact::SetStorage { column: col_name })
            }
            AlterColumnOption::SetNotNull(_) => {
                Some(AlterTableActionFact::SetNotNull { column: col_name })
            }
            AlterColumnOption::DropNotNull(_) => {
                Some(AlterTableActionFact::DropNotNull { column: col_name })
            }
            AlterColumnOption::SetType(st) => {
                let has_using = st
                    .syntax()
                    .descendants()
                    .any(|t| t.kind() == SyntaxKind::USING_KW);
                Some(AlterTableActionFact::SetType {
                    column: col_name,
                    ty: st.ty()?.syntax().text().to_string(),
                    has_using,
                })
            }
            AlterColumnOption::SetDefault(sd) => Some(AlterTableActionFact::SetDefault {
                column: col_name,
                default: sd
                    .expr()
                    .map(crate::analysis::expr_visitor::ExprVisitor::convert),
            }),
            AlterColumnOption::SetExpression(se) => Some(AlterTableActionFact::SetExpression {
                column: col_name,
                expr: se
                    .expr()
                    .map(crate::analysis::expr_visitor::ExprVisitor::convert)
                    .unwrap_or(ExprIr::Omitted),
            }),
            AlterColumnOption::SetOptions(so) => Some(AlterTableActionFact::SetOptions {
                column: col_name,
                attributes: so
                    .attribute_list()
                    .map(|al| {
                        al.attribute_options()
                            .map(|ao| crate::analysis::facts::AttributeFact {
                                name: ao
                                    .name()
                                    .and_then(|n| n.ident_token())
                                    .map(|t| t.text().to_string())
                                    .unwrap_or_default(),
                                value: ao
                                    .syntax()
                                    .descendants()
                                    .find_map(ast::Literal::cast)
                                    .map(|l| l.syntax().text().to_string())
                                    .unwrap_or_default(),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            }),
            AlterColumnOption::Inherit(i) => Some(AlterTableActionFact::Inherit {
                column: col_name,
                parent: i
                    .syntax()
                    .descendants()
                    .find_map(Path::cast)
                    .and_then(|p| Self::path_to_qualified_name(&p))
                    .unwrap_or_else(|| {
                        QualifiedName::new(None, Ident::new("unknown".to_string(), false))
                    }),
            }),
            AlterColumnOption::NoInherit(ni) => Some(AlterTableActionFact::NoInherit {
                column: col_name,
                parent: ni
                    .syntax()
                    .descendants()
                    .find_map(Path::cast)
                    .and_then(|p| Self::path_to_qualified_name(&p))
                    .unwrap_or_else(|| {
                        QualifiedName::new(None, Ident::new("unknown".to_string(), false))
                    }),
            }),
            _ => None,
        }
    }

    fn extract_add_constraint_fact(
        ac: &squawk_syntax::ast::AddConstraint,
    ) -> Option<AlterTableActionFact> {
        let not_valid = ac.not_valid().is_some();

        if let Some(fkc) = ac
            .syntax()
            .descendants()
            .find_map(ast::ForeignKeyConstraint::cast)
        {
            let constraint_name = fkc
                .constraint_name_clause()
                .and_then(|cn| cn.constraint_name())
                .and_then(|cn| cn.ident_token())
                .map(|t| Self::resolve_identifier_token(t.text()))
                .or_else(|| {
                    ac.syntax()
                        .descendants()
                        .find_map(ast::ConstraintName::cast)
                        .and_then(|cn| cn.ident_token())
                        .map(|t| Self::resolve_identifier_token(t.text()))
                });
            let path = fkc.table_name_ref()?.path_ref()?;
            let references = Self::path_ref_to_qualified_name(&path)?;
            return Some(AlterTableActionFact::AddForeignKey {
                constraint_name,
                references,
                from_columns: fkc
                    .syntax()
                    .descendants()
                    .filter_map(ast::ColumnRefList::cast)
                    .next()
                    .map(Self::extract_column_list_names)
                    .unwrap_or_default(),
                to_columns: fkc
                    .syntax()
                    .descendants()
                    .filter_map(ast::ColumnRefList::cast)
                    .nth(1)
                    .map(Self::extract_column_list_names)
                    .unwrap_or_default(),
                not_valid,
            });
        }

        if let Some(cc) = ac
            .syntax()
            .descendants()
            .find_map(ast::CheckConstraint::cast)
        {
            let constraint_name = cc
                .constraint_name_clause()
                .and_then(|cn| cn.constraint_name())
                .and_then(|cn| cn.ident_token())
                .map(|t| Self::resolve_identifier_token(t.text()))
                .or_else(|| {
                    ac.syntax()
                        .descendants()
                        .find_map(ast::ConstraintName::cast)
                        .and_then(|cn| cn.ident_token())
                        .map(|t| Self::resolve_identifier_token(t.text()))
                });
            return Some(AlterTableActionFact::AddCheckConstraint {
                constraint_name,
                not_valid,
            });
        }

        if let Some(unique) = ac
            .syntax()
            .descendants()
            .find_map(ast::UniqueConstraint::cast)
        {
            let constraint_name = unique
                .constraint_name_clause()
                .and_then(|clause| clause.constraint_name())
                .and_then(|name| name.ident_token())
                .map(|token| Self::resolve_identifier_token(token.text()));
            let using_index = unique
                .using_index()
                .and_then(|using_index| using_index.index_ref())
                .and_then(|index_ref| index_ref.path_ref())
                .and_then(|path| Self::path_ref_to_qualified_name(&path));
            return Some(AlterTableActionFact::AddUniqueConstraint {
                constraint_name,
                using_index,
            });
        }

        if let Some(primary_key) = ac
            .syntax()
            .descendants()
            .find_map(ast::PrimaryKeyConstraint::cast)
        {
            let constraint_name = primary_key
                .constraint_name_clause()
                .and_then(|clause| clause.constraint_name())
                .and_then(|name| name.ident_token())
                .map(|token| Self::resolve_identifier_token(token.text()));
            let using_index = primary_key
                .using_index()
                .and_then(|using_index| using_index.index_ref())
                .and_then(|index_ref| index_ref.path_ref())
                .and_then(|path| Self::path_ref_to_qualified_name(&path));
            return Some(AlterTableActionFact::AddPrimaryKeyConstraint {
                constraint_name,
                using_index,
            });
        }

        if let Some(exclusion) = ac
            .syntax()
            .descendants()
            .find_map(ast::ExcludeConstraint::cast)
        {
            let constraint_name = exclusion
                .constraint_name_clause()
                .and_then(|clause| clause.constraint_name())
                .and_then(|name| name.ident_token())
                .map(|token| Self::resolve_identifier_token(token.text()));
            return Some(AlterTableActionFact::AddExcludeConstraint { constraint_name });
        }

        None
    }

    fn extract_table_constraint_fact(tc: &TableConstraint) -> Option<TableConstraintFact> {
        match tc {
            TableConstraint::PrimaryKeyConstraint(pkc) => Some(TableConstraintFact::PrimaryKey {
                constraint_name: pkc
                    .constraint_name_clause()
                    .and_then(|clause| clause.constraint_name())
                    .and_then(|name| name.ident_token())
                    .map(|token| Self::resolve_identifier_token(token.text())),
                columns: Self::extract_column_list_names(
                    pkc.syntax()
                        .descendants()
                        .find_map(ast::ColumnRefList::cast)?,
                ),
            }),
            TableConstraint::UniqueConstraint(uc) => Some(TableConstraintFact::Unique {
                constraint_name: uc
                    .constraint_name_clause()
                    .and_then(|clause| clause.constraint_name())
                    .and_then(|name| name.ident_token())
                    .map(|token| Self::resolve_identifier_token(token.text())),
                columns: Self::extract_column_list_names(
                    uc.syntax()
                        .descendants()
                        .find_map(ast::ColumnRefList::cast)?,
                ),
            }),
            TableConstraint::CheckConstraint(_) => Some(TableConstraintFact::Check),
            _ => None,
        }
    }

    fn extract_column_fk_facts(col: &Column) -> Vec<FkFact> {
        let col_name = col
            .name()
            .and_then(|n| n.ident_token())
            .or_else(|| {
                col.name().and_then(|cn| {
                    cn.syntax()
                        .descendants_with_tokens()
                        .filter_map(|e| e.into_token())
                        .find(|t| t.kind() != SyntaxKind::WHITESPACE)
                })
            })
            .map(|t| Self::resolve_identifier_token(t.text()));
        col.constraints()
            .filter_map(|c| {
                if let ColumnConstraint::ReferencesConstraint(rc) = c {
                    let ref_path = rc
                        .syntax()
                        .descendants()
                        .find_map(ast::PathRef::cast)
                        .and_then(|pr| {
                            // Try PathRef first (new parser), then fall back to Path (old)
                            Self::path_ref_to_qualified_name(&pr)
                        })
                        .or_else(|| {
                            rc.syntax()
                                .descendants()
                                .find_map(Path::cast)
                                .and_then(|p| Self::path_to_qualified_name(&p))
                        })?;
                    Some(FkFact {
                        constraint_name: None,
                        references: ref_path,
                        from_columns: col_name.iter().cloned().collect(),
                        to_columns: Vec::new(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    fn extract_table_fk_fact(tc: &TableConstraint) -> Option<FkFact> {
        if let TableConstraint::ForeignKeyConstraint(fkc) = tc {
            let constraint_name = fkc
                .constraint_name_clause()
                .and_then(|cn| cn.constraint_name())
                .and_then(|cn| cn.ident_token())
                .map(|t| Self::resolve_identifier_token(t.text()));
            let path = fkc
                .table_name_ref()
                .and_then(|t| t.path_ref())
                .and_then(|p| Self::path_ref_to_qualified_name(&p))?;
            let references = path;
            let from_columns = fkc
                .syntax()
                .descendants()
                .filter_map(ast::ColumnRefList::cast)
                .next()
                .map(Self::extract_column_list_names)
                .unwrap_or_default();
            let to_columns = fkc
                .syntax()
                .descendants()
                .filter_map(ast::ColumnRefList::cast)
                .nth(1)
                .map(Self::extract_column_list_names)
                .unwrap_or_default();

            return Some(FkFact {
                constraint_name,
                references,
                from_columns,
                to_columns,
            });
        }
        None
    }

    fn extract_column_list_names(cl: ast::ColumnRefList) -> Vec<String> {
        cl.column_refs()
            .filter_map(|col| {
                col.name_ref()
                    .and_then(|nr| nr.ident_token())
                    .map(|nr| Self::resolve_identifier_token(nr.text()))
            })
            .collect()
    }

    fn extract_create_index(node: &CreateIndex) -> Option<StatementFact> {
        let relation = node.table_relation_name()?.table_name_ref()?.path_ref()?;
        let relation = Self::path_ref_to_qualified_name(&relation)?;

        let index_ident = if let Some(name) = node
            .index()
            .and_then(|i| i.path())
            .and_then(|p| Self::path_to_qualified_name(&p))
        {
            name.name
        } else {
            Ident::new(
                format!("<unnamed_idx_on_{}>", relation.name.resolve()),
                false,
            )
        };

        let using_method = node.using_method().map(|um| {
            um.access_method_ref()
                .and_then(|nr| nr.ident_token())
                .map(|nr| nr.text().to_string().to_uppercase())
                .unwrap_or_default()
        });

        let has_predicate = node.where_clause().is_some();
        let unique = node.unique_token().is_some();

        Some(StatementFact::CreateIndex {
            name: QualifiedName::new(None, index_ident),
            relation,
            if_not_exists: node.if_not_exists().is_some(),
            concurrently: node.concurrently_token().is_some(),
            using_method,
            has_predicate,
            unique,
        })
    }

    fn extract_alter_index(node: &AlterIndex) -> Option<StatementFact> {
        let path = node.index_ref()?.path_ref()?;
        let name = Self::path_ref_to_qualified_name(&path)?;
        let mut actions = Vec::new();

        if let Some(squawk_syntax::ast::AlterIndexAction::IndexRenameTo(rt)) =
            node.alter_index_action()
            && let Some(new_name_node) = rt
                .index()
                .and_then(|i| i.path())
                .and_then(|p| Self::path_to_qualified_name(&p))
        {
            actions.push(AlterIndexActionFact::RenameTo {
                new_name: new_name_node.name,
            });
        }

        if actions.is_empty() {
            return None;
        }
        Some(StatementFact::AlterIndex { name, actions })
    }

    fn extract_drop_index(node: &DropIndex) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node
            .index_refs()
            .filter_map(|r| r.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .collect();
        if names.is_empty() {
            return None;
        }
        Some(StatementFact::DropIndex {
            names,
            if_exists: node.if_exists().is_some(),
            concurrently: node.concurrently_token().is_some(),
        })
    }

    fn extract_create_view(node: &CreateView) -> Option<StatementFact> {
        let path = node.view()?.path()?;
        Some(StatementFact::CreateView {
            name: Self::path_to_qualified_name(&path)?,
            or_replace: node.or_replace().is_some(),
            depends_on: Self::extract_view_dependencies(node.syntax()),
        })
    }

    fn extract_alter_view(node: &ast::AlterView) -> Option<StatementFact> {
        let path = node.view_ref()?.path_ref()?;
        let name = Self::path_ref_to_qualified_name(&path)?;

        let action = node.alter_view_action()?;
        match action {
            ast::AlterViewAction::ViewRenameTo(rt) => {
                let new_name_node = rt.view()?.path()?;
                Some(StatementFact::AlterView {
                    name,
                    action: crate::analysis::facts::AlterViewAction::RenameTo {
                        new_name: Self::path_to_qualified_name(&new_name_node)?.name,
                    },
                })
            }
            ast::AlterViewAction::OwnerTo(ot) => {
                let token = ot.role_ref()?.ident_token()?;
                Some(StatementFact::AlterView {
                    name,
                    action: crate::analysis::facts::AlterViewAction::OwnerTo {
                        new_owner: Self::resolve_identifier_token(token.text()),
                    },
                })
            }
            ast::AlterViewAction::SetSchema(ss) => {
                let token = ss.schema_ref()?.ident_token()?;
                Some(StatementFact::AlterView {
                    name,
                    action: crate::analysis::facts::AlterViewAction::SetSchema {
                        new_schema: Self::resolve_identifier_token(token.text()),
                    },
                })
            }
            ast::AlterViewAction::AlterViewColumn(avc) => {
                let col_token = avc.name()?.ident_token()?;
                let col_name = Self::resolve_identifier_token(col_token.text());

                if avc.drop_default().is_some() {
                    Some(StatementFact::AlterView {
                        name,
                        action: crate::analysis::facts::AlterViewAction::DropDefault {
                            column: col_name,
                        },
                    })
                } else if let Some(sd) = avc.set_default() {
                    let expr = sd.expr()?;
                    Some(StatementFact::AlterView {
                        name,
                        action: crate::analysis::facts::AlterViewAction::SetDefault {
                            column: col_name,
                            default: Some(crate::analysis::expr_visitor::ExprVisitor::convert(
                                expr,
                            )),
                        },
                    })
                } else {
                    None
                }
            }
            ast::AlterViewAction::RenameColumn(rc) => {
                let from_token = rc.column_name_ref()?.ident_token()?;
                let from = Self::identifier_from_token(from_token.text());

                let to_token = rc.column_name()?.ident_token()?;
                let to = Self::identifier_from_token(to_token.text());

                Some(StatementFact::AlterView {
                    name,
                    action: crate::analysis::facts::AlterViewAction::RenameColumn { from, to },
                })
            }
            ast::AlterViewAction::SetOptions(_) => Some(StatementFact::AlterView {
                name,
                action: crate::analysis::facts::AlterViewAction::SetOptions {
                    options: Vec::new(),
                },
            }),
            ast::AlterViewAction::ResetOptions(_) => Some(StatementFact::AlterView {
                name,
                action: crate::analysis::facts::AlterViewAction::ResetOptions {
                    options: Vec::new(),
                },
            }),
        }
    }

    fn extract_create_materialized_view(node: &CreateMaterializedView) -> Option<StatementFact> {
        let path = node.view()?.path()?;
        Some(StatementFact::CreateMaterializedView {
            name: Self::path_to_qualified_name(&path)?,
            depends_on: Self::extract_view_dependencies(node.syntax()),
        })
    }

    fn extract_alter_materialized_view(node: &ast::AlterMaterializedView) -> Option<StatementFact> {
        let path = node.view_ref()?.path_ref()?;
        let new_name = node.action().find_map(|action| {
            if let squawk_syntax::ast::AlterMaterializedViewAction::ViewRenameTo(rt) = action {
                rt.view()?
                    .path()?
                    .segment()?
                    .name()
                    .map(|n| Self::identifier_from_name(n.text(), n.is_quoted()))
            } else {
                None
            }
        });
        Some(StatementFact::AlterMaterializedView {
            name: Self::path_ref_to_qualified_name(&path)?,
            new_name,
        })
    }

    fn extract_refresh(node: &ast::Refresh) -> Option<StatementFact> {
        let path = node.view_ref()?.path_ref()?;
        Some(StatementFact::RefreshMaterializedView {
            name: Self::path_ref_to_qualified_name(&path)?,
            concurrently: node.concurrently_token().is_some(),
        })
    }

    fn extract_drop_view(node: &DropView) -> Option<StatementFact> {
        let path = node
            .view_refs()
            .filter_map(|r| r.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .next()?;
        Some(StatementFact::DropView {
            name: path,
            if_exists: node.if_exists().is_some(),
            cascade: node.cascade_token().is_some(),
        })
    }

    fn extract_drop_materialized_view(node: &DropMaterializedView) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node
            .view_refs()
            .filter_map(|r| r.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .collect();
        if names.is_empty() {
            return None;
        }
        Some(StatementFact::DropMaterializedView {
            names,
            if_exists: node.if_exists().is_some(),
            cascade: node.cascade_token().is_some(),
        })
    }

    fn extract_view_dependencies(syntax: &squawk_syntax::SyntaxNode) -> Vec<QualifiedName> {
        let mut depends_on = Vec::new();
        let keywords = [
            "SELECT",
            "FROM",
            "WHERE",
            "JOIN",
            "ON",
            "AND",
            "OR",
            "AS",
            "WITH",
            "GROUP",
            "BY",
            "HAVING",
            "LIMIT",
            "OFFSET",
            "ORDER",
            "ASC",
            "DESC",
            "IN",
            "NOT",
            "IS",
            "NULL",
            "UNION",
            "ALL",
            "EXCEPT",
            "INTERSECT",
            "TRUE",
            "FALSE",
        ];

        let mut local_declarations = Vec::new();
        for name_node in syntax.descendants().filter_map(Name::cast) {
            local_declarations.push(
                Self::identifier_from_name(name_node.text(), name_node.is_quoted()).resolve(),
            );
        }
        for cte_name in syntax.descendants().filter_map(CteName::cast) {
            if let Some(tok) = cte_name.ident_token() {
                local_declarations.push(tok.text().to_string());
            }
        }

        for n in syntax.descendants().filter_map(NameRef::cast) {
            let text = n.text().to_string();
            let upper = text.to_uppercase();
            let is_quoted = n.is_quoted();
            let clean_text = Self::identifier_from_token(&text).text;

            if !is_quoted && keywords.contains(&upper.as_str()) {
                continue;
            }

            if local_declarations.contains(&clean_text) {
                continue;
            }

            let relation = n
                .syntax()
                .ancestors()
                .skip(1)
                .find_map(RelationNameRef::cast);

            let qname = if let Some(rn) = relation {
                if let Some(pr) = rn.path_ref() {
                    if let Some(qn) = Self::path_ref_to_qualified_name(&pr) {
                        qn
                    } else {
                        QualifiedName::new(None, Ident::new(clean_text.clone(), is_quoted))
                    }
                } else {
                    QualifiedName::new(None, Ident::new(clean_text.clone(), is_quoted))
                }
            } else {
                QualifiedName::new(None, Ident::new(clean_text.clone(), is_quoted))
            };

            if !depends_on.contains(&qname) {
                depends_on.push(qname);
            }
        }
        depends_on
    }

    fn extract_create_sequence(node: &CreateSequence) -> Option<StatementFact> {
        let path = node.sequence()?.path()?;
        let name = Self::path_to_qualified_name(&path)?;
        Some(StatementFact::CreateSequence {
            name,
            if_not_exists: node.if_not_exists().is_some(),
            owned_by: Self::extract_owned_by(node.syntax()),
        })
    }

    fn extract_alter_sequence(node: &AlterSequence) -> Option<StatementFact> {
        let path = node.sequence_ref()?.path_ref()?;
        let name = Self::path_ref_to_qualified_name(&path)?;
        Some(StatementFact::AlterSequence {
            name,
            owned_by: Self::extract_owned_by(node.syntax()),
        })
    }

    fn extract_drop_sequence(node: &DropSequence) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node
            .sequence_refs()
            .filter_map(|r| r.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .collect();

        Some(StatementFact::DropSequence {
            names,
            if_exists: node.if_exists().is_some(),
            cascade: node.cascade_token().is_some(),
        })
    }

    fn extract_owned_by(node: &squawk_syntax::SyntaxNode) -> Option<(QualifiedName, String)> {
        for opt in node.descendants().filter_map(ast::OptionOwnedBy::cast) {
            let path_ref = opt.name()?.path_ref()?;
            let mut segments = Vec::new();
            let mut current_ref = Some(path_ref);

            while let Some(pr) = current_ref {
                if let Some(segment) = pr.segment()
                    && let Some(nr) = segment.name_ref()
                {
                    segments.push(Ident::new(nr.text().to_string(), nr.is_quoted()));
                }
                current_ref = pr.qualifier();
            }

            segments.reverse();

            if segments.len() >= 2 {
                let col_name = segments.last().unwrap().clone().resolve();
                let table_len = segments.len() - 1;
                let table_name = if table_len == 1 {
                    QualifiedName::new(None, segments[0].clone())
                } else {
                    QualifiedName::new(
                        Some(segments[table_len - 2].clone()),
                        segments[table_len - 1].clone(),
                    )
                };

                return Some((table_name, col_name));
            }
        }
        None
    }

    fn extract_create_domain(node: &CreateDomain) -> Option<StatementFact> {
        let path = node.domain()?.path()?;
        let base_type = node
            .ty()
            .map(|t| t.syntax().text().to_string())
            .unwrap_or_else(|| "<domain>".to_string());
        Some(StatementFact::CreateDomain {
            name: Self::path_to_qualified_name(&path)?,
            base_type,
        })
    }

    fn extract_alter_domain(node: &AlterDomain) -> Option<StatementFact> {
        let path = node.domain_ref()?.path_ref()?;
        let action = node.action().map(|a| match a {
            squawk_syntax::ast::AlterDomainAction::AddConstraint(_) => {
                crate::analysis::facts::AlterDomainActionFact::AddConstraint
            }
            squawk_syntax::ast::AlterDomainAction::DropConstraint(_) => {
                crate::analysis::facts::AlterDomainActionFact::DropConstraint
            }
            squawk_syntax::ast::AlterDomainAction::DropDefault(_) => {
                crate::analysis::facts::AlterDomainActionFact::DropDefault
            }
            squawk_syntax::ast::AlterDomainAction::DropNotNull(_) => {
                crate::analysis::facts::AlterDomainActionFact::DropNotNull
            }
            squawk_syntax::ast::AlterDomainAction::OwnerTo(_) => {
                crate::analysis::facts::AlterDomainActionFact::OwnerChange
            }
            squawk_syntax::ast::AlterDomainAction::RenameConstraint(_) => {
                crate::analysis::facts::AlterDomainActionFact::RenameConstraint
            }
            squawk_syntax::ast::AlterDomainAction::DomainRenameTo(_) => {
                crate::analysis::facts::AlterDomainActionFact::RenameTo
            }
            squawk_syntax::ast::AlterDomainAction::SetDefault(_) => {
                crate::analysis::facts::AlterDomainActionFact::SetDefault
            }
            squawk_syntax::ast::AlterDomainAction::SetNotNull(_) => {
                crate::analysis::facts::AlterDomainActionFact::SetNotNull
            }
            squawk_syntax::ast::AlterDomainAction::SetSchema(_) => {
                crate::analysis::facts::AlterDomainActionFact::SetSchema
            }
            squawk_syntax::ast::AlterDomainAction::ValidateConstraint(_) => {
                crate::analysis::facts::AlterDomainActionFact::ValidateConstraint
            }
        });
        Some(StatementFact::AlterDomain {
            name: Self::path_ref_to_qualified_name(&path)?,
            action,
        })
    }

    fn extract_drop_type(node: &DropType) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node
            .type_name_refs()
            .filter_map(|p| p.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .collect();

        Some(StatementFact::DropType {
            names,
            if_exists: node.if_exists().is_some(),
            cascade: node.cascade_token().is_some(),
        })
    }
    fn extract_drop_domain(node: &DropDomain) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node
            .domain_refs()
            .filter_map(|p| p.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .collect();

        Some(StatementFact::DropDomain {
            names,
            if_exists: node.if_exists().is_some(),
            cascade: node.cascade_token().is_some(),
        })
    }

    fn extract_create_type(node: &CreateType) -> Option<StatementFact> {
        let path = node.type_name()?.path()?;
        let name = Self::path_to_qualified_name(&path)?;

        let kind = match node.kind()? {
            ast::CreateTypeKind::EnumType(_) => TypeCreationKind::Enum,
            ast::CreateTypeKind::RangeType(_) => TypeCreationKind::Range,
            ast::CreateTypeKind::CompositeType(_) => TypeCreationKind::Composite,
            ast::CreateTypeKind::BaseType(_) => TypeCreationKind::Base,
        };

        Some(StatementFact::CreateType(CreateTypeFact { name, kind }))
    }

    fn extract_alter_type(node: &AlterType) -> Option<StatementFact> {
        let path = node.type_name_ref()?.path_ref()?;
        let name = Self::path_ref_to_qualified_name(&path)?;
        let mut actions = Vec::new();

        if let Some(squawk_syntax::ast::AlterTypeAction::AddValue(av)) = node.action()
            && let Some(lit) = av.literal()
        {
            let action_sql = av.syntax().text().to_string();
            let action_lower = action_sql.to_ascii_lowercase();
            let neighbor = av
                .syntax()
                .descendants()
                .filter_map(ast::Literal::cast)
                .map(|literal| {
                    literal
                        .syntax()
                        .text()
                        .to_string()
                        .trim_matches('\'')
                        .replace("''", "'")
                })
                .nth(1);
            actions.push(AlterTypeActionFact::AddValue {
                new_value: lit
                    .syntax()
                    .text()
                    .to_string()
                    .trim_matches('\'')
                    .replace("''", "'"),
                neighbor,
                before: action_lower.contains(" before "),
            });
        }

        Some(StatementFact::AlterType(AlterTypeFact { name, actions }))
    }

    fn extract_create_policy(node: &CreatePolicy) -> Option<StatementFact> {
        let name_token = node.policy()?.ident_token()?;
        let name = Self::resolve_identifier_token(name_token.text());
        let path = node.on_table()?.table_name_ref()?.path_ref()?;
        let table = Self::path_ref_to_qualified_name(&path)?;

        let permissive = if let Some(as_type) = node.as_policy_type() {
            as_type
                .ident_token()
                .map(|t| t.text().to_lowercase())
                .map(|t| t == "permissive")
                .unwrap_or(true)
        } else {
            true
        };

        let command = if node.all_token().is_some() {
            crate::analysis::facts::PolicyCommand::All
        } else if node.select_token().is_some() {
            crate::analysis::facts::PolicyCommand::Select
        } else if node.insert_token().is_some() {
            crate::analysis::facts::PolicyCommand::Insert
        } else if node.update_token().is_some() {
            crate::analysis::facts::PolicyCommand::Update
        } else if node.delete_token().is_some() {
            crate::analysis::facts::PolicyCommand::Delete
        } else {
            crate::analysis::facts::PolicyCommand::All
        };

        Some(StatementFact::CreatePolicy {
            name,
            table,
            permissive,
            command,
        })
    }

    fn extract_drop_policy(node: &DropPolicy) -> Option<StatementFact> {
        let path = node.on_table()?.table_name_ref()?.path_ref()?;
        let table = Self::path_ref_to_qualified_name(&path)?;
        let name_token = node.policy_ref()?.ident_token()?;
        let name = Self::resolve_identifier_token(name_token.text());
        Some(StatementFact::DropPolicy {
            name,
            table,
            if_exists: node.if_exists().is_some(),
        })
    }

    fn extract_create_trigger(node: &CreateTrigger) -> Option<StatementFact> {
        let name_token = node.trigger()?.ident_token()?;
        let name = Self::resolve_identifier_token(name_token.text());
        let path = node.on_relation()?.relation_name_ref()?.path_ref()?;
        let table = Self::path_ref_to_qualified_name(&path)?;
        let function = node.call_expr().and_then(|call| {
            let node_ref = call.syntax();
            let fn_name = node_ref.descendants().find_map(Name::cast).map(|n| {
                QualifiedName::new(None, Self::identifier_from_name(n.text(), n.is_quoted()))
            });
            if fn_name.is_some() {
                return fn_name;
            }
            node_ref.descendants().find_map(NameRef::cast).map(|n| {
                QualifiedName::new(None, Self::identifier_from_name(n.text(), n.is_quoted()))
            })
        });
        Some(StatementFact::CreateTrigger {
            name,
            table,
            function,
        })
    }

    fn extract_drop_trigger(node: &DropTrigger) -> Option<StatementFact> {
        let trigger_token = node.trigger_ref()?.ident_token()?;
        let trigger_name = Self::resolve_identifier_token(trigger_token.text());
        let table_path = node.on_relation()?.relation_name_ref()?.path_ref()?;
        let table = Self::path_ref_to_qualified_name(&table_path)?;
        Some(StatementFact::DropTrigger {
            name: trigger_name,
            table,
            if_exists: node.if_exists().is_some(),
        })
    }

    fn extract_param(param: &squawk_syntax::ast::Param) -> crate::analysis::facts::ParamFact {
        crate::analysis::facts::ParamFact {
            mode: match param.mode() {
                Some(ast::ParamMode::ParamVariadic(_)) => {
                    crate::analysis::facts::ParamModeFact::Variadic
                }
                Some(ast::ParamMode::ParamInOut(_)) => crate::analysis::facts::ParamModeFact::InOut,
                Some(ast::ParamMode::ParamOut(_)) => crate::analysis::facts::ParamModeFact::Out,
                _ => crate::analysis::facts::ParamModeFact::In,
            },
            name: param
                .name()
                .and_then(|n| n.ident_token())
                .map(|t| Self::resolve_identifier_token(t.text())),
            ty: param
                .ty()
                .map(|t| t.syntax().text().to_string())
                .unwrap_or_else(|| "unknown".into()),
            default: param.param_default().and_then(|pd| {
                pd.expr()
                    .map(crate::analysis::expr_visitor::ExprVisitor::convert)
            }),
        }
    }

    fn extract_ret_type(ret: &squawk_syntax::ast::RetType) -> crate::analysis::facts::RetTypeFact {
        if let Some(tal) = ret.table_arg_list() {
            let cols = tal
                .args()
                .filter_map(|arg| match arg {
                    TableArg::Column(col) => Self::extract_column_fact(&col),
                    _ => None,
                })
                .collect();
            crate::analysis::facts::RetTypeFact::Table(cols)
        } else {
            let ty = ret
                .ty()
                .map(|t| t.syntax().text().to_string())
                .unwrap_or_else(|| "unknown".into());
            crate::analysis::facts::RetTypeFact::Scalar(ty)
        }
    }

    fn extract_func_option(
        opt: &squawk_syntax::ast::FuncOption,
    ) -> crate::analysis::facts::FuncOptionFact {
        match opt {
            ast::FuncOption::LanguageFuncOption(f) => {
                crate::analysis::facts::FuncOptionFact::Language(
                    f.language_ref()
                        .and_then(|lr| lr.ident_token())
                        .map(|t| t.text().to_string())
                        .unwrap_or_default(),
                )
            }
            ast::FuncOption::VolatilityFuncOption(f) => {
                let vol = if f.immutable_token().is_some() {
                    crate::analysis::facts::VolatilityKind::Immutable
                } else if f.stable_token().is_some() {
                    crate::analysis::facts::VolatilityKind::Stable
                } else {
                    crate::analysis::facts::VolatilityKind::Volatile
                };
                crate::analysis::facts::FuncOptionFact::Volatility(vol)
            }
            ast::FuncOption::SecurityFuncOption(f) => {
                let sec = if f.invoker_token().is_some() {
                    crate::analysis::facts::SecurityKind::Invoker
                } else {
                    crate::analysis::facts::SecurityKind::Definer
                };
                crate::analysis::facts::FuncOptionFact::Security(sec)
            }
            ast::FuncOption::StrictFuncOption(_) => crate::analysis::facts::FuncOptionFact::Strict(
                crate::analysis::facts::StrictKind::Strict,
            ),
            ast::FuncOption::CalledOnNullInputFuncOption(_) => {
                crate::analysis::facts::FuncOptionFact::Strict(
                    crate::analysis::facts::StrictKind::CalledOnNull,
                )
            }
            ast::FuncOption::ReturnsNullOnNullInputFuncOption(_) => {
                crate::analysis::facts::FuncOptionFact::Strict(
                    crate::analysis::facts::StrictKind::ReturnsNullOnNull,
                )
            }
            ast::FuncOption::LeakproofFuncOption(f) => {
                let is_leakproof = f.leakproof_token().is_some();
                crate::analysis::facts::FuncOptionFact::Leakproof(is_leakproof)
            }
            ast::FuncOption::ParallelFuncOption(f) => {
                crate::analysis::facts::FuncOptionFact::Parallel(
                    f.syntax()
                        .descendants()
                        .find_map(ast::NameRef::cast)
                        .map(|n| n.text())
                        .unwrap_or_default(),
                )
            }
            ast::FuncOption::CostFuncOption(_) => crate::analysis::facts::FuncOptionFact::Cost,
            ast::FuncOption::RowsFuncOption(_) => crate::analysis::facts::FuncOptionFact::Rows,
            ast::FuncOption::ResetFuncOption(f) => crate::analysis::facts::FuncOptionFact::Reset(
                f.config_parameter_ref()
                    .and_then(|cpr| cpr.path_ref())
                    .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                    .map(|qn| qn.name.resolve())
                    .unwrap_or_default(),
            ),
            ast::FuncOption::AsFuncOption(f) => {
                let lit = f
                    .syntax()
                    .descendants()
                    .find_map(ast::Literal::cast)
                    .map(|l| l.syntax().text().to_string().trim_matches('\'').to_string());
                crate::analysis::facts::FuncOptionFact::As {
                    definition: lit,
                    obj_file: None,
                    link_symbol: None,
                }
            }
            ast::FuncOption::TransformFuncOption(_) => {
                crate::analysis::facts::FuncOptionFact::Transform
            }
            ast::FuncOption::WindowFuncOption(_) => crate::analysis::facts::FuncOptionFact::Window,
            ast::FuncOption::SupportFuncOption(_) => {
                crate::analysis::facts::FuncOptionFact::Support
            }
            _ => crate::analysis::facts::FuncOptionFact::Unknown,
        }
    }

    fn extract_create_function(node: &squawk_syntax::ast::CreateFunction) -> Option<StatementFact> {
        let path = node.name()?.path()?;
        let name = Self::path_to_qualified_name(&path)?;
        let or_replace = node.or_replace().is_some();
        let params = node
            .param_list()
            .map(|pl| pl.params().map(|p| Self::extract_param(&p)).collect())
            .unwrap_or_default();
        let return_type = node.ret_type().map(|r| Self::extract_ret_type(&r));
        let options = node
            .option_list()
            .map(|ol| {
                ol.options()
                    .map(|o| Self::extract_func_option(&o))
                    .collect()
            })
            .unwrap_or_default();

        Some(StatementFact::CreateFunction(
            crate::analysis::facts::CreateFunctionFact {
                name,
                or_replace,
                params,
                return_type,
                options,
            },
        ))
    }

    fn extract_alter_function(node: &ast::AlterFunction) -> Option<StatementFact> {
        let path = node.function_sig()?.function_name_ref()?.path_ref()?;
        let name = Self::path_ref_to_qualified_name(&path)?;
        let params = node
            .function_sig()
            .and_then(|sig| sig.param_list())
            .map(|pl| pl.params().map(|p| p.syntax().text().to_string()).collect())
            .unwrap_or_default();

        let action = node.alter_function_action().and_then(|a| match a {
            ast::AlterFunctionAction::FunctionRenameTo(rt) => {
                let new_name = rt
                    .function_name()?
                    .path()?
                    .segment()?
                    .name()?
                    .text()
                    .to_string();
                Some(crate::analysis::facts::AlterFunctionAction::Rename {
                    from: name.name.resolve(),
                    to: new_name,
                })
            }
            ast::AlterFunctionAction::OwnerTo(ot) => {
                Some(crate::analysis::facts::AlterFunctionAction::OwnerChange(
                    Self::extract_role(&ot.role_ref()?),
                ))
            }
            ast::AlterFunctionAction::SetSchema(ss) => {
                let token = ss.schema_ref()?.ident_token()?;
                Some(crate::analysis::facts::AlterFunctionAction::SchemaChange {
                    new_schema: Self::resolve_identifier_token(token.text()),
                })
            }
            ast::AlterFunctionAction::DependsOnExtension(de) => {
                let ext = de.extension_ref()?.ident_token()?.text().to_string();
                Some(
                    crate::analysis::facts::AlterFunctionAction::DependsOnExtension {
                        extension: ext,
                    },
                )
            }
            ast::AlterFunctionAction::NoDependsOnExtension(nde) => {
                let ext = nde.extension_ref()?.ident_token()?.text().to_string();
                Some(
                    crate::analysis::facts::AlterFunctionAction::NoDependsOnExtension {
                        extension: ext,
                    },
                )
            }
            ast::AlterFunctionAction::FuncOptionList(ol) => {
                Some(crate::analysis::facts::AlterFunctionAction::OptionsChange(
                    ol.options()
                        .map(|o| Self::extract_func_option(&o))
                        .collect(),
                ))
            }
        });

        Some(StatementFact::AlterFunction(
            crate::analysis::facts::AlterFunctionFact {
                name,
                params,
                action: action?,
            },
        ))
    }

    fn extract_drop_function(node: &squawk_syntax::ast::DropFunction) -> Option<StatementFact> {
        let sigs = node
            .function_sig_list()
            .map(|sl| {
                sl.function_sigs()
                    .filter_map(|sig| {
                        let path = sig.function_name_ref()?.path_ref()?;
                        Some(crate::analysis::facts::FunctionSigFact {
                            name: Self::path_ref_to_qualified_name(&path).unwrap_or_else(|| {
                                QualifiedName::new(None, Ident::new("unknown".to_string(), false))
                            }),
                            params: sig
                                .param_list()
                                .map(|pl| {
                                    pl.params()
                                        .filter_map(|p| {
                                            if matches!(p.mode(), Some(ast::ParamMode::ParamOut(_)))
                                            {
                                                return None;
                                            }
                                            Some(
                                                p.ty()
                                                    .map(|t| t.syntax().text().to_string())
                                                    .unwrap_or_else(|| "unknown".into()),
                                            )
                                        })
                                        .collect()
                                })
                                .unwrap_or_default(),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Some(StatementFact::DropFunction(
            crate::analysis::facts::DropFunctionFact {
                signatures: sigs,
                if_exists: node.if_exists().is_some(),
                cascade: node.cascade_token().is_some(),
            },
        ))
    }

    fn extract_create_procedure(
        node: &squawk_syntax::ast::CreateProcedure,
    ) -> Option<StatementFact> {
        let path = node.name()?.path()?;
        let name = Self::path_to_qualified_name(&path)?;
        let or_replace = node.or_replace().is_some();
        let params = node
            .param_list()
            .map(|pl| pl.params().map(|p| Self::extract_param(&p)).collect())
            .unwrap_or_default();
        let options = node
            .option_list()
            .map(|ol| {
                ol.options()
                    .map(|o| Self::extract_func_option(&o))
                    .collect()
            })
            .unwrap_or_default();

        Some(StatementFact::CreateProcedure(
            crate::analysis::facts::CreateProcedureFact {
                name,
                or_replace,
                params,
                options,
            },
        ))
    }

    fn extract_alter_procedure(node: &ast::AlterProcedure) -> Option<StatementFact> {
        let path = node.procedure_sig()?.procedure_name_ref()?.path_ref()?;
        let name = Self::path_ref_to_qualified_name(&path)?;
        let params = node
            .procedure_sig()
            .and_then(|sig| sig.param_list())
            .map(|pl| pl.params().map(|p| p.syntax().text().to_string()).collect())
            .unwrap_or_default();

        let action = node.alter_procedure_action().and_then(|a| match a {
            ast::AlterProcedureAction::ProcedureRenameTo(rt) => {
                let new_name = rt
                    .procedure_name()?
                    .path()?
                    .segment()?
                    .name()?
                    .text()
                    .to_string();
                Some(crate::analysis::facts::AlterFunctionAction::Rename {
                    from: name.name.resolve(),
                    to: new_name,
                })
            }
            ast::AlterProcedureAction::OwnerTo(ot) => {
                Some(crate::analysis::facts::AlterFunctionAction::OwnerChange(
                    Self::extract_role(&ot.role_ref()?),
                ))
            }
            ast::AlterProcedureAction::SetSchema(ss) => {
                Some(crate::analysis::facts::AlterFunctionAction::SchemaChange {
                    new_schema: ss.schema_ref()?.ident_token()?.text().to_string(),
                })
            }
            _ => None,
        });

        Some(StatementFact::AlterProcedure(
            crate::analysis::facts::AlterProcedureFact {
                name,
                params,
                action: action?,
            },
        ))
    }

    fn extract_drop_procedure(node: &squawk_syntax::ast::DropProcedure) -> Option<StatementFact> {
        let sigs = node
            .procedure_sig_list()
            .map(|sl| {
                sl.procedure_sigs()
                    .filter_map(|sig| {
                        let path = sig.procedure_name_ref()?.path_ref()?;
                        Some(crate::analysis::facts::FunctionSigFact {
                            name: Self::path_ref_to_qualified_name(&path).unwrap_or_else(|| {
                                QualifiedName::new(None, Ident::new("unknown".to_string(), false))
                            }),
                            params: sig
                                .param_list()
                                .map(|pl| {
                                    pl.params()
                                        .map(|p| {
                                            p.ty()
                                                .map(|t| t.syntax().text().to_string())
                                                .unwrap_or_else(|| "unknown".into())
                                        })
                                        .collect()
                                })
                                .unwrap_or_default(),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Some(StatementFact::DropProcedure(
            crate::analysis::facts::DropProcedureFact {
                signatures: sigs,
                if_exists: node.if_exists().is_some(),
                cascade: node.cascade_token().is_some(),
            },
        ))
    }

    fn extract_create_publication(
        node: &squawk_syntax::ast::CreatePublication,
    ) -> Option<StatementFact> {
        let name = node
            .publication()
            .and_then(|p| p.ident_token())
            .map(|t| t.text().to_string())
            .unwrap_or_default();
        let scope = if let Some(fapo) = node.for_all_publication_objects() {
            crate::analysis::facts::PublicationScope::AllTables {
                except: fapo
                    .except_table_clause()
                    .map(|etc| {
                        etc.except_table_names()
                            .filter_map(|etn| etn.table_relation_name())
                            .filter_map(|trn| trn.table_name_ref())
                            .filter_map(|tnr| tnr.path_ref())
                            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
                            .map(|qn| qn.name.resolve())
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        } else {
            let objects = node
                .publication_objects()
                .flat_map(|obj| {
                    if let Some(table_name_ref) = obj.table_name_ref() {
                        let path = table_name_ref.path_ref()?;
                        Some(crate::analysis::facts::PublicationObjectFact::Table {
                            name: Self::path_ref_to_qualified_name(&path)?,
                            only: obj.only_token().is_some(),
                            include_partitions: obj.star_token().is_some(),
                            columns: obj.column_ref_list().map(|cl| {
                                cl.column_refs()
                                    .filter_map(|c| c.name_ref())
                                    .map(|n| n.text().to_string())
                                    .collect()
                            }),
                            row_filter: obj.where_condition_clause().and_then(|w| {
                                w.expr()
                                    .map(crate::analysis::expr_visitor::ExprVisitor::convert)
                            }),
                        })
                    } else if let Some(schema_ref) = obj.schema_ref() {
                        Some(
                            crate::analysis::facts::PublicationObjectFact::SchemaTables {
                                schema: schema_ref
                                    .ident_token()
                                    .map(|t| t.text().to_string())
                                    .unwrap_or_default(),
                                row_filter: obj.where_condition_clause().and_then(|w| {
                                    w.expr()
                                        .map(crate::analysis::expr_visitor::ExprVisitor::convert)
                                }),
                            },
                        )
                    } else if obj.current_schema_token().is_some() {
                        Some(crate::analysis::facts::PublicationObjectFact::CurrentSchemaShorthand)
                    } else {
                        None
                    }
                })
                .collect();
            crate::analysis::facts::PublicationScope::Explicit(objects)
        };
        let params = node
            .with_params()
            .map(|wp| {
                wp.attribute_list()
                    .map(|al| {
                        al.attribute_options()
                            .map(|p| crate::analysis::facts::AttributeFact {
                                name: p
                                    .name()
                                    .and_then(|n| n.ident_token())
                                    .map(|t| t.text().to_string())
                                    .unwrap_or_default(),
                                value: p
                                    .syntax()
                                    .descendants()
                                    .find_map(ast::Literal::cast)
                                    .map(|l| l.syntax().text().to_string())
                                    .unwrap_or_default(),
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_default();

        Some(StatementFact::CreatePublication(
            crate::analysis::facts::CreatePublicationFact {
                name,
                scope,
                params,
            },
        ))
    }

    fn extract_alter_publication(
        node: &squawk_syntax::ast::AlterPublication,
    ) -> Option<StatementFact> {
        let name = node
            .publication_ref()
            .and_then(|pr| pr.ident_token())
            .map(|t| t.text().to_string())
            .unwrap_or_default();
        Some(StatementFact::AlterPublication(
            crate::analysis::facts::AlterPublicationFact { name },
        ))
    }

    fn extract_drop_publication(
        node: &squawk_syntax::ast::DropPublication,
    ) -> Option<StatementFact> {
        let names = node
            .publication_refs()
            .filter_map(|pr| pr.ident_token())
            .map(|t| t.text().to_string())
            .collect();
        Some(StatementFact::DropPublication(
            crate::analysis::facts::DropPublicationFact {
                names,
                if_exists: node.if_exists().is_some(),
                cascade: node.cascade_token().is_some(),
            },
        ))
    }

    fn extract_create_subscription(
        node: &squawk_syntax::ast::CreateSubscription,
    ) -> Option<StatementFact> {
        let name = node
            .subscription()
            .and_then(|s| s.ident_token())
            .map(|t| t.text().to_string());
        let connection = if node.server_token().is_some() {
            crate::analysis::facts::ConnectionTarget::Server(
                node.server_ref()
                    .and_then(|sr| sr.ident_token())
                    .map(|t| t.text().to_string()),
            )
        } else {
            crate::analysis::facts::ConnectionTarget::Literal(
                node.literal()
                    .map(|l| l.syntax().text().to_string().trim_matches('\'').to_string()),
            )
        };
        let publications = node
            .publication_refs()
            .filter_map(|pr| pr.ident_token())
            .map(|t| t.text().to_string())
            .collect();
        let params = node.with_params().map(|wp| {
            wp.attribute_list()
                .map(|al| {
                    al.attribute_options()
                        .map(|p| crate::analysis::facts::AttributeFact {
                            name: p
                                .name()
                                .and_then(|n| n.ident_token())
                                .map(|t| t.text().to_string())
                                .unwrap_or_default(),
                            value: p
                                .syntax()
                                .descendants()
                                .find_map(ast::Literal::cast)
                                .map(|l| l.syntax().text().to_string())
                                .unwrap_or_default(),
                        })
                        .collect()
                })
                .unwrap_or_default()
        });

        Some(StatementFact::CreateSubscription(
            crate::analysis::facts::CreateSubscriptionFact {
                name,
                connection,
                publications,
                params,
            },
        ))
    }

    fn extract_alter_subscription(
        node: &squawk_syntax::ast::AlterSubscription,
    ) -> Option<StatementFact> {
        let name = node
            .subscription_ref()
            .and_then(|sr| sr.ident_token())
            .map(|t| t.text().to_string())
            .unwrap_or_default();
        Some(StatementFact::AlterSubscription(
            crate::analysis::facts::AlterSubscriptionFact { name },
        ))
    }

    fn extract_drop_subscription(
        node: &squawk_syntax::ast::DropSubscription,
    ) -> Option<StatementFact> {
        let name = node.subscription_ref()?.ident_token()?.text().to_string();
        Some(StatementFact::DropSubscription(
            crate::analysis::facts::DropSubscriptionFact {
                name,
                if_exists: node.if_exists().is_some(),
            },
        ))
    }

    fn extract_role(role_ref: &squawk_syntax::ast::RoleRef) -> crate::analysis::facts::RoleFact {
        if let Some(token) = role_ref.ident_token() {
            let name = Self::resolve_identifier_token(token.text());
            return crate::analysis::facts::RoleFact::Named {
                name,
                via_legacy_group_syntax: role_ref.group_token().is_some(),
            };
        }
        if role_ref.current_role_token().is_some() {
            return crate::analysis::facts::RoleFact::CurrentRole;
        }
        if role_ref.current_user_token().is_some() {
            return crate::analysis::facts::RoleFact::CurrentUser;
        }
        if role_ref.session_user_token().is_some() {
            return crate::analysis::facts::RoleFact::SessionUser;
        }
        let via_group = role_ref.group_token().is_some();
        if let Some(token) = role_ref
            .syntax()
            .descendants_with_tokens()
            .filter_map(|x| x.into_token())
            .find(|t| t.kind() != SyntaxKind::WHITESPACE && t.kind() != SyntaxKind::COMMENT)
        {
            let name = Self::resolve_identifier_token(token.text());
            return crate::analysis::facts::RoleFact::Named {
                name,
                via_legacy_group_syntax: via_group,
            };
        }
        crate::analysis::facts::RoleFact::Unknown
    }

    fn extract_create_role(node: &squawk_syntax::ast::CreateRole) -> Option<StatementFact> {
        let name = node.role()?.ident_token()?.text().to_string();
        let inherits = node
            .role_option_list()
            .map(|ol| ol.role_options().any(|o| o.inherit_token().is_some()))
            .unwrap_or(false);
        Some(StatementFact::CreateRole(
            crate::analysis::facts::CreateRoleFact { name, inherits },
        ))
    }

    fn extract_alter_role(node: &squawk_syntax::ast::AlterRole) -> Option<StatementFact> {
        let name = Self::extract_role(&node.role_ref()?);
        let inherits = node.alter_role_action().and_then(|a| match a {
            ast::AlterRoleAction::RoleOptionList(ol) => {
                let mut found = None;
                for o in ol.role_options() {
                    if o.inherit_token().is_some() {
                        found = Some(true);
                    }
                }
                found
            }
            _ => None,
        });
        Some(StatementFact::AlterRole(
            crate::analysis::facts::AlterRoleFact { name, inherits },
        ))
    }

    fn extract_drop_role(node: &squawk_syntax::ast::DropRole) -> Option<StatementFact> {
        let names = node
            .role_refs()
            .map(|r| {
                r.ident_token()
                    .map(|t| t.text().to_string())
                    .unwrap_or_default()
            })
            .collect();
        Some(StatementFact::DropRole(
            crate::analysis::facts::DropRoleFact {
                names,
                if_exists: node.if_exists().is_some(),
            },
        ))
    }

    fn extract_privilege_from_revoke_command(
        cmd: &RevokeCommand,
    ) -> crate::analysis::facts::PrivilegeFact {
        if cmd.select_token().is_some() {
            crate::analysis::facts::PrivilegeFact::Select
        } else if cmd.insert_token().is_some() {
            crate::analysis::facts::PrivilegeFact::Insert
        } else if cmd.update_token().is_some() {
            crate::analysis::facts::PrivilegeFact::Update
        } else if cmd.delete_token().is_some() {
            crate::analysis::facts::PrivilegeFact::Delete
        } else if cmd.truncate_token().is_some() {
            crate::analysis::facts::PrivilegeFact::Truncate
        } else if cmd.references_token().is_some() {
            crate::analysis::facts::PrivilegeFact::References
        } else if cmd.trigger_token().is_some() {
            crate::analysis::facts::PrivilegeFact::Trigger
        } else if cmd.execute_token().is_some() {
            crate::analysis::facts::PrivilegeFact::Execute
        } else if cmd.create_token().is_some() {
            crate::analysis::facts::PrivilegeFact::Create
        } else if cmd.temp_token().is_some() || cmd.temporary_token().is_some() {
            crate::analysis::facts::PrivilegeFact::Temporary
        } else if cmd.alter_token().is_some() && cmd.system_token().is_some() {
            crate::analysis::facts::PrivilegeFact::AlterSystem
        } else if cmd.all_token().is_some() {
            crate::analysis::facts::PrivilegeFact::All
        } else if let Some(role_ref) = cmd.role_ref() {
            if let Some(ident) = role_ref.ident_token() {
                let raw = ident.text().to_string();
                let name = Self::resolve_identifier_token(&raw);
                if !Self::identifier_from_token(&raw).quoted {
                    match name.as_str() {
                        "insert" => return crate::analysis::facts::PrivilegeFact::Insert,
                        "update" => return crate::analysis::facts::PrivilegeFact::Update,
                        "delete" => return crate::analysis::facts::PrivilegeFact::Delete,
                        _ => {}
                    }
                }
                crate::analysis::facts::PrivilegeFact::RoleMembership(name)
            } else {
                let text = role_ref.syntax().text().to_string();
                match text.to_lowercase().as_str() {
                    "insert" => crate::analysis::facts::PrivilegeFact::Insert,
                    "update" => crate::analysis::facts::PrivilegeFact::Update,
                    "delete" => crate::analysis::facts::PrivilegeFact::Delete,
                    _ => crate::analysis::facts::PrivilegeFact::Unknown,
                }
            }
        } else if let Some(ident) = cmd.syntax().descendants().find_map(ast::Name::cast) {
            crate::analysis::facts::PrivilegeFact::Named(ident.text().to_string())
        } else {
            crate::analysis::facts::PrivilegeFact::Unknown
        }
    }

    fn extract_grant_target_from_privilege_objects(
        po: Option<squawk_syntax::ast::PrivilegeObjects>,
        _syntax: &squawk_syntax::SyntaxNode,
    ) -> Option<crate::analysis::facts::GrantTarget> {
        use squawk_syntax::ast::PrivilegeObjects;
        let names: Vec<_> = match po? {
            PrivilegeObjects::PrivilegeTable(obj) => obj
                .relation_name_refs()
                .filter_map(|rn| {
                    rn.path_ref()
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                })
                .collect(),
            PrivilegeObjects::PrivilegeDefault(obj) => obj
                .relation_name_refs()
                .filter_map(|rn| {
                    rn.path_ref()
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                })
                .collect(),
            PrivilegeObjects::PrivilegeAllInSchema(pais) => {
                let schemas: Vec<_> = pais
                    .schema_refs()
                    .filter_map(|sr| sr.ident_token().map(|t| t.text().to_string()))
                    .collect();
                return if schemas.is_empty() {
                    None
                } else {
                    Some(crate::analysis::facts::GrantTarget::AllTablesInSchema(
                        schemas,
                    ))
                };
            }
            _ => return None,
        };
        if names.is_empty() {
            None
        } else {
            Some(crate::analysis::facts::GrantTarget::Tables(names))
        }
    }

    fn extract_grant(node: &Grant) -> Option<StatementFact> {
        let privileges = if node.all_privileges().is_some() {
            crate::analysis::facts::PrivilegeSpec::All
        } else {
            crate::analysis::facts::PrivilegeSpec::List(
                node.revoke_command_list()
                    .map(|rcl| {
                        rcl.revoke_commands()
                            .map(|rc| Self::extract_privilege_from_revoke_command(&rc))
                            .collect()
                    })
                    .unwrap_or_default(),
            )
        };

        let target = Self::extract_grant_target_from_privilege_objects(
            node.privilege_objects(),
            node.syntax(),
        )?;

        let grantees = node
            .role_ref_list()
            .map(|rrl| rrl.role_refs().map(|r| Self::extract_role(&r)).collect())
            .unwrap_or_default();
        let with_grant_option = node.grant_with_clause().is_some();
        let granted_by = node.role_ref().map(|r| Self::extract_role(&r));

        Some(StatementFact::Grant(crate::analysis::facts::GrantFact {
            privileges,
            target,
            grantees,
            with_grant_option,
            granted_by,
        }))
    }

    fn extract_revoke(node: &Revoke) -> Option<StatementFact> {
        let grant_option_only = node.for_token().is_some()
            && node.grant_token().is_some()
            && node.option_token().is_some();

        let privileges = if let Some(p) = node.privileges() {
            if p.all_token().is_some() {
                crate::analysis::facts::PrivilegeSpec::All
            } else {
                crate::analysis::facts::PrivilegeSpec::List(
                    p.revoke_command_list()
                        .map(|rcl| {
                            rcl.revoke_commands()
                                .map(|rc| Self::extract_privilege_from_revoke_command(&rc))
                                .collect()
                        })
                        .unwrap_or_default(),
                )
            }
        } else {
            crate::analysis::facts::PrivilegeSpec::List(vec![])
        };

        let target = Self::extract_grant_target_from_privilege_objects(
            node.privilege_objects(),
            node.syntax(),
        )?;

        let revokees = node
            .role_ref_list()
            .map(|rrl| rrl.role_refs().map(|r| Self::extract_role(&r)).collect())
            .unwrap_or_default();
        let granted_by = node.role_ref().map(|r| Self::extract_role(&r));
        let cascade = node.cascade_token().is_some();

        Some(StatementFact::Revoke(crate::analysis::facts::RevokeFact {
            grant_option_only,
            privileges,
            target,
            revokees,
            granted_by,
            cascade,
        }))
    }

    fn extract_db_option(
        opt: squawk_syntax::ast::DatabaseOption,
    ) -> crate::analysis::facts::DatabaseOptionFact {
        let value = if opt.default_token().is_some() {
            crate::analysis::facts::DatabaseOptionValue::Default
        } else {
            crate::analysis::facts::DatabaseOptionValue::Literal(
                opt.literal()
                    .map(|l| l.syntax().text().to_string().trim_matches('\'').to_string()),
            )
        };

        if opt.owner_token().is_some() {
            crate::analysis::facts::DatabaseOptionFact::Owner(value)
        } else if opt.template_token().is_some() {
            crate::analysis::facts::DatabaseOptionFact::Template(value)
        } else if opt.encoding_token().is_some() {
            crate::analysis::facts::DatabaseOptionFact::Encoding(value)
        } else if opt.tablespace_token().is_some() {
            crate::analysis::facts::DatabaseOptionFact::Tablespace(value)
        } else if opt.connection_token().is_some() && opt.limit_token().is_some() {
            crate::analysis::facts::DatabaseOptionFact::ConnectionLimit(value)
        } else if let Some(ident) = opt.ident_token() {
            crate::analysis::facts::DatabaseOptionFact::Named(ident.text().to_string(), value)
        } else {
            crate::analysis::facts::DatabaseOptionFact::Unknown(value)
        }
    }

    fn extract_create_database(node: &CreateDatabase) -> Option<StatementFact> {
        let name = node
            .database()
            .and_then(|d| d.ident_token())
            .map(|t| t.text().to_string())
            .unwrap_or_default();
        let options = node
            .database_option_list()
            .map(|ol| ol.database_options().map(Self::extract_db_option).collect())
            .unwrap_or_default();
        Some(StatementFact::CreateDatabase(
            crate::analysis::facts::CreateDatabaseFact { name, options },
        ))
    }

    fn extract_alter_database(node: &ast::AlterDatabase) -> Option<StatementFact> {
        use squawk_syntax::ast::AlterDatabaseAction;
        let name = node
            .database_ref()
            .and_then(|dr| dr.ident_token())
            .map(|t| t.text().to_string())
            .unwrap_or_default();
        let name = QualifiedName::new(None, Ident::new(name, false));

        let action = match node.alter_database_action()? {
            AlterDatabaseAction::DatabaseRenameTo(rt) => {
                crate::analysis::facts::AlterDatabaseAction::Rename {
                    to: rt
                        .database()
                        .and_then(|d| d.ident_token())
                        .map(|t| t.text().to_string())
                        .unwrap_or_default(),
                }
            }
            AlterDatabaseAction::OwnerTo(ot) => {
                crate::analysis::facts::AlterDatabaseAction::OwnerChange(Self::extract_role(
                    &ot.role_ref().unwrap(),
                ))
            }
            AlterDatabaseAction::SetTablespace(st) => {
                crate::analysis::facts::AlterDatabaseAction::TablespaceChange {
                    new_tablespace: st
                        .tablespace_ref()
                        .and_then(|tr| tr.ident_token())
                        .map(|t| t.text().to_string())
                        .unwrap_or_default(),
                }
            }
            AlterDatabaseAction::SetConfigParam(scp) => {
                crate::analysis::facts::AlterDatabaseAction::SetConfigParam {
                    param: scp
                        .config_parameter_ref()
                        .and_then(|cpr| cpr.path_ref())
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                        .map(|qn| qn.name.resolve())
                        .unwrap_or_default(),
                }
            }
            AlterDatabaseAction::ResetConfigParam(rcp) => {
                crate::analysis::facts::AlterDatabaseAction::ResetConfigParam {
                    param: rcp
                        .config_parameter_ref()
                        .and_then(|cpr| cpr.path_ref())
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                        .map(|qn| qn.name.resolve()),
                }
            }
            AlterDatabaseAction::RefreshCollationVersion(_) => {
                crate::analysis::facts::AlterDatabaseAction::RefreshCollationVersion
            }
            AlterDatabaseAction::DatabaseOptionList(ol) => {
                crate::analysis::facts::AlterDatabaseAction::OptionChanges(
                    ol.database_options().map(Self::extract_db_option).collect(),
                )
            }
        };

        Some(StatementFact::AlterDatabase(
            crate::analysis::facts::AlterDatabaseFact { name, action },
        ))
    }

    fn extract_drop_database(node: &ast::DropDatabase) -> Option<StatementFact> {
        let name = node
            .database_ref()
            .and_then(|dr| dr.ident_token())
            .map(|t| t.text().to_string())
            .unwrap_or_default();
        let name = QualifiedName::new(None, Ident::new(name, false));
        Some(StatementFact::DropDatabase(
            crate::analysis::facts::DropDatabaseFact {
                name,
                if_exists: node.if_exists().is_some(),
            },
        ))
    }

    fn extract_set(node: &Set) -> Option<StatementFact> {
        use squawk_syntax::ast::SetTarget;
        let target = node.set_target()?;
        match target {
            SetTarget::SetConfig(sc) => {
                let setting_name = sc
                    .config_parameter_ref()
                    .and_then(|cpr| cpr.path_ref())
                    .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                    .map(|qn| qn.name.resolve())
                    .unwrap_or_default()
                    .to_lowercase();
                if setting_name != "search_path" {
                    return None;
                }

                let schemas: Vec<String> = sc
                    .config_values()
                    .filter_map(|cv| match cv {
                        ast::ConfigValue::ConfigValueName(cvn) => cvn
                            .ident_token()
                            .map(|t| Self::resolve_identifier_token(t.text())),
                        ast::ConfigValue::Literal(_) => None,
                    })
                    .filter(|s| s.to_lowercase() != "default")
                    .collect();

                if schemas.is_empty() {
                    Some(StatementFact::SetSearchPath {
                        target: SearchPathTarget::Default,
                    })
                } else {
                    Some(StatementFact::SetSearchPath {
                        target: SearchPathTarget::Schemas(schemas),
                    })
                }
            }
            _ => None,
        }
    }

    fn extract_rollback(node: &Rollback) -> Option<StatementFact> {
        if node.prepared_token().is_some() {
            return Some(StatementFact::OpaqueBlock);
        }

        match node
            .savepoint_ref()
            .and_then(|s| s.ident_token())
            .map(|t| Self::resolve_identifier_token(t.text()))
        {
            Some(name) => Some(StatementFact::RollbackToSavepoint { name }),
            None if node.chain_token().is_some() && node.no_token().is_none() => {
                Some(StatementFact::RollbackAndChain)
            }
            None => Some(StatementFact::RollbackTransaction),
        }
    }

    fn extract_savepoint(node: &squawk_syntax::ast::SavepointCreate) -> StatementFact {
        StatementFact::Savepoint {
            name: node
                .savepoint()
                .and_then(|s| s.ident_token())
                .map(|n| Self::resolve_identifier_token(n.text()))
                .unwrap_or_default(),
        }
    }

    fn extract_release_savepoint(node: &ReleaseSavepoint) -> StatementFact {
        StatementFact::ReleaseSavepoint {
            name: node
                .savepoint_ref()
                .and_then(|s| s.ident_token())
                .map(|t| Self::resolve_identifier_token(t.text()))
                .unwrap_or_default(),
        }
    }

    fn resolve_identifier_token(text: impl AsRef<str>) -> String {
        Self::identifier_from_token(text).resolve()
    }

    fn identifier_from_token(text: impl AsRef<str>) -> Ident {
        Self::identifier_from_name(text, false)
    }

    fn identifier_from_name(text: impl AsRef<str>, quoted: bool) -> Ident {
        let text = text.as_ref();
        match text
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
        {
            Some(inner) => Ident::new(inner.replace("\"\"", "\""), true),
            None => Ident::new(text.to_string(), quoted),
        }
    }

    fn segment_ident(segment: PathSegment) -> Option<Ident> {
        if let Some(nr) = segment.syntax().descendants().find_map(NameRef::cast) {
            Some(Self::identifier_from_name(nr.text(), nr.is_quoted()))
        } else {
            segment
                .syntax()
                .descendants()
                .find_map(Name::cast)
                .map(|n| Self::identifier_from_name(n.text(), n.is_quoted()))
        }
    }

    fn path_ref_to_qualified_name(path_ref: &squawk_syntax::ast::PathRef) -> Option<QualifiedName> {
        let mut segments = Vec::new();
        let mut current_ref = Some(path_ref.clone());

        while let Some(pr) = current_ref {
            if let Some(segment) = pr.segment()
                && let Some(nr) = segment.name_ref()
            {
                segments.push(Self::identifier_from_name(nr.text(), nr.is_quoted()));
            }
            current_ref = pr.qualifier();
        }

        segments.reverse();

        if segments.is_empty() {
            return None;
        }

        if segments.len() >= 2 {
            Some(QualifiedName::new(
                Some(segments[0].clone()),
                segments[1].clone(),
            ))
        } else {
            Some(QualifiedName::new(None, segments[0].clone()))
        }
    }

    fn path_to_qualified_name(path: &Path) -> Option<QualifiedName> {
        let mut segments: Vec<Ident> = Vec::new();

        if let Some(pr) = path
            .syntax()
            .descendants()
            .find_map(squawk_syntax::ast::PathRef::cast)
        {
            let mut current_ref = Some(pr);
            while let Some(r) = current_ref {
                if let Some(seg) = r.segment()
                    && let Some(nr) = seg.name_ref()
                {
                    segments.push(Self::identifier_from_name(nr.text(), nr.is_quoted()));
                }
                current_ref = r.qualifier();
            }
        }

        for ps in path.syntax().descendants().filter_map(PathSegment::cast) {
            if let Some(ident) = Self::segment_ident(ps) {
                segments.push(ident);
            }
        }

        if segments.is_empty() {
            return None;
        }

        if segments.len() >= 2 {
            Some(QualifiedName::new(
                Some(segments[0].clone()),
                segments[1].clone(),
            ))
        } else {
            Some(QualifiedName::new(None, segments[0].clone()))
        }
    }
}
