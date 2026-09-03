use crate::_internal::analysis::expr_ir::ExprIr;
use crate::_internal::analysis::facts::{
    AlterIndexActionFact, AlterTableActionFact, AlterTypeActionFact, AlterTypeFact, ColumnFact,
    CreateTypeFact, FkFact, PersistenceFact, ResetSettingTarget, SearchPathTarget, StatementFact,
    TableConstraintFact, TimeoutSetting, TimeoutSettingValue, TypeCreationKind,
};
use crate::_internal::ast::identifiers::{Ident, QualifiedName};
use squawk_syntax::ast::{
    AlterColumnOption, AlterConstraint, AlterDomain, AlterIndex, AlterSequence, AlterTable,
    AlterTableAction, AlterTrigger, AlterType, AstNode, AttachPartition, Column, ColumnConstraint,
    Constraint, CreateDatabase, CreateDomain, CreateIndex, CreateMaterializedView, CreatePolicy,
    CreateSequence, CreateTable, CreateTableAs, CreateTrigger, CreateType, CreateView, CteName,
    DetachPartition, DropDomain, DropIndex, DropMaterializedView, DropPolicy, DropSequence,
    DropTable, DropTrigger, DropType, DropView, Grant, NameRef, PartitionType, Path, PathSegment,
    PathSegmentRef, RelationNameRef, ReleaseSavepoint, Revoke, RevokeCommand, Rollback, Set, Stmt,
    TableArg, TableConstraint,
};
use squawk_syntax::{SyntaxKind, ast};

pub struct AstVisitor;

impl AstVisitor {
    fn expr_columns(expr: crate::_internal::analysis::expr_ir::ExprIr) -> Vec<String> {
        fn walk(expr: crate::_internal::analysis::expr_ir::ExprIr, columns: &mut Vec<String>) {
            use crate::_internal::analysis::expr_ir::ExprIr;
            match expr {
                ExprIr::ColumnRef(name) => {
                    if !columns.contains(&name) {
                        columns.push(name);
                    }
                }
                ExprIr::FunctionCall { args, .. } => {
                    for arg in args {
                        walk(arg, columns);
                    }
                }
                ExprIr::BinaryOp { left, right, .. } => {
                    walk(*left, columns);
                    walk(*right, columns);
                }
                ExprIr::Cast { expr, .. } => walk(*expr, columns),
                ExprIr::Literal(_) | ExprIr::Sentinel(_) | ExprIr::Omitted => {}
            }
        }
        let mut columns = Vec::new();
        walk(expr, &mut columns);
        columns
    }

    fn expr_columns_with_completeness(
        expr: crate::_internal::analysis::expr_ir::ExprIr,
    ) -> (Vec<String>, bool) {
        let complete = !expr.contains_opaque();
        (Self::expr_columns(expr), complete)
    }

    fn resolve_string_literal(literal: &ast::Literal) -> Option<String> {
        let token = literal.syntax().first_token()?;
        let raw = token.text();
        let mut decoded = String::new();
        match token.kind() {
            SyntaxKind::STRING => {
                squawk_syntax::unescape::decode_plain_string(
                    squawk_syntax::quote::strip_quotes(raw)?,
                    &mut decoded,
                );
            }
            SyntaxKind::ESC_STRING => {
                squawk_syntax::unescape::decode_esc_string(
                    squawk_syntax::quote::strip_prefixed_quotes(raw, ['e', 'E'])?,
                    &mut decoded,
                );
            }
            SyntaxKind::NATIONAL_STRING => {
                squawk_syntax::unescape::decode_plain_string(
                    squawk_syntax::quote::strip_prefixed_quotes(raw, ['n', 'N'])?,
                    &mut decoded,
                );
            }
            SyntaxKind::UNICODE_ESC_STRING => {
                squawk_syntax::unescape::decode_unicode_esc_string(
                    squawk_syntax::quote::strip_unicode_esc_prefix(raw)?,
                    '\\',
                    &mut decoded,
                );
            }
            SyntaxKind::DOLLAR_QUOTED_STRING => {
                decoded.push_str(squawk_syntax::quote::strip_dollar_quotes(raw)?);
            }
            _ => return None,
        }
        Some(decoded)
    }

    fn resolve_name(n: PathSegment) -> String {
        Self::identifier_from_name(n.text(), n.is_quoted()).resolve()
    }

    fn resolve_name_ref(nr: &NameRef) -> String {
        Self::identifier_from_name(nr.text(), nr.is_quoted()).resolve()
    }

    fn resolve_ast_identifier(node: &impl AstNode) -> String {
        Self::resolve_identifier_token(node.syntax().text().to_string().trim())
    }

    fn is_and_chain(clause: Option<ast::ChainClause>) -> bool {
        matches!(clause, Some(ast::ChainClause::AndChain(_)))
    }

    fn is_cascade(behavior: Option<ast::DropBehavior>) -> bool {
        matches!(behavior, Some(ast::DropBehavior::Cascade(_)))
    }

    fn is_local(scope: Option<ast::SetScope>) -> bool {
        matches!(scope, Some(ast::SetScope::LocalScope(_)))
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
            Stmt::Reset(node) => return Self::extract_reset(node),
            Stmt::Grant(node) => return Self::extract_grant(node),
            Stmt::Revoke(node) => return Self::extract_revoke(node),
            Stmt::CreateUser(node) => return Self::extract_create_user(node),
            Stmt::Begin(_) => return Some(StatementFact::BeginTransaction),
            Stmt::Commit(node) => {
                return Some(if Self::is_and_chain(node.chain_clause()) {
                    StatementFact::CommitAndChain
                } else {
                    StatementFact::CommitTransaction
                });
            }
            Stmt::Rollback(node) => return Self::extract_rollback(node),
            Stmt::SavepointCreate(node) => return Some(Self::extract_savepoint(node)),
            Stmt::ReleaseSavepoint(node) => return Some(Self::extract_release_savepoint(node)),
            Stmt::Do(_) => return Some(StatementFact::OpaqueBlock),
            Stmt::Execute(_) => return Some(StatementFact::Execute),
            Stmt::SetRole(node) => return Self::extract_set_role(node),
            Stmt::SetSessionAuth(node) => return Self::extract_set_session_auth(node),
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
        if let Some(node) = AlterTrigger::cast(syntax.clone()) {
            return Self::extract_alter_trigger(&node);
        }
        if ast::CommentOn::cast(syntax.clone()).is_some() {
            return Some(StatementFact::SchemaNeutralNoop);
        }

        if let Some(node) = ast::PrepareTransaction::cast(syntax.clone()) {
            let name = node
                .literal()
                .and_then(|literal| Self::resolve_string_literal(&literal))
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
        if let Some(node) = ast::CreateAggregate::cast(syntax.clone()) {
            return Self::extract_create_aggregate(&node);
        }
        if let Some(node) = ast::AlterAggregate::cast(syntax.clone()) {
            return Self::extract_alter_aggregate(&node);
        }
        if let Some(node) = ast::DropAggregate::cast(syntax.clone()) {
            return Self::extract_drop_aggregate(&node);
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
        let (name, authorization) = match node.create_schema_target()? {
            ast::CreateSchemaTarget::NamedSchema(ns) => (
                ns.schema()
                    .and_then(|schema| schema.ident_token())
                    .map(|token| Self::identifier_from_token(token.text()))?,
                ns.role_ref().map(|role| Self::extract_role(&role)),
            ),
            ast::CreateSchemaTarget::AuthorizationSchema(aus) => {
                let role = aus.role()?;
                let authorization = Self::extract_role_node(&role);
                let crate::_internal::analysis::facts::RoleFact::Named { name, .. } = &authorization else {
                    return None;
                };
                (Ident::new(name.clone(), true), Some(authorization))
            }
        };

        Some(StatementFact::CreateSchema {
            name: QualifiedName::new(None, name),
            if_not_exists: node.if_not_exists().is_some(),
            authorization,
        })
    }

    fn extract_alter_schema(node: &ast::AlterSchema) -> Option<StatementFact> {
        let nr = node.schema_ref()?.ident_token()?;
        let name = QualifiedName::new(None, Self::identifier_from_token(nr.text()));
        let action = node.action().and_then(|a| match a {
            ast::AlterSchemaAction::SchemaRenameTo(rt) => {
                rt.schema().and_then(|s| s.ident_token()).map(|n| {
                    crate::_internal::analysis::facts::AlterSchemaActionFact::RenameTo {
                        new_name: Self::identifier_from_token(n.text()),
                    }
                })
            }
            ast::AlterSchemaAction::OwnerTo(owner) => owner.role_ref().map(|role| {
                crate::_internal::analysis::facts::AlterSchemaActionFact::OwnerTo {
                    new_owner: Self::extract_role(&role),
                }
            }),
        })?;
        Some(StatementFact::AlterSchema { name, action })
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
            cascade: Self::is_cascade(node.drop_behavior()),
        })
    }

    fn extract_create_table(node: &CreateTable) -> Option<StatementFact> {
        let path = node.table_name()?.path()?;
        let name = Self::path_to_qualified_name(&path)?;

        // These forms copy inherited/type/LIKE metadata or add transaction
        // lifecycle semantics that the current table facts cannot represent.
        // Keep them on the engine's opaque path instead of creating an
        // incomplete table while claiming an exact state transition.
        if node.inherits().is_some()
            || node.of_type().is_some()
            || node.on_commit().is_some()
            || node.table_arg_list().is_some_and(|args| {
                args.args()
                    .any(|arg| matches!(arg, TableArg::LikeClause(_)))
            })
        {
            return None;
        }

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
            .map(|tal| {
                let (columns, foreign_keys, table_constraints) =
                    Self::extract_table_body(tal.args());
                (columns, foreign_keys, table_constraints)
            })
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
        // CTAS relations with ON COMMIT actions do not have the same
        // transaction lifecycle as an ordinary relation.  We do not model
        // that lifecycle yet, so preserve the engine's opaque-statement path
        // instead of claiming the relation survives (or disappears) exactly.
        if node.on_commit().is_some() {
            return None;
        }
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
        let names: Vec<QualifiedName> = node
            .table_name_refs()
            .filter_map(|r| r.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .collect();
        if names.is_empty() {
            return None;
        }
        Some(StatementFact::DropTable {
            names,
            if_exists: node.if_exists().is_some(),
            cascade: Self::is_cascade(node.drop_behavior()),
        })
    }

    fn extract_alter_table(node: &AlterTable) -> Option<StatementFact> {
        let path = node.table_relation_name()?.table_name_ref()?.path_ref()?;
        let table_name = Self::path_ref_to_qualified_name(&path)?;
        let mut actions = Vec::new();
        let mut unsupported_action = false;

        for action in node.actions() {
            if let Some(ap) = AttachPartition::cast(action.syntax().clone()) {
                if let Some(child) = ap
                    .table_name_ref()
                    .and_then(|tn| tn.path_ref())
                    .and_then(|p| Self::path_ref_to_qualified_name(&p))
                {
                    let strategy = match ap.partition_type() {
                        Some(PartitionType::PartitionForValuesIn(_)) => Some("LIST".to_string()),
                        Some(PartitionType::PartitionForValuesFrom(_)) => Some("RANGE".to_string()),
                        Some(PartitionType::PartitionForValuesWith(_)) => Some("HASH".to_string()),
                        Some(PartitionType::PartitionDefault(_)) | None => None,
                    };
                    actions.push(AlterTableActionFact::AttachPartition { child, strategy });
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
                let name = ac
                    .constraint_name_ref()
                    .and_then(|name| name.path_ref())
                    .and_then(|path| Self::path_ref_to_qualified_name(&path))
                    .map(|name| name.name.resolve());
                actions.push(AlterTableActionFact::AlterConstraint { name, deferrable });
                continue;
            }
            if let Some(rc) = ast::RenameConstraint::cast(action.syntax().clone()) {
                let old_name = rc
                    .constraint_name_ref()
                    .and_then(|name| name.path_ref())
                    .and_then(|path| Self::path_ref_to_qualified_name(&path))
                    .map(|name| name.name.resolve());
                let new_name = rc
                    .constraint_name()
                    .and_then(|name| name.ident_token())
                    .map(|token| Self::resolve_identifier_token(token.text()));
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
                        let mut generation = crate::_internal::analysis::facts::ColumnGeneration::Ordinary;
                        for c in add.constraints() {
                            match c {
                                Constraint::NotNullConstraint(_) => not_null = true,
                                Constraint::PrimaryKeyConstraint(_) => not_null = true,
                                Constraint::DefaultConstraint(dc) => {
                                    default = dc
                                        .expr()
                                        .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
                                }
                                Constraint::GeneratedConstraint(generated)
                                    if matches!(
                                        generated.generated_as(),
                                        Some(ast::GeneratedAs::GeneratedIdentity(_))
                                    ) =>
                                {
                                    generation = crate::_internal::analysis::facts::ColumnGeneration::Identity;
                                    not_null = true;
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
                            generation: if Self::is_serial_type(
                                add.ty().map(|ty| ty.syntax().text().to_string()).as_deref(),
                            ) {
                                crate::_internal::analysis::facts::ColumnGeneration::Serial
                            } else {
                                generation
                            },
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
                            cascade: Self::is_cascade(drop.drop_behavior()),
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
                                .find_map(PathSegment::cast)
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
                        actions.push(AlterTableActionFact::DropConstraint {
                            name,
                            if_exists: dc.if_exists().is_some(),
                            cascade: Self::is_cascade(dc.drop_behavior()),
                        });
                    }
                }
                AlterTableAction::AlterColumn(alter_col) => {
                    let col_ident = alter_col
                        .column_name_ref()
                        .and_then(|c| c.ident_token())
                        .map(|t| Self::resolve_identifier_token(t.text()))
                        .or_else(|| {
                            alter_col
                                .syntax()
                                .descendants()
                                .find_map(PathSegment::cast)
                                .map(Self::resolve_name)
                        })
                        .or_else(|| {
                            alter_col.column_name_ref().and_then(|cnr| {
                                cnr.syntax()
                                    .descendants_with_tokens()
                                    .filter_map(|e| e.into_token())
                                    .find(|t| t.kind() != SyntaxKind::WHITESPACE)
                                    .map(|t| Self::resolve_identifier_token(t.text()))
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
                        .constraint_name_ref()
                        .and_then(|name| name.path_ref())
                        .and_then(|path| Self::path_ref_to_qualified_name(&path))
                        .map(|name| name.name.resolve())
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
                    let trigger_name = match dt.trigger_target() {
                        Some(ast::TriggerTarget::TriggerRef(trigger)) => trigger
                            .ident_token()
                            .map(|name| Self::resolve_identifier_token(name.text())),
                        Some(ast::TriggerTarget::All(_)) => Some("ALL".to_string()),
                        Some(ast::TriggerTarget::User(_)) | None => None,
                    };
                    actions.push(AlterTableActionFact::DisableTrigger { trigger_name });
                }
                AlterTableAction::EnableTrigger(et) => {
                    let trigger_name = match et.trigger_target() {
                        Some(ast::TriggerTarget::TriggerRef(trigger)) => trigger
                            .ident_token()
                            .map(|name| Self::resolve_identifier_token(name.text())),
                        Some(ast::TriggerTarget::All(_)) => Some("ALL".to_string()),
                        Some(ast::TriggerTarget::User(_)) | None => None,
                    };
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
                    if let Some(new_owner) = ot.role_ref().map(|role| Self::extract_role(&role)) {
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
                    let option = match ri.replica_identity_option() {
                        Some(ast::ReplicaIdentityOption::ReplicaIdentityDefault(_)) => {
                            "DEFAULT".to_string()
                        }
                        Some(ast::ReplicaIdentityOption::ReplicaIdentityFull(_)) => {
                            "FULL".to_string()
                        }
                        Some(ast::ReplicaIdentityOption::ReplicaIdentityNothing(_)) => {
                            "NOTHING".to_string()
                        }
                        Some(ast::ReplicaIdentityOption::UsingIndexName(using_index)) => {
                            using_index
                                .index_ref()
                                .and_then(|index| index.path_ref())
                                .and_then(|path| Self::path_ref_to_qualified_name(&path))
                                .map(|name| name.name.resolve())
                                .unwrap_or_default()
                        }
                        None => String::new(),
                    };
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
                    } else {
                        // Parser-accepted actions that are not represented in
                        // our fact model must take the engine's explicit
                        // opaque path instead of becoming an exact no-op.
                        unsupported_action = true;
                    }
                }
            }
        }

        if unsupported_action {
            return None;
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
        let is_identity = col.constraints().any(|constraint| {
            matches!(constraint, ColumnConstraint::GeneratedConstraint(generated)
                if matches!(generated.generated_as(), Some(ast::GeneratedAs::GeneratedIdentity(_))))
        });
        let not_null = is_identity
            || col
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
                Some(crate::_internal::analysis::expr_visitor::ExprVisitor::convert(
                    dc.expr()?,
                ))
            } else {
                None
            }
        });
        let generation = if Self::is_serial_type(ty.as_deref()) {
            crate::_internal::analysis::facts::ColumnGeneration::Serial
        } else if is_identity {
            crate::_internal::analysis::facts::ColumnGeneration::Identity
        } else {
            crate::_internal::analysis::facts::ColumnGeneration::Ordinary
        };
        Some(ColumnFact {
            name,
            ty,
            not_null,
            is_primary_key,
            primary_key_constraint_name,
            is_unique,
            unique_constraint_name,
            default,
            generation,
        })
    }

    fn is_serial_type(ty: Option<&str>) -> bool {
        ty.map(str::trim)
            .map(str::to_ascii_lowercase)
            .is_some_and(|ty| {
                matches!(
                    ty.as_str(),
                    "smallserial" | "serial2" | "serial" | "serial4" | "bigserial" | "serial8"
                )
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
                let has_using = st.using_token().is_some();
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
                    .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert),
            }),
            AlterColumnOption::DropDefault(_) => Some(AlterTableActionFact::SetDefault {
                column: col_name,
                default: None,
            }),
            AlterColumnOption::SetExpression(se) => Some(AlterTableActionFact::SetExpression {
                column: col_name,
                expr: se
                    .expr()
                    .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
                    .unwrap_or(ExprIr::Omitted),
            }),
            AlterColumnOption::SetOptions(so) => Some(AlterTableActionFact::SetOptions {
                column: col_name,
                attributes: so
                    .attribute_list()
                    .map(|al| {
                        al.attribute_options()
                            .map(|ao| crate::_internal::analysis::facts::AttributeFact {
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
        if let Some(fkc) = ac
            .syntax()
            .descendants()
            .find_map(ast::ForeignKeyConstraint::cast)
        {
            let not_valid = fkc
                .constraint_options()
                .any(|option| matches!(option, ast::ConstraintOption::NotValid(_)));
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
            let column_lists = Self::extract_foreign_key_column_lists(&fkc);
            return Some(AlterTableActionFact::AddForeignKey {
                constraint_name,
                references,
                from_columns: column_lists.first().cloned().unwrap_or_default(),
                to_columns: column_lists.get(1).cloned().unwrap_or_default(),
                not_valid,
            });
        }

        if let Some(cc) = ac
            .syntax()
            .descendants()
            .find_map(ast::CheckConstraint::cast)
        {
            let not_valid = cc
                .constraint_options()
                .any(|option| matches!(option, ast::ConstraintOption::NotValid(_)));
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
            let (columns, columns_complete) = cc
                .expr()
                .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
                .map(Self::expr_columns_with_completeness)
                .unwrap_or((Vec::new(), false));
            return Some(AlterTableActionFact::AddCheckConstraint {
                constraint_name,
                columns,
                columns_complete,
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
            let columns = unique
                .syntax()
                .descendants()
                .find_map(ast::ConstraintColumnRefList::cast)
                .map(Self::extract_constraint_column_list_names)
                .unwrap_or_default();
            return Some(AlterTableActionFact::AddUniqueConstraint {
                constraint_name,
                columns,
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
            let columns = primary_key
                .syntax()
                .descendants()
                .find_map(ast::ConstraintColumnRefList::cast)
                .map(Self::extract_constraint_column_list_names)
                .unwrap_or_default();
            return Some(AlterTableActionFact::AddPrimaryKeyConstraint {
                constraint_name,
                columns,
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
            let mut columns_complete = true;
            let columns = exclusion
                .constraint_exclusion_list()
                .map(|list| {
                    list.constraint_exclusions()
                        .filter_map(|item| item.expr())
                        .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
                        .map(Self::expr_columns_with_completeness)
                        .inspect(|(_, complete)| columns_complete &= *complete)
                        .flat_map(|(columns, _)| columns)
                        .collect()
                })
                .unwrap_or_else(|| {
                    columns_complete = false;
                    Vec::new()
                });
            return Some(AlterTableActionFact::AddExcludeConstraint {
                constraint_name,
                columns,
                columns_complete,
            });
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
                columns: pkc
                    .syntax()
                    .descendants()
                    .find_map(ast::ConstraintColumnRefList::cast)
                    .map(Self::extract_constraint_column_list_names)
                    .or_else(|| pkc.using_index().map(|_| Vec::new()))?,
            }),
            TableConstraint::UniqueConstraint(uc) => Some(TableConstraintFact::Unique {
                constraint_name: uc
                    .constraint_name_clause()
                    .and_then(|clause| clause.constraint_name())
                    .and_then(|name| name.ident_token())
                    .map(|token| Self::resolve_identifier_token(token.text())),
                columns: uc
                    .syntax()
                    .descendants()
                    .find_map(ast::ConstraintColumnRefList::cast)
                    .map(Self::extract_constraint_column_list_names)
                    .or_else(|| uc.using_index().map(|_| Vec::new()))?,
            }),
            TableConstraint::CheckConstraint(check) => {
                let (columns, columns_complete) = check
                    .expr()
                    .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
                    .map(Self::expr_columns_with_completeness)
                    .unwrap_or((Vec::new(), false));
                Some(TableConstraintFact::Check {
                    constraint_name: check
                        .constraint_name_clause()
                        .and_then(|clause| clause.constraint_name())
                        .and_then(|name| name.ident_token())
                        .map(|token| Self::resolve_identifier_token(token.text())),
                    columns,
                    columns_complete,
                })
            }
            TableConstraint::ExcludeConstraint(exclude) => {
                let mut columns_complete = true;
                let columns = exclude
                    .constraint_exclusion_list()
                    .map(|list| {
                        list.constraint_exclusions()
                            .filter_map(|item| item.expr())
                            .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
                            .map(Self::expr_columns_with_completeness)
                            .inspect(|(_, complete)| columns_complete &= *complete)
                            .flat_map(|(columns, _)| columns)
                            .collect()
                    })
                    .unwrap_or_else(|| {
                        columns_complete = false;
                        Vec::new()
                    });
                Some(TableConstraintFact::Exclude {
                    constraint_name: exclude
                        .constraint_name_clause()
                        .and_then(|clause| clause.constraint_name())
                        .and_then(|name| name.ident_token())
                        .map(|token| Self::resolve_identifier_token(token.text())),
                    columns,
                    columns_complete,
                })
            }
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
            let column_lists = Self::extract_foreign_key_column_lists(fkc);
            let from_columns = column_lists.first().cloned().unwrap_or_default();
            let to_columns = column_lists.get(1).cloned().unwrap_or_default();

            return Some(FkFact {
                constraint_name,
                references,
                from_columns,
                to_columns,
            });
        }
        None
    }

    fn extract_constraint_column_list_names(cl: ast::ConstraintColumnRefList) -> Vec<String> {
        cl.column_name_refs()
            .filter_map(|column| column.ident_token())
            .map(|token| Self::resolve_identifier_token(token.text()))
            .collect()
    }

    fn extract_foreign_key_column_lists(
        constraint: &ast::ForeignKeyConstraint,
    ) -> Vec<Vec<String>> {
        // PostgreSQL lists the referencing columns first and referenced columns
        // second. Later lists, such as ON DELETE SET NULL (columns), must not
        // change that positional contract.
        constraint
            .syntax()
            .descendants()
            .filter_map(ast::ForeignKeyColumnList::cast)
            .map(|list| {
                list.column_name_refs()
                    .filter_map(|column| column.ident_token())
                    .map(|token| Self::resolve_identifier_token(token.text()))
                    .collect()
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
        let included_columns = node
            .index_include_clause()
            .and_then(|include| include.partition_item_list())
            .into_iter()
            .flat_map(|items| items.partition_items())
            .filter_map(|item| match item.expr() {
                Some(ast::Expr::NameRef(name)) => Some(Self::resolve_identifier_token(name.text())),
                _ => None,
            })
            .collect();
        let mut key_columns = Vec::new();
        let mut has_expression_keys = false;
        let mut has_default_sort_order = true;
        let mut has_default_opclasses = true;
        let mut has_default_collations = true;
        for item in node
            .syntax()
            .children()
            .find_map(ast::PartitionItemList::cast)
            .into_iter()
            .flat_map(|items| items.partition_items())
        {
            if item.sort_order().is_some() || item.nulls_order().is_some() {
                has_default_sort_order = false;
            }
            if item.op_class_ref().is_some() {
                has_default_opclasses = false;
            }
            if item.collate().is_some() {
                has_default_collations = false;
            }
            match item.expr() {
                Some(ast::Expr::NameRef(name)) => {
                    key_columns.push(Self::resolve_identifier_token(name.text()));
                }
                _ => has_expression_keys = true,
            }
        }

        Some(StatementFact::CreateIndex {
            name: QualifiedName::new(None, index_ident),
            relation,
            if_not_exists: node.if_not_exists().is_some(),
            concurrently: node.concurrently_token().is_some(),
            using_method,
            has_predicate,
            unique,
            key_columns,
            included_columns,
            has_expression_keys,
            has_default_sort_order,
            has_default_opclasses,
            has_default_collations,
        })
    }

    fn extract_alter_index(node: &AlterIndex) -> Option<StatementFact> {
        let path = node.index_ref()?.path_ref()?;
        let name = Self::path_ref_to_qualified_name(&path)?;
        let mut actions = Vec::new();

        if let Some(squawk_syntax::ast::AlterIndexAction::IndexRenameTo(rt)) = node.action()
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
            cascade: Self::is_cascade(node.drop_behavior()),
        })
    }

    fn extract_create_view(node: &CreateView) -> Option<StatementFact> {
        // View options and WITH CHECK OPTION alter write/security semantics
        // that are not represented by the relation state or dependency graph.
        if node.with_check_option().is_some() || node.with_params().is_some() {
            return None;
        }
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

        let action = node.action()?;
        match action {
            ast::AlterViewAction::ViewRenameTo(rt) => {
                let new_name_node = rt.view()?.path()?;
                Some(StatementFact::AlterView {
                    name,
                    action: crate::_internal::analysis::facts::AlterViewAction::RenameTo {
                        new_name: Self::path_to_qualified_name(&new_name_node)?.name,
                    },
                })
            }
            ast::AlterViewAction::OwnerTo(ot) => {
                let new_owner = Self::extract_role(&ot.role_ref()?);
                Some(StatementFact::AlterView {
                    name,
                    action: crate::_internal::analysis::facts::AlterViewAction::OwnerTo { new_owner },
                })
            }
            ast::AlterViewAction::SetSchema(ss) => {
                let token = ss.schema_ref()?.ident_token()?;
                Some(StatementFact::AlterView {
                    name,
                    action: crate::_internal::analysis::facts::AlterViewAction::SetSchema {
                        new_schema: Self::resolve_identifier_token(token.text()),
                    },
                })
            }
            ast::AlterViewAction::AlterViewColumn(_) => {
                // View column defaults are not represented by the relation
                // state and the resolver has no corresponding mutation.
                // Keep these parser-valid actions opaque rather than
                // returning a fact that is silently discarded.
                None
            }
            ast::AlterViewAction::RenameColumn(rc) => {
                let from_token = rc.column_name_ref()?.ident_token()?;
                let from = Self::identifier_from_token(from_token.text());

                let to_token = rc.column_name()?.ident_token()?;
                let to = Self::identifier_from_token(to_token.text());

                Some(StatementFact::AlterView {
                    name,
                    action: crate::_internal::analysis::facts::AlterViewAction::RenameColumn { from, to },
                })
            }
            ast::AlterViewAction::SetOptions(_) | ast::AlterViewAction::ResetOptions(_) => None,
        }
    }

    fn extract_create_materialized_view(node: &CreateMaterializedView) -> Option<StatementFact> {
        // A materialized view created WITH NO DATA cannot be refreshed
        // concurrently until it has been populated; populated state is not
        // modeled, so preserve the opaque path for this explicit form.
        if node
            .data_option()
            .is_some_and(|option| matches!(option, ast::DataOption::WithNoData(_)))
        {
            return None;
        }
        let path = node.view()?.path()?;
        Some(StatementFact::CreateMaterializedView {
            name: Self::path_to_qualified_name(&path)?,
            depends_on: Self::extract_view_dependencies(node.syntax()),
        })
    }

    fn extract_alter_materialized_view(node: &ast::AlterMaterializedView) -> Option<StatementFact> {
        let path = node.view_ref()?.path_ref()?;
        let Some(squawk_syntax::ast::AlterMaterializedViewAction::ViewRenameTo(rt)) =
            node.action().next()
        else {
            // SET SCHEMA, column changes, extension dependencies, and other
            // parser-valid actions are not represented by this mutation.
            // Do not turn them into a fact with no resolver mutation.
            return None;
        };
        let segment = rt.view()?.path()?.segment()?;
        let new_name = Some(Self::identifier_from_name(
            segment.text(),
            segment.is_quoted(),
        ));
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
        let names: Vec<QualifiedName> = node
            .view_refs()
            .filter_map(|r| r.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .collect();
        if names.is_empty() {
            return None;
        }
        Some(StatementFact::DropView {
            names,
            if_exists: node.if_exists().is_some(),
            cascade: Self::is_cascade(node.drop_behavior()),
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
            cascade: Self::is_cascade(node.drop_behavior()),
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
        for cte_name in syntax.descendants().filter_map(CteName::cast) {
            if let Some(tok) = cte_name.ident_token() {
                local_declarations.push(Self::resolve_identifier_token(tok.text()));
            }
        }

        for n in syntax.descendants().filter_map(PathSegmentRef::cast) {
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

            let Some(relation) = n
                .syntax()
                .ancestors()
                .skip(1)
                .find_map(RelationNameRef::cast)
            else {
                // Path segments outside a relation name are expressions,
                // casts, function calls, aliases, or CTE internals. They are
                // not relation dependencies (for example, `regclass` in a
                // `nextval(...::regclass)` cast), so do not turn them into
                // phantom graph edges.
                continue;
            };

            let qname = if let Some(pr) = relation.path_ref() {
                if let Some(qn) = Self::path_ref_to_qualified_name(&pr) {
                    qn
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
            owned_by: node.sequence_options().find_map(|option| match option {
                ast::SequenceOption::OptionOwnedBy(owned_by) => Self::extract_owned_by(&owned_by),
                _ => None,
            }),
        })
    }

    fn extract_alter_sequence(node: &AlterSequence) -> Option<StatementFact> {
        let path = node.sequence_ref()?.path_ref()?;
        let name = Self::path_ref_to_qualified_name(&path)?;
        let action = match node.actions().next() {
            Some(ast::AlterSequenceAction::OwnerTo(owner)) => owner
                .role_ref()
                .map(|role| {
                    crate::_internal::analysis::facts::AlterSequenceActionFact::OwnerTo(Self::extract_role(
                        &role,
                    ))
                })
                .unwrap_or(crate::_internal::analysis::facts::AlterSequenceActionFact::Other),
            Some(ast::AlterSequenceAction::SequenceRenameTo(rename)) => rename
                .sequence()
                .and_then(|sequence| sequence.path())
                .and_then(|path| Self::path_to_qualified_name(&path))
                .map(|name| crate::_internal::analysis::facts::AlterSequenceActionFact::RenameTo(name.name))
                .unwrap_or(crate::_internal::analysis::facts::AlterSequenceActionFact::Other),
            Some(ast::AlterSequenceAction::SetSchema(set_schema)) => set_schema
                .schema_ref()
                .and_then(|schema| schema.ident_token())
                .map(|token| {
                    crate::_internal::analysis::facts::AlterSequenceActionFact::SetSchema(
                        Self::resolve_identifier_token(token.text()),
                    )
                })
                .unwrap_or(crate::_internal::analysis::facts::AlterSequenceActionFact::Other),
            Some(ast::AlterSequenceAction::SequenceOption(ast::SequenceOption::OptionOwnedBy(
                option,
            ))) => match option.owned_by_target() {
                Some(ast::OwnedByTarget::OwnedByNone(_)) => {
                    crate::_internal::analysis::facts::AlterSequenceActionFact::OwnedBy(None)
                }
                Some(_) => crate::_internal::analysis::facts::AlterSequenceActionFact::OwnedBy(
                    Self::extract_owned_by(&option),
                ),
                None => crate::_internal::analysis::facts::AlterSequenceActionFact::Other,
            },
            _ => crate::_internal::analysis::facts::AlterSequenceActionFact::Other,
        };
        Some(StatementFact::AlterSequence {
            name,
            if_exists: node.if_exists().is_some(),
            action,
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
            cascade: Self::is_cascade(node.drop_behavior()),
        })
    }

    fn extract_owned_by(opt: &ast::OptionOwnedBy) -> Option<(QualifiedName, String)> {
        let ast::OwnedByTarget::QualifiedColumnNameRef(name) = opt.owned_by_target()? else {
            return None;
        };
        let path_ref = name.path_ref()?;
        let mut segments = Vec::new();
        let mut current_ref = Some(path_ref);

        while let Some(pr) = current_ref {
            if let Some(segment) = pr.segment() {
                segments.push(Self::identifier_from_name(
                    segment.text(),
                    segment.is_quoted(),
                ));
            }
            current_ref = pr.qualifier();
        }

        segments.reverse();

        if segments.len() < 2 {
            return None;
        }
        let col_name = segments.pop()?.resolve();
        let table_len = segments.len();
        let table_name = if table_len == 1 {
            QualifiedName::new(None, segments[0].clone())
        } else {
            QualifiedName::new(
                Some(segments[table_len - 2].clone()),
                segments[table_len - 1].clone(),
            )
        };
        Some((table_name, col_name))
    }

    fn extract_create_domain(node: &CreateDomain) -> Option<StatementFact> {
        // Domain constraints and collations affect every column using the
        // domain, but are not represented in TypeState.  Do not claim an
        // exact domain when either catalog-visible property is present.
        if node.collate().is_some() || node.constraints().next().is_some() {
            return None;
        }
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
                crate::_internal::analysis::facts::AlterDomainActionFact::AddConstraint
            }
            squawk_syntax::ast::AlterDomainAction::DropConstraint(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::DropConstraint
            }
            squawk_syntax::ast::AlterDomainAction::DropDefault(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::DropDefault
            }
            squawk_syntax::ast::AlterDomainAction::DropNotNull(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::DropNotNull
            }
            squawk_syntax::ast::AlterDomainAction::OwnerTo(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::OwnerChange
            }
            squawk_syntax::ast::AlterDomainAction::RenameConstraint(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::RenameConstraint
            }
            squawk_syntax::ast::AlterDomainAction::DomainRenameTo(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::RenameTo
            }
            squawk_syntax::ast::AlterDomainAction::SetDefault(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::SetDefault
            }
            squawk_syntax::ast::AlterDomainAction::SetNotNull(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::SetNotNull
            }
            squawk_syntax::ast::AlterDomainAction::SetSchema(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::SetSchema
            }
            squawk_syntax::ast::AlterDomainAction::ValidateConstraint(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::ValidateConstraint
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
            cascade: Self::is_cascade(node.drop_behavior()),
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
            cascade: Self::is_cascade(node.drop_behavior()),
        })
    }

    fn extract_create_type(node: &CreateType) -> Option<StatementFact> {
        let path = node.type_name()?.path()?;
        let name = Self::path_to_qualified_name(&path)?;

        let kind = match node.kind()? {
            ast::CreateTypeKind::EnumType(enum_type) => TypeCreationKind::Enum {
                variants: enum_type
                    .variant_list()?
                    .variants()
                    .map(|variant| {
                        variant
                            .literal()
                            .and_then(|literal| Self::resolve_string_literal(&literal))
                    })
                    .collect::<Option<Vec<_>>>()?,
            },
            // Range/composite/base types carry subtype, attribute, function,
            // and/or catalog dependency metadata that TypeState does not
            // retain. Keep enum creation exact, but route these forms through
            // the explicit opaque path.
            ast::CreateTypeKind::RangeType(_)
            | ast::CreateTypeKind::CompositeType(_)
            | ast::CreateTypeKind::BaseType(_) => return None,
        };

        Some(StatementFact::CreateType(CreateTypeFact { name, kind }))
    }

    fn extract_alter_type(node: &AlterType) -> Option<StatementFact> {
        let path = node.type_name_ref()?.path_ref()?;
        let name = Self::path_ref_to_qualified_name(&path)?;
        let mut actions = Vec::new();

        match node.action()? {
            ast::AlterTypeAction::TypeRenameTo(rename_type) => {
                let new_name = rename_type.type_name()?.path()?.segment()?;
                actions.push(AlterTypeActionFact::RenameTo {
                    new_name: Self::identifier_from_name(new_name.text(), new_name.is_quoted()),
                });
            }
            ast::AlterTypeAction::SetSchema(set_schema) => {
                let new_schema = set_schema.schema_ref()?.ident_token()?;
                actions.push(AlterTypeActionFact::SetSchema {
                    new_schema: Self::resolve_identifier_token(new_schema.text()),
                });
            }
            ast::AlterTypeAction::AddValue(add_value) => {
                let literals = add_value
                    .syntax()
                    .descendants()
                    .filter_map(ast::Literal::cast)
                    .map(|literal| Self::resolve_string_literal(&literal))
                    .collect::<Option<Vec<_>>>()?;
                let new_value = literals.first()?.clone();
                let neighbor = literals.get(1).cloned();
                let before = matches!(
                    add_value.value_position(),
                    Some(ast::ValuePosition::BeforeValue(_))
                );
                actions.push(AlterTypeActionFact::AddValue {
                    new_value,
                    neighbor,
                    before,
                });
            }
            ast::AlterTypeAction::RenameValue(rename_value) => {
                let literals = rename_value
                    .syntax()
                    .descendants()
                    .filter_map(ast::Literal::cast)
                    .map(|literal| Self::resolve_string_literal(&literal))
                    .collect::<Option<Vec<_>>>()?;
                actions.push(AlterTypeActionFact::RenameValue {
                    old_value: literals.first()?.clone(),
                    new_value: literals.get(1)?.clone(),
                });
            }
            // PostgreSQL also accepts attribute changes, OWNER changes, and
            // type options.  Those facts are not represented in the state
            // model; returning an empty action list would turn them into a
            // silent no-op, so route them through UnsupportedStatement.
            _ => return None,
        }

        Some(StatementFact::AlterType(AlterTypeFact { name, actions }))
    }

    fn extract_create_policy(node: &CreatePolicy) -> Option<StatementFact> {
        let semantics_complete = node.policy_roles().is_none()
            && node.using_expr_clause().is_none()
            && node.with_check_expr_clause().is_none();
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

        let command = match node.policy_command().and_then(|command| command.command()) {
            Some(ast::PolicyCommandKind::PolicyCommandSelect(_)) => {
                crate::_internal::analysis::facts::PolicyCommand::Select
            }
            Some(ast::PolicyCommandKind::PolicyCommandInsert(_)) => {
                crate::_internal::analysis::facts::PolicyCommand::Insert
            }
            Some(ast::PolicyCommandKind::PolicyCommandUpdate(_)) => {
                crate::_internal::analysis::facts::PolicyCommand::Update
            }
            Some(ast::PolicyCommandKind::PolicyCommandDelete(_)) => {
                crate::_internal::analysis::facts::PolicyCommand::Delete
            }
            Some(ast::PolicyCommandKind::PolicyCommandAll(_)) | None => {
                crate::_internal::analysis::facts::PolicyCommand::All
            }
        };

        Some(StatementFact::CreatePolicy {
            name,
            table,
            permissive,
            command,
            semantics_complete,
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
        let function = node
            .call_expr()
            .and_then(|call| call.expr())
            .and_then(Self::expr_to_qualified_name);
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

    fn extract_alter_trigger(node: &AlterTrigger) -> Option<StatementFact> {
        let name = Self::resolve_identifier_token(node.trigger_ref()?.ident_token()?.text());
        let table_path = node.on_relation()?.relation_name_ref()?.path_ref()?;
        let table = Self::path_ref_to_qualified_name(&table_path)?;
        let ast::AlterTriggerAction::TriggerRenameTo(rename) = node.action()? else {
            return None;
        };
        let new_name = Self::resolve_identifier_token(rename.trigger()?.ident_token()?.text());
        Some(StatementFact::AlterTrigger {
            name,
            table,
            new_name,
        })
    }

    fn extract_param(param: &squawk_syntax::ast::Param) -> crate::_internal::analysis::facts::ParamFact {
        crate::_internal::analysis::facts::ParamFact {
            mode: match param.mode() {
                Some(ast::ParamMode::ParamVariadic(_)) => {
                    crate::_internal::analysis::facts::ParamModeFact::Variadic
                }
                Some(ast::ParamMode::ParamInOut(_)) => crate::_internal::analysis::facts::ParamModeFact::InOut,
                Some(ast::ParamMode::ParamOut(_)) => crate::_internal::analysis::facts::ParamModeFact::Out,
                _ => crate::_internal::analysis::facts::ParamModeFact::In,
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
                    .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
            }),
        }
    }

    fn extract_ret_type(ret: &squawk_syntax::ast::RetType) -> crate::_internal::analysis::facts::RetTypeFact {
        if let Some(tal) = ret.table_arg_list() {
            let cols = tal
                .args()
                .filter_map(|arg| match arg {
                    TableArg::Column(col) => Self::extract_column_fact(&col),
                    _ => None,
                })
                .collect();
            crate::_internal::analysis::facts::RetTypeFact::Table(cols)
        } else {
            let ty = ret
                .ty()
                .map(|t| t.syntax().text().to_string())
                .unwrap_or_else(|| "unknown".into());
            crate::_internal::analysis::facts::RetTypeFact::Scalar(ty)
        }
    }

    fn extract_func_option(
        opt: &squawk_syntax::ast::FuncOption,
    ) -> crate::_internal::analysis::facts::FuncOptionFact {
        match opt {
            ast::FuncOption::LanguageFuncOption(f) => {
                crate::_internal::analysis::facts::FuncOptionFact::Language(
                    f.language_ref()
                        .and_then(|lr| lr.ident_token())
                        .map(|t| Self::resolve_identifier_token(t.text()))
                        .unwrap_or_default(),
                )
            }
            ast::FuncOption::VolatilityFuncOption(f) => {
                let vol = match f {
                    ast::VolatilityFuncOption::Immutable(_) => {
                        crate::_internal::analysis::facts::VolatilityKind::Immutable
                    }
                    ast::VolatilityFuncOption::Stable(_) => {
                        crate::_internal::analysis::facts::VolatilityKind::Stable
                    }
                    ast::VolatilityFuncOption::Volatile(_) => {
                        crate::_internal::analysis::facts::VolatilityKind::Volatile
                    }
                };
                crate::_internal::analysis::facts::FuncOptionFact::Volatility(vol)
            }
            ast::FuncOption::SecurityInvokerFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Security(
                    crate::_internal::analysis::facts::SecurityKind::Invoker,
                )
            }
            ast::FuncOption::SecurityDefinerFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Security(
                    crate::_internal::analysis::facts::SecurityKind::Definer,
                )
            }
            ast::FuncOption::StrictFuncOption(_) => crate::_internal::analysis::facts::FuncOptionFact::Strict(
                crate::_internal::analysis::facts::StrictKind::Strict,
            ),
            ast::FuncOption::CalledOnNullInputFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Strict(
                    crate::_internal::analysis::facts::StrictKind::CalledOnNull,
                )
            }
            ast::FuncOption::ReturnsNullOnNullInputFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Strict(
                    crate::_internal::analysis::facts::StrictKind::ReturnsNullOnNull,
                )
            }
            ast::FuncOption::LeakproofFuncOption(f) => {
                let is_leakproof = f.leakproof_token().is_some();
                crate::_internal::analysis::facts::FuncOptionFact::Leakproof(is_leakproof)
            }
            ast::FuncOption::NotLeakproofFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Leakproof(false)
            }
            ast::FuncOption::ParallelFuncOption(f) => {
                crate::_internal::analysis::facts::FuncOptionFact::Parallel(
                    f.ident_token()
                        .map(|token| Self::resolve_identifier_token(token.text()))
                        .unwrap_or_default(),
                )
            }
            ast::FuncOption::CostFuncOption(_) => crate::_internal::analysis::facts::FuncOptionFact::Cost,
            ast::FuncOption::RowsFuncOption(_) => crate::_internal::analysis::facts::FuncOptionFact::Rows,
            ast::FuncOption::ResetFuncOption(f) => crate::_internal::analysis::facts::FuncOptionFact::Reset(
                f.config_parameter_ref()
                    .and_then(|cpr| cpr.path_ref())
                    .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                    .map(|qn| qn.name.resolve())
                    .unwrap_or_default(),
            ),
            ast::FuncOption::AsFuncOption(f) => {
                let (definition, obj_file, link_symbol) = match f.as_func_target() {
                    Some(ast::AsFuncTarget::AsDefinition(definition)) => (
                        definition
                            .literal()
                            .and_then(|literal| Self::resolve_string_literal(&literal)),
                        None,
                        None,
                    ),
                    Some(ast::AsFuncTarget::AsObjFile(obj_file)) => (
                        None,
                        obj_file
                            .obj_file()
                            .and_then(|literal| Self::resolve_string_literal(&literal)),
                        obj_file
                            .link_symbol()
                            .and_then(|literal| Self::resolve_string_literal(&literal)),
                    ),
                    None => (None, None, None),
                };
                crate::_internal::analysis::facts::FuncOptionFact::As {
                    definition,
                    obj_file,
                    link_symbol,
                }
            }
            ast::FuncOption::TransformFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Transform
            }
            ast::FuncOption::WindowFuncOption(_) => crate::_internal::analysis::facts::FuncOptionFact::Window,
            ast::FuncOption::SupportFuncOption(_) => {
                crate::_internal::analysis::facts::FuncOptionFact::Support
            }
            _ => crate::_internal::analysis::facts::FuncOptionFact::Unknown,
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
            crate::_internal::analysis::facts::CreateFunctionFact {
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
        let params =
            Self::extract_signature_params(node.function_sig().and_then(|sig| sig.param_list()));

        let action = node.action().and_then(|a| match a {
            ast::AlterFunctionAction::FunctionRenameTo(rt) => {
                let new_name = Self::resolve_name(rt.function_name()?.path()?.segment()?);
                Some(crate::_internal::analysis::facts::AlterFunctionAction::Rename {
                    from: name.name.resolve(),
                    to: new_name,
                })
            }
            ast::AlterFunctionAction::OwnerTo(ot) => {
                Some(crate::_internal::analysis::facts::AlterFunctionAction::OwnerChange(
                    Self::extract_role(&ot.role_ref()?),
                ))
            }
            ast::AlterFunctionAction::SetSchema(ss) => {
                let token = ss.schema_ref()?.ident_token()?;
                Some(crate::_internal::analysis::facts::AlterFunctionAction::SchemaChange {
                    new_schema: Self::resolve_identifier_token(token.text()),
                })
            }
            ast::AlterFunctionAction::DependsOnExtension(de) => {
                let ext = Self::resolve_identifier_token(de.extension_ref()?.ident_token()?.text());
                Some(
                    crate::_internal::analysis::facts::AlterFunctionAction::DependsOnExtension {
                        extension: ext,
                    },
                )
            }
            ast::AlterFunctionAction::NoDependsOnExtension(nde) => {
                let ext =
                    Self::resolve_identifier_token(nde.extension_ref()?.ident_token()?.text());
                Some(
                    crate::_internal::analysis::facts::AlterFunctionAction::NoDependsOnExtension {
                        extension: ext,
                    },
                )
            }
            ast::AlterFunctionAction::FuncOptionList(ol) => {
                Some(crate::_internal::analysis::facts::AlterFunctionAction::OptionsChange(
                    ol.options()
                        .map(|o| Self::extract_func_option(&o))
                        .collect(),
                ))
            }
        });

        Some(StatementFact::AlterFunction(
            crate::_internal::analysis::facts::AlterFunctionFact {
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
                        Some(crate::_internal::analysis::facts::FunctionSigFact {
                            name: Self::path_ref_to_qualified_name(&path).unwrap_or_else(|| {
                                QualifiedName::new(None, Ident::new("unknown".to_string(), false))
                            }),
                            params: Self::extract_signature_params(sig.param_list()),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Some(StatementFact::DropFunction(
            crate::_internal::analysis::facts::DropFunctionFact {
                signatures: sigs,
                if_exists: node.if_exists().is_some(),
                cascade: Self::is_cascade(node.drop_behavior()),
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
            crate::_internal::analysis::facts::CreateProcedureFact {
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
        let params =
            Self::extract_signature_params(node.procedure_sig().and_then(|sig| sig.param_list()));

        let action = node.action().and_then(|a| match a {
            ast::AlterProcedureAction::ProcedureRenameTo(rt) => {
                let new_name = Self::resolve_name(rt.procedure_name()?.path()?.segment()?);
                Some(crate::_internal::analysis::facts::AlterFunctionAction::Rename {
                    from: name.name.resolve(),
                    to: new_name,
                })
            }
            ast::AlterProcedureAction::OwnerTo(ot) => {
                Some(crate::_internal::analysis::facts::AlterFunctionAction::OwnerChange(
                    Self::extract_role(&ot.role_ref()?),
                ))
            }
            ast::AlterProcedureAction::SetSchema(ss) => {
                Some(crate::_internal::analysis::facts::AlterFunctionAction::SchemaChange {
                    new_schema: Self::resolve_identifier_token(
                        ss.schema_ref()?.ident_token()?.text(),
                    ),
                })
            }
            _ => None,
        });

        Some(StatementFact::AlterProcedure(
            crate::_internal::analysis::facts::AlterProcedureFact {
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
                        Some(crate::_internal::analysis::facts::FunctionSigFact {
                            name: Self::path_ref_to_qualified_name(&path).unwrap_or_else(|| {
                                QualifiedName::new(None, Ident::new("unknown".to_string(), false))
                            }),
                            params: Self::extract_signature_params(sig.param_list()),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Some(StatementFact::DropProcedure(
            crate::_internal::analysis::facts::DropProcedureFact {
                signatures: sigs,
                if_exists: node.if_exists().is_some(),
                cascade: Self::is_cascade(node.drop_behavior()),
            },
        ))
    }

    fn extract_signature_params(params: Option<ast::ParamList>) -> Vec<String> {
        params
            .map(|params| {
                params
                    .params()
                    .filter_map(|param| {
                        if matches!(param.mode(), Some(ast::ParamMode::ParamOut(_))) {
                            return None;
                        }
                        Some(
                            param
                                .ty()
                                .map(|ty| ty.syntax().text().to_string())
                                .unwrap_or_else(|| "unknown".to_string()),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn extract_create_aggregate(node: &ast::CreateAggregate) -> Option<StatementFact> {
        let name = Self::path_to_qualified_name(&node.aggregate_name()?.path()?)?;
        let params = if let Some(params) = node.param_list() {
            params
                .params()
                .map(|param| Self::extract_param(&param))
                .collect()
        } else {
            Self::extract_attribute_list(node.attribute_list())
                .into_iter()
                .find(|attribute| attribute.name.eq_ignore_ascii_case("basetype"))
                .filter(|attribute| {
                    !matches!(attribute.value.to_ascii_lowercase().as_str(), "any" | "*")
                })
                .map(|attribute| {
                    vec![crate::_internal::analysis::facts::ParamFact {
                        mode: crate::_internal::analysis::facts::ParamModeFact::In,
                        name: None,
                        ty: attribute.value,
                        default: None,
                    }]
                })
                .unwrap_or_default()
        };
        Some(StatementFact::CreateAggregate(
            crate::_internal::analysis::facts::CreateAggregateFact {
                name,
                or_replace: node.or_replace().is_some(),
                params,
            },
        ))
    }

    fn extract_alter_aggregate(node: &ast::AlterAggregate) -> Option<StatementFact> {
        let aggregate = node.aggregate()?;
        let name = Self::path_ref_to_qualified_name(&aggregate.path_ref()?)?;
        let params = Self::extract_signature_params(aggregate.param_list());
        let action = match node.action()? {
            ast::AlterAggregateAction::AggregateRenameTo(rename) => {
                let to = Self::path_to_qualified_name(&rename.aggregate_name()?.path()?)?
                    .name
                    .resolve();
                crate::_internal::analysis::facts::AlterFunctionAction::Rename {
                    from: name.name.resolve(),
                    to,
                }
            }
            ast::AlterAggregateAction::OwnerTo(owner) => {
                crate::_internal::analysis::facts::AlterFunctionAction::OwnerChange(Self::extract_role(
                    &owner.role_ref()?,
                ))
            }
            ast::AlterAggregateAction::SetSchema(set_schema) => {
                crate::_internal::analysis::facts::AlterFunctionAction::SchemaChange {
                    new_schema: Self::resolve_ast_identifier(&set_schema.schema_ref()?),
                }
            }
        };
        Some(StatementFact::AlterAggregate(
            crate::_internal::analysis::facts::AlterAggregateFact {
                name,
                params,
                action,
            },
        ))
    }

    fn extract_drop_aggregate(node: &ast::DropAggregate) -> Option<StatementFact> {
        let signatures = node
            .aggregates()
            .filter_map(|aggregate| {
                Some(crate::_internal::analysis::facts::FunctionSigFact {
                    name: Self::path_ref_to_qualified_name(&aggregate.path_ref()?)?,
                    params: Self::extract_signature_params(aggregate.param_list()),
                })
            })
            .collect();
        Some(StatementFact::DropAggregate(
            crate::_internal::analysis::facts::DropAggregateFact {
                signatures,
                if_exists: node.if_exists().is_some(),
                cascade: Self::is_cascade(node.drop_behavior()),
            },
        ))
    }

    fn extract_attribute_list(
        list: Option<ast::AttributeList>,
    ) -> Vec<crate::_internal::analysis::facts::AttributeFact> {
        list.map(|list| {
            list.attribute_options()
                .map(|option| crate::_internal::analysis::facts::AttributeFact {
                    name: option
                        .name()
                        .map(|name| {
                            Self::resolve_identifier_token(name.syntax().text().to_string().trim())
                        })
                        .unwrap_or_default(),
                    value: option
                        .attribute_value()
                        .map(|value| {
                            value
                                .literal()
                                .and_then(|literal| Self::resolve_string_literal(&literal))
                                .unwrap_or_else(|| {
                                    value.syntax().text().to_string().trim().to_string()
                                })
                        })
                        .unwrap_or_else(|| "true".to_string()),
                })
                .collect()
        })
        .unwrap_or_default()
    }

    fn extract_publication_object(
        object: ast::PublicationObject,
    ) -> Option<crate::_internal::analysis::facts::PublicationObjectFact> {
        match object {
            ast::PublicationObject::PublicationObjectTable(object) => {
                let path = object.table_name_ref()?.path_ref()?;
                Some(crate::_internal::analysis::facts::PublicationObjectFact::Table {
                    name: Self::path_ref_to_qualified_name(&path)?,
                    only: object.only_token().is_some(),
                    include_partitions: object.star_token().is_some(),
                    columns: object.column_ref_list().map(|columns| {
                        columns
                            .column_name_refs()
                            .map(|name| Self::resolve_ast_identifier(&name))
                            .collect()
                    }),
                    row_filter: object.where_condition_clause().and_then(|where_clause| {
                        where_clause
                            .expr()
                            .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
                            .map(crate::_internal::analysis::facts::PublicationRowFilter::Parsed)
                    }),
                })
            }
            ast::PublicationObject::PublicationObjectTablesInSchema(object) => {
                object.schema_ref().map(|schema_ref| {
                    crate::_internal::analysis::facts::PublicationObjectFact::SchemaTables {
                        schema: Self::resolve_ast_identifier(&schema_ref),
                        row_filter: object.where_condition_clause().and_then(|where_clause| {
                            where_clause
                                .expr()
                                .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
                                .map(crate::_internal::analysis::facts::PublicationRowFilter::Parsed)
                        }),
                    }
                })
            }
            ast::PublicationObject::PublicationObjectCurrentSchema(_) => {
                Some(crate::_internal::analysis::facts::PublicationObjectFact::CurrentSchemaShorthand)
            }
        }
    }

    fn extract_create_publication(
        node: &squawk_syntax::ast::CreatePublication,
    ) -> Option<StatementFact> {
        let name = node
            .publication()
            .map(|publication| Self::resolve_ast_identifier(&publication))
            .unwrap_or_default();
        let scope = match node.publication_for_clause() {
            Some(ast::PublicationForClause::ForAllPublicationObjects(all_objects)) => {
                crate::_internal::analysis::facts::PublicationScope::AllTables {
                    except: all_objects
                        .except_table_clause()
                        .map(|clause| {
                            clause
                                .except_table_names()
                                .filter_map(|name| name.table_relation_name())
                                .filter_map(|name| name.table_name_ref())
                                .filter_map(|name| name.path_ref())
                                .filter_map(|path| Self::path_ref_to_qualified_name(&path))
                                .map(|name| name.name.resolve())
                                .collect()
                        })
                        .unwrap_or_default(),
                }
            }
            Some(ast::PublicationForClause::ForPublicationObjects(objects)) => {
                crate::_internal::analysis::facts::PublicationScope::Explicit(
                    objects
                        .publication_objects()
                        .filter_map(Self::extract_publication_object)
                        .collect(),
                )
            }
            None => crate::_internal::analysis::facts::PublicationScope::Explicit(Vec::new()),
        };
        let params =
            Self::extract_attribute_list(node.with_params().and_then(|with| with.attribute_list()));

        Some(StatementFact::CreatePublication(
            crate::_internal::analysis::facts::CreatePublicationFact {
                name,
                scope,
                params,
            },
        ))
    }

    fn extract_alter_publication(
        node: &squawk_syntax::ast::AlterPublication,
    ) -> Option<StatementFact> {
        let name = Self::resolve_ast_identifier(&node.publication_ref()?);
        let action = match node.action()? {
            ast::AlterPublicationAction::AddPublicationObjects(action) => {
                crate::_internal::analysis::facts::AlterPublicationActionFact::AddObjects(
                    action
                        .publication_objects()
                        .filter_map(Self::extract_publication_object)
                        .collect(),
                )
            }
            ast::AlterPublicationAction::DropPublicationObjects(action) => {
                crate::_internal::analysis::facts::AlterPublicationActionFact::DropObjects(
                    action
                        .publication_objects()
                        .filter_map(Self::extract_publication_object)
                        .collect(),
                )
            }
            ast::AlterPublicationAction::SetPublicationObjects(action) => {
                crate::_internal::analysis::facts::AlterPublicationActionFact::SetObjects(
                    crate::_internal::analysis::facts::PublicationScope::Explicit(
                        action
                            .publication_objects()
                            .filter_map(Self::extract_publication_object)
                            .collect(),
                    ),
                )
            }
            ast::AlterPublicationAction::SetAllPublicationObjectList(action) => {
                let except = action
                    .except_table_clause()
                    .map(|clause| {
                        clause
                            .except_table_names()
                            .filter_map(|name| name.table_relation_name())
                            .filter_map(|name| name.table_name_ref())
                            .filter_map(|name| name.path_ref())
                            .filter_map(|path| Self::path_ref_to_qualified_name(&path))
                            .map(|name| name.name.resolve())
                            .collect()
                    })
                    .unwrap_or_default();
                crate::_internal::analysis::facts::AlterPublicationActionFact::SetObjects(
                    crate::_internal::analysis::facts::PublicationScope::AllTables { except },
                )
            }
            ast::AlterPublicationAction::SetOptions(action) => {
                crate::_internal::analysis::facts::AlterPublicationActionFact::SetOptions(
                    Self::extract_attribute_list(action.attribute_list()),
                )
            }
            ast::AlterPublicationAction::OwnerTo(action) => {
                crate::_internal::analysis::facts::AlterPublicationActionFact::OwnerChange(Self::extract_role(
                    &action.role_ref()?,
                ))
            }
            ast::AlterPublicationAction::PublicationRenameTo(action) => {
                crate::_internal::analysis::facts::AlterPublicationActionFact::Rename {
                    to: Self::resolve_ast_identifier(&action.publication()?),
                }
            }
        };
        Some(StatementFact::AlterPublication(
            crate::_internal::analysis::facts::AlterPublicationFact { name, action },
        ))
    }

    fn extract_drop_publication(
        node: &squawk_syntax::ast::DropPublication,
    ) -> Option<StatementFact> {
        let names = node
            .publication_refs()
            .map(|publication| Self::resolve_ast_identifier(&publication))
            .collect();
        Some(StatementFact::DropPublication(
            crate::_internal::analysis::facts::DropPublicationFact {
                names,
                if_exists: node.if_exists().is_some(),
                cascade: Self::is_cascade(node.drop_behavior()),
            },
        ))
    }

    fn extract_create_subscription(
        node: &squawk_syntax::ast::CreateSubscription,
    ) -> Option<StatementFact> {
        let name = node
            .subscription()
            .map(|subscription| Self::resolve_ast_identifier(&subscription));
        let connection = match node.source() {
            Some(ast::SubscriptionSource::ServerClause(server)) => {
                crate::_internal::analysis::facts::ConnectionTarget::Server(
                    server
                        .server_ref()
                        .map(|server| Self::resolve_ast_identifier(&server)),
                )
            }
            Some(ast::SubscriptionSource::ConnectionClause(connection)) => {
                crate::_internal::analysis::facts::ConnectionTarget::Literal(
                    connection
                        .literal()
                        .and_then(|literal| Self::resolve_string_literal(&literal)),
                )
            }
            None => crate::_internal::analysis::facts::ConnectionTarget::Literal(None),
        };
        let publications = node
            .publication_refs()
            .map(|publication| Self::resolve_ast_identifier(&publication))
            .collect();
        let params = node
            .with_params()
            .map(|with| Self::extract_attribute_list(with.attribute_list()));

        Some(StatementFact::CreateSubscription(
            crate::_internal::analysis::facts::CreateSubscriptionFact {
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
        let name = Self::resolve_ast_identifier(&node.subscription_ref()?);
        let action = match node.action()? {
            ast::AlterSubscriptionAction::ConnectionClause(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::SetConnection(
                    crate::_internal::analysis::facts::ConnectionTarget::Literal(
                        action
                            .literal()
                            .and_then(|literal| Self::resolve_string_literal(&literal)),
                    ),
                )
            }
            ast::AlterSubscriptionAction::ServerClause(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::SetServer(
                    action
                        .server_ref()
                        .map(|server| Self::resolve_ast_identifier(&server)),
                )
            }
            ast::AlterSubscriptionAction::SetPublication(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::Publications {
                    mode: crate::_internal::analysis::facts::SubscriptionPublicationMode::Set,
                    publications: action
                        .publication_refs()
                        .map(|publication| Self::resolve_ast_identifier(&publication))
                        .collect(),
                    params: Self::extract_attribute_list(
                        action
                            .with_params()
                            .and_then(|params| params.attribute_list()),
                    ),
                }
            }
            ast::AlterSubscriptionAction::AddPublication(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::Publications {
                    mode: crate::_internal::analysis::facts::SubscriptionPublicationMode::Add,
                    publications: action
                        .publication_refs()
                        .map(|publication| Self::resolve_ast_identifier(&publication))
                        .collect(),
                    params: Self::extract_attribute_list(
                        action
                            .with_params()
                            .and_then(|params| params.attribute_list()),
                    ),
                }
            }
            ast::AlterSubscriptionAction::DropSubscriptionPublication(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::Publications {
                    mode: crate::_internal::analysis::facts::SubscriptionPublicationMode::Drop,
                    publications: action
                        .publication_refs()
                        .map(|publication| Self::resolve_ast_identifier(&publication))
                        .collect(),
                    params: Self::extract_attribute_list(
                        action
                            .with_params()
                            .and_then(|params| params.attribute_list()),
                    ),
                }
            }
            ast::AlterSubscriptionAction::RefreshPublication(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::RefreshPublication(
                    Self::extract_attribute_list(
                        action
                            .with_params()
                            .and_then(|params| params.attribute_list()),
                    ),
                )
            }
            ast::AlterSubscriptionAction::EnableSubscription(_) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::SetEnabled(true)
            }
            ast::AlterSubscriptionAction::DisableSubscription(_) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::SetEnabled(false)
            }
            ast::AlterSubscriptionAction::SetOptions(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::SetOptions(
                    Self::extract_attribute_list(action.attribute_list()),
                )
            }
            ast::AlterSubscriptionAction::SkipSubscription(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::Skip(
                    Self::extract_attribute_list(action.attribute_list()),
                )
            }
            ast::AlterSubscriptionAction::OwnerTo(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::OwnerChange(
                    Self::extract_role(&action.role_ref()?),
                )
            }
            ast::AlterSubscriptionAction::SubscriptionRenameTo(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::Rename {
                    to: Self::resolve_ast_identifier(&action.subscription()?),
                }
            }
        };
        Some(StatementFact::AlterSubscription(
            crate::_internal::analysis::facts::AlterSubscriptionFact { name, action },
        ))
    }

    fn extract_drop_subscription(
        node: &squawk_syntax::ast::DropSubscription,
    ) -> Option<StatementFact> {
        let name = Self::resolve_ast_identifier(&node.subscription_ref()?);
        Some(StatementFact::DropSubscription(
            crate::_internal::analysis::facts::DropSubscriptionFact {
                name,
                if_exists: node.if_exists().is_some(),
            },
        ))
    }

    fn extract_role(role_ref: &squawk_syntax::ast::RoleRef) -> crate::_internal::analysis::facts::RoleFact {
        if let Some(token) = role_ref.ident_token() {
            let name = Self::resolve_identifier_token(token.text());
            return crate::_internal::analysis::facts::RoleFact::Named {
                name,
                via_legacy_group_syntax: role_ref.group_token().is_some(),
            };
        }
        if role_ref.current_role_token().is_some() {
            return crate::_internal::analysis::facts::RoleFact::CurrentRole;
        }
        if role_ref.current_user_token().is_some() {
            return crate::_internal::analysis::facts::RoleFact::CurrentUser;
        }
        if role_ref.session_user_token().is_some() {
            return crate::_internal::analysis::facts::RoleFact::SessionUser;
        }
        let via_group = role_ref.group_token().is_some();
        if let Some(token) = role_ref
            .syntax()
            .descendants_with_tokens()
            .filter_map(|x| x.into_token())
            .find(|t| t.kind() != SyntaxKind::WHITESPACE && t.kind() != SyntaxKind::COMMENT)
        {
            let name = Self::resolve_identifier_token(token.text());
            return crate::_internal::analysis::facts::RoleFact::Named {
                name,
                via_legacy_group_syntax: via_group,
            };
        }
        crate::_internal::analysis::facts::RoleFact::Unknown
    }

    fn extract_role_node(role: &squawk_syntax::ast::Role) -> crate::_internal::analysis::facts::RoleFact {
        if let Some(token) = role.ident_token() {
            return crate::_internal::analysis::facts::RoleFact::Named {
                name: Self::resolve_identifier_token(token.text()),
                via_legacy_group_syntax: role.group_token().is_some(),
            };
        }
        if role.current_role_token().is_some() {
            return crate::_internal::analysis::facts::RoleFact::CurrentRole;
        }
        if role.current_user_token().is_some() {
            return crate::_internal::analysis::facts::RoleFact::CurrentUser;
        }
        if role.session_user_token().is_some() {
            return crate::_internal::analysis::facts::RoleFact::SessionUser;
        }
        crate::_internal::analysis::facts::RoleFact::Unknown
    }

    fn extract_create_role(node: &squawk_syntax::ast::CreateRole) -> Option<StatementFact> {
        let name = Self::resolve_identifier_token(node.role()?.ident_token()?.text());
        let (inherits, can_login, unsupported) =
            Self::extract_create_role_options(node.role_option_list(), false);
        if unsupported {
            return None;
        }
        Some(StatementFact::CreateRole(
            crate::_internal::analysis::facts::CreateRoleFact {
                name,
                inherits,
                can_login,
            },
        ))
    }

    fn extract_create_user(node: &squawk_syntax::ast::CreateUser) -> Option<StatementFact> {
        let name = Self::resolve_identifier_token(node.role()?.ident_token()?.text());
        let (inherits, can_login, unsupported) =
            Self::extract_create_role_options(node.role_option_list(), true);
        if unsupported {
            return None;
        }
        Some(StatementFact::CreateRole(
            crate::_internal::analysis::facts::CreateRoleFact {
                name,
                inherits,
                can_login,
            },
        ))
    }

    fn extract_create_role_options(
        options: Option<squawk_syntax::ast::RoleOptionList>,
        default_login: bool,
    ) -> (bool, bool, bool) {
        let mut inherits = true;
        let mut can_login = default_login;
        let mut unsupported = false;
        if let Some(options) = options {
            for option in options.role_options() {
                match option {
                    ast::RoleOption::RoleOptionInherit(_) => inherits = true,
                    ast::RoleOption::RoleOptionGeneric(option) => {
                        let option = option.syntax().text().to_string().to_ascii_lowercase();
                        match option.trim() {
                            "inherit" => inherits = true,
                            "noinherit" => inherits = false,
                            "login" => can_login = true,
                            "nologin" => can_login = false,
                            _ => unsupported = true,
                        }
                    }
                    _ => unsupported = true,
                }
            }
        }
        (inherits, can_login, unsupported)
    }

    fn extract_alter_role(node: &squawk_syntax::ast::AlterRole) -> Option<StatementFact> {
        let name = Self::extract_role(&node.role_ref()?);
        let inherits = node.action().and_then(|a| match a {
            ast::AlterRoleAction::RoleOptionList(ol) => {
                let mut found = None;
                for o in ol.role_options() {
                    match o {
                        ast::RoleOption::RoleOptionInherit(_) => found = Some(true),
                        ast::RoleOption::RoleOptionGeneric(option) => {
                            match option
                                .ident_token()
                                .map(|token| token.text().to_ascii_lowercase())
                                .as_deref()
                            {
                                Some("inherit") => found = Some(true),
                                Some("noinherit") => found = Some(false),
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
                found
            }
            _ => None,
        });
        Some(StatementFact::AlterRole(
            crate::_internal::analysis::facts::AlterRoleFact { name, inherits },
        ))
    }

    fn extract_drop_role(node: &squawk_syntax::ast::DropRole) -> Option<StatementFact> {
        let names = node
            .role_refs()
            .map(|r| {
                r.ident_token()
                    .map(|t| Self::resolve_identifier_token(t.text()))
                    .unwrap_or_default()
            })
            .collect();
        Some(StatementFact::DropRole(
            crate::_internal::analysis::facts::DropRoleFact {
                names,
                if_exists: node.if_exists().is_some(),
            },
        ))
    }

    fn extract_privilege_from_revoke_command(
        cmd: &RevokeCommand,
    ) -> crate::_internal::analysis::facts::PrivilegeFact {
        if cmd.select_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Select
        } else if cmd.insert_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Insert
        } else if cmd.update_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Update
        } else if cmd.delete_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Delete
        } else if cmd.truncate_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Truncate
        } else if cmd.references_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::References
        } else if cmd.trigger_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Trigger
        } else if cmd.execute_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Execute
        } else if cmd.create_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Create
        } else if cmd.temp_token().is_some() || cmd.temporary_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Temporary
        } else if cmd.alter_token().is_some() && cmd.system_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::AlterSystem
        } else if cmd.all_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::All
        } else if let Some(ident) = cmd.ident_token() {
            let raw = ident.text().to_string();
            let name = Self::resolve_identifier_token(&raw);
            if !Self::identifier_from_token(&raw).quoted && name == "maintain" {
                crate::_internal::analysis::facts::PrivilegeFact::Maintain
            } else {
                crate::_internal::analysis::facts::PrivilegeFact::RoleMembership(name)
            }
        } else if let Some(role_ref) = cmd.role_ref() {
            // Squawk 2.63.0 exposes PostgreSQL 17 MAINTAIN through the
            // grammar's generic identifier branch (there is no
            // `maintain_token()` accessor), so recognize it before treating
            // the same branch as legacy role-membership syntax.
            if let Some(ident) = role_ref.ident_token() {
                let raw = ident.text().to_string();
                let name = Self::resolve_identifier_token(&raw);
                if !Self::identifier_from_token(&raw).quoted {
                    match name.as_str() {
                        "insert" => return crate::_internal::analysis::facts::PrivilegeFact::Insert,
                        "update" => return crate::_internal::analysis::facts::PrivilegeFact::Update,
                        "delete" => return crate::_internal::analysis::facts::PrivilegeFact::Delete,
                        "maintain" => return crate::_internal::analysis::facts::PrivilegeFact::Maintain,
                        _ => {}
                    }
                }
                crate::_internal::analysis::facts::PrivilegeFact::RoleMembership(name)
            } else {
                let text = role_ref.syntax().text().to_string();
                match text.to_lowercase().as_str() {
                    "insert" => crate::_internal::analysis::facts::PrivilegeFact::Insert,
                    "update" => crate::_internal::analysis::facts::PrivilegeFact::Update,
                    "delete" => crate::_internal::analysis::facts::PrivilegeFact::Delete,
                    "maintain" => crate::_internal::analysis::facts::PrivilegeFact::Maintain,
                    _ => crate::_internal::analysis::facts::PrivilegeFact::Unknown,
                }
            }
        } else if let Some(ident) = cmd.syntax().descendants().find_map(PathSegment::cast) {
            crate::_internal::analysis::facts::PrivilegeFact::Named(ident.text().to_string())
        } else {
            crate::_internal::analysis::facts::PrivilegeFact::Unknown
        }
    }

    fn extract_grant_target_from_privilege_objects(
        po: Option<squawk_syntax::ast::PrivilegeObjects>,
        _syntax: &squawk_syntax::SyntaxNode,
    ) -> Option<crate::_internal::analysis::facts::GrantTarget> {
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
            PrivilegeObjects::PrivilegeAllTablesInSchema(pais) => {
                let schemas: Vec<_> = pais
                    .schema_refs()
                    .filter_map(|sr| {
                        sr.ident_token()
                            .map(|t| Self::resolve_identifier_token(t.text()))
                    })
                    .collect();
                return if schemas.is_empty() {
                    None
                } else {
                    Some(crate::_internal::analysis::facts::GrantTarget::AllTablesInSchema(
                        schemas,
                    ))
                };
            }
            _ => return None,
        };
        if names.is_empty() {
            None
        } else {
            Some(crate::_internal::analysis::facts::GrantTarget::Tables(names))
        }
    }

    fn extract_role_membership_option(
        option: &squawk_syntax::ast::GrantRoleOption,
    ) -> Option<crate::_internal::analysis::facts::RoleMembershipOptionFact> {
        let name = option
            .grant_role_option_name()?
            .syntax()
            .text()
            .to_string()
            .trim()
            .to_ascii_lowercase();
        let value = if option.false_token().is_some() {
            false
        } else if option.true_token().is_some() || option.option_token().is_some() {
            true
        } else {
            return None;
        };
        match name.as_str() {
            "admin" => Some(crate::_internal::analysis::facts::RoleMembershipOptionFact::Admin(
                value,
            )),
            "inherit" => Some(crate::_internal::analysis::facts::RoleMembershipOptionFact::Inherit(
                value,
            )),
            "set" => Some(crate::_internal::analysis::facts::RoleMembershipOptionFact::Set(value)),
            _ => None,
        }
    }

    fn extract_grant(node: &Grant) -> Option<StatementFact> {
        let privileges = match node.privileges() {
            Some(ast::Privileges::AllPrivileges(_)) => crate::_internal::analysis::facts::PrivilegeSpec::All,
            Some(ast::Privileges::RevokeCommandList(commands)) => {
                crate::_internal::analysis::facts::PrivilegeSpec::List(
                    commands
                        .revoke_commands()
                        .map(|command| Self::extract_privilege_from_revoke_command(&command))
                        .collect(),
                )
            }
            None => crate::_internal::analysis::facts::PrivilegeSpec::List(Vec::new()),
        };

        let target = if let Some(objects) = node
            .on_privilege_objects_clause()
            .and_then(|clause| clause.privilege_objects())
        {
            Self::extract_grant_target_from_privilege_objects(Some(objects), node.syntax())?
        } else {
            let crate::_internal::analysis::facts::PrivilegeSpec::List(items) = &privileges else {
                return None;
            };
            let roles = items
                .iter()
                .map(|item| match item {
                    crate::_internal::analysis::facts::PrivilegeFact::RoleMembership(name) => {
                        Some(name.clone())
                    }
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()?;
            if roles.is_empty() {
                return None;
            }
            crate::_internal::analysis::facts::GrantTarget::Roles(roles)
        };

        let grantees = node
            .role_ref_list()
            .map(|rrl| rrl.role_refs().map(|r| Self::extract_role(&r)).collect())
            .unwrap_or_default();
        let (with_grant_option, role_options) = match node.grant_with_clause() {
            None => (false, Vec::new()),
            Some(clause) if clause.grant_option().is_some() => (true, Vec::new()),
            Some(clause) => {
                let list = clause.grant_role_option_list()?;
                let options = list
                    .grant_role_options()
                    .map(|option| Self::extract_role_membership_option(&option))
                    .collect::<Option<Vec<_>>>()?;
                (false, options)
            }
        };
        let granted_by = node
            .granted_by_clause()
            .and_then(|clause| clause.role_ref())
            .map(|role| Self::extract_role(&role));

        Some(StatementFact::Grant(crate::_internal::analysis::facts::GrantFact {
            privileges,
            target,
            grantees,
            with_grant_option,
            role_options,
            granted_by,
        }))
    }

    fn extract_revoke(node: &Revoke) -> Option<StatementFact> {
        let (grant_option_only, role_option) = match node.revoke_option_for() {
            None => (false, None),
            Some(ast::RevokeOptionFor::GrantOptionFor(_)) => (true, None),
            Some(ast::RevokeOptionFor::AdminOptionFor(_)) => (
                false,
                Some(crate::_internal::analysis::facts::RoleMembershipOptionFact::Admin(
                    false,
                )),
            ),
            Some(ast::RevokeOptionFor::InheritOptionFor(_)) => (
                false,
                Some(crate::_internal::analysis::facts::RoleMembershipOptionFact::Inherit(
                    false,
                )),
            ),
            Some(ast::RevokeOptionFor::SetOptionFor(_)) => (
                false,
                Some(crate::_internal::analysis::facts::RoleMembershipOptionFact::Set(false)),
            ),
        };

        let privileges = match node.privileges() {
            Some(ast::Privileges::AllPrivileges(_)) => crate::_internal::analysis::facts::PrivilegeSpec::All,
            Some(ast::Privileges::RevokeCommandList(commands)) => {
                crate::_internal::analysis::facts::PrivilegeSpec::List(
                    commands
                        .revoke_commands()
                        .map(|command| Self::extract_privilege_from_revoke_command(&command))
                        .collect(),
                )
            }
            None => crate::_internal::analysis::facts::PrivilegeSpec::List(Vec::new()),
        };

        let target = if let Some(objects) = node
            .on_privilege_objects_clause()
            .and_then(|clause| clause.privilege_objects())
        {
            Self::extract_grant_target_from_privilege_objects(Some(objects), node.syntax())?
        } else {
            let ast::Privileges::RevokeCommandList(commands) = node.privileges()? else {
                return None;
            };
            let roles = commands
                .revoke_commands()
                .map(
                    |command| match Self::extract_privilege_from_revoke_command(&command) {
                        crate::_internal::analysis::facts::PrivilegeFact::RoleMembership(name) => Some(name),
                        _ => None,
                    },
                )
                .collect::<Option<Vec<_>>>()?;
            if roles.is_empty() {
                return None;
            }
            crate::_internal::analysis::facts::GrantTarget::Roles(roles)
        };

        let revokees = node
            .role_ref_list()
            .map(|rrl| rrl.role_refs().map(|r| Self::extract_role(&r)).collect())
            .unwrap_or_default();
        let granted_by = node
            .granted_by_clause()
            .and_then(|clause| clause.role_ref())
            .map(|role| Self::extract_role(&role));
        let cascade = Self::is_cascade(node.drop_behavior());

        Some(StatementFact::Revoke(crate::_internal::analysis::facts::RevokeFact {
            grant_option_only,
            role_option,
            privileges,
            target,
            revokees,
            granted_by,
            cascade,
        }))
    }

    fn extract_db_option(
        opt: squawk_syntax::ast::DatabaseOption,
    ) -> crate::_internal::analysis::facts::DatabaseOptionFact {
        let value_for = |default: bool, literal: Option<ast::Literal>| {
            if default {
                crate::_internal::analysis::facts::DatabaseOptionValue::Default
            } else {
                crate::_internal::analysis::facts::DatabaseOptionValue::Literal(
                    literal.map(|l| l.syntax().text().to_string().trim_matches('\'').to_string()),
                )
            }
        };

        match opt {
            ast::DatabaseOption::DatabaseOptionOwner(opt) => {
                crate::_internal::analysis::facts::DatabaseOptionFact::Owner(value_for(
                    opt.default_token().is_some(),
                    opt.literal(),
                ))
            }
            ast::DatabaseOption::DatabaseOptionTemplate(opt) => {
                crate::_internal::analysis::facts::DatabaseOptionFact::Template(value_for(
                    opt.default_token().is_some(),
                    opt.literal(),
                ))
            }
            ast::DatabaseOption::DatabaseOptionEncoding(opt) => {
                crate::_internal::analysis::facts::DatabaseOptionFact::Encoding(value_for(
                    opt.default_token().is_some(),
                    opt.literal(),
                ))
            }
            ast::DatabaseOption::DatabaseOptionTablespace(opt) => {
                crate::_internal::analysis::facts::DatabaseOptionFact::Tablespace(value_for(
                    opt.default_token().is_some(),
                    opt.literal(),
                ))
            }
            ast::DatabaseOption::DatabaseOptionConnectionLimit(opt) => {
                crate::_internal::analysis::facts::DatabaseOptionFact::ConnectionLimit(value_for(
                    opt.default_token().is_some(),
                    opt.literal(),
                ))
            }
            ast::DatabaseOption::DatabaseOptionGeneric(opt) => {
                let value = value_for(opt.default_token().is_some(), opt.literal());
                opt.ident_token()
                    .map(|ident| {
                        crate::_internal::analysis::facts::DatabaseOptionFact::Named(
                            ident.text().to_string(),
                            value.clone(),
                        )
                    })
                    .unwrap_or(crate::_internal::analysis::facts::DatabaseOptionFact::Unknown(value))
            }
        }
    }

    fn extract_create_database(node: &CreateDatabase) -> Option<StatementFact> {
        let name = node
            .database()
            .and_then(|d| d.ident_token())
            .map(|t| Self::resolve_identifier_token(t.text()))
            .unwrap_or_default();
        let options = node
            .database_option_list()
            .map(|ol| ol.database_options().map(Self::extract_db_option).collect())
            .unwrap_or_default();
        Some(StatementFact::CreateDatabase(
            crate::_internal::analysis::facts::CreateDatabaseFact { name, options },
        ))
    }

    fn extract_alter_database(node: &ast::AlterDatabase) -> Option<StatementFact> {
        use squawk_syntax::ast::AlterDatabaseAction;
        let name = node
            .database_ref()
            .and_then(|dr| dr.ident_token())
            .map(|t| Self::identifier_from_token(t.text()))
            .unwrap_or_else(|| Ident::new(String::new(), false));
        let name = QualifiedName::new(None, name);

        let action = match node.action()? {
            AlterDatabaseAction::DatabaseRenameTo(rt) => {
                crate::_internal::analysis::facts::AlterDatabaseAction::Rename {
                    to: rt
                        .database()
                        .and_then(|d| d.ident_token())
                        .map(|t| Self::resolve_identifier_token(t.text()))
                        .unwrap_or_default(),
                }
            }
            AlterDatabaseAction::OwnerTo(ot) => {
                crate::_internal::analysis::facts::AlterDatabaseAction::OwnerChange(Self::extract_role(
                    &ot.role_ref()?,
                ))
            }
            AlterDatabaseAction::SetTablespace(st) => {
                crate::_internal::analysis::facts::AlterDatabaseAction::TablespaceChange {
                    new_tablespace: st
                        .tablespace_ref()
                        .and_then(|tr| tr.ident_token())
                        .map(|t| Self::resolve_identifier_token(t.text()))
                        .unwrap_or_default(),
                }
            }
            AlterDatabaseAction::SetConfigParam(scp) => {
                crate::_internal::analysis::facts::AlterDatabaseAction::SetConfigParam {
                    param: scp
                        .config_parameter_ref()
                        .and_then(|cpr| cpr.path_ref())
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                        .map(|qn| qn.name.resolve())
                        .unwrap_or_default(),
                }
            }
            AlterDatabaseAction::ResetConfigParam(rcp) => {
                crate::_internal::analysis::facts::AlterDatabaseAction::ResetConfigParam {
                    param: rcp
                        .config_parameter_ref()
                        .and_then(|cpr| cpr.path_ref())
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                        .map(|qn| qn.name.resolve()),
                }
            }
            AlterDatabaseAction::RefreshCollationVersion(_) => {
                crate::_internal::analysis::facts::AlterDatabaseAction::RefreshCollationVersion
            }
            AlterDatabaseAction::DatabaseOptionList(ol) => {
                crate::_internal::analysis::facts::AlterDatabaseAction::OptionChanges(
                    ol.database_options().map(Self::extract_db_option).collect(),
                )
            }
        };

        Some(StatementFact::AlterDatabase(
            crate::_internal::analysis::facts::AlterDatabaseFact { name, action },
        ))
    }

    fn extract_drop_database(node: &ast::DropDatabase) -> Option<StatementFact> {
        let name = node
            .database_ref()
            .and_then(|dr| dr.ident_token())
            .map(|t| Self::identifier_from_token(t.text()))
            .unwrap_or_else(|| Ident::new(String::new(), false));
        let name = QualifiedName::new(None, name);
        Some(StatementFact::DropDatabase(
            crate::_internal::analysis::facts::DropDatabaseFact {
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
                    .filter(|qn| qn.schema.is_none())?
                    .name
                    .resolve()
                    .to_lowercase();
                let local = Self::is_local(node.set_scope());

                if setting_name == "search_path" {
                    return match sc.config_assignment() {
                        Some(ast::ConfigAssignment::ToConfigValue(assignment))
                            if assignment.default_token().is_some() =>
                        {
                            Some(StatementFact::SetSearchPath {
                                target: SearchPathTarget::Default,
                                local,
                            })
                        }
                        Some(ast::ConfigAssignment::ToConfigValue(assignment)) => {
                            let schemas: Vec<String> = assignment
                                .config_values()
                                .filter_map(|value| match value {
                                    ast::ConfigValue::ConfigValueName(name) => name
                                        .ident_token()
                                        .map(|token| Self::resolve_identifier_token(token.text())),
                                    ast::ConfigValue::Literal(literal) => {
                                        Self::resolve_string_literal(&literal)
                                    }
                                })
                                .collect();
                            (!schemas.is_empty()).then_some(StatementFact::SetSearchPath {
                                target: SearchPathTarget::Schemas(schemas),
                                local,
                            })
                        }
                        Some(ast::ConfigAssignment::FromCurrent(_)) | None => None,
                    };
                }

                if setting_name == "application_name" {
                    return Some(StatementFact::SchemaNeutralNoop);
                }

                let timeout_setting = match setting_name.as_str() {
                    "lock_timeout" => TimeoutSetting::Lock,
                    "statement_timeout" => TimeoutSetting::Statement,
                    _ => return None,
                };
                let value = match sc.config_assignment() {
                    Some(ast::ConfigAssignment::FromCurrent(_)) => TimeoutSettingValue::Current,
                    Some(ast::ConfigAssignment::ToConfigValue(assignment))
                        if assignment.default_token().is_some() =>
                    {
                        TimeoutSettingValue::Default
                    }
                    Some(ast::ConfigAssignment::ToConfigValue(assignment)) => {
                        let values: Vec<String> = assignment
                            .config_values()
                            .filter_map(|value| match value {
                                ast::ConfigValue::ConfigValueName(name) => {
                                    name.ident_token().map(|token| token.text().to_string())
                                }
                                ast::ConfigValue::Literal(literal) => {
                                    Self::resolve_string_literal(&literal)
                                        .or_else(|| Some(literal.syntax().text().to_string()))
                                }
                            })
                            .collect();
                        if values.len() != 1 {
                            TimeoutSettingValue::Invalid(sc.syntax().text().to_string())
                        } else {
                            match crate::_internal::analysis::settings::parse_timeout_ms(&values[0]) {
                                Ok(milliseconds) => TimeoutSettingValue::Milliseconds(milliseconds),
                                Err(error) => TimeoutSettingValue::Invalid(error),
                            }
                        }
                    }
                    None => TimeoutSettingValue::Invalid(sc.syntax().text().to_string()),
                };
                Some(StatementFact::SetTimeout {
                    setting: timeout_setting,
                    value,
                    local,
                })
            }
            _ => None,
        }
    }

    fn extract_reset(node: &ast::Reset) -> Option<StatementFact> {
        use squawk_syntax::ast::ResetTarget;

        let target = match node.reset_target()? {
            ResetTarget::All(_) => ResetSettingTarget::All,
            ResetTarget::ConfigParameterRef(parameter) => {
                let name = parameter
                    .path_ref()
                    .and_then(|path| Self::path_ref_to_qualified_name(&path))
                    .filter(|name| name.schema.is_none())?
                    .name
                    .resolve()
                    .to_lowercase();
                match name.as_str() {
                    "search_path" => ResetSettingTarget::SearchPath,
                    "lock_timeout" => ResetSettingTarget::LockTimeout,
                    "statement_timeout" => ResetSettingTarget::StatementTimeout,
                    "application_name" => return Some(StatementFact::SchemaNeutralNoop),
                    // An unknown GUC may affect DDL behavior (for example
                    // replication or constraint enforcement). Keep it on the
                    // explicit opaque path instead of silently claiming no
                    // state impact.
                    _ => return None,
                }
            }
            ResetTarget::ResetTimeZone(_) | ResetTarget::ResetTransactionIsolation(_) => {
                return Some(StatementFact::SchemaNeutralNoop);
            }
        };
        Some(StatementFact::ResetSettings { target })
    }

    /// Extract `SET [LOCAL] ROLE { rolename | NONE }`.
    fn extract_set_role(node: &squawk_syntax::ast::SetRole) -> Option<StatementFact> {
        let local = Self::is_local(node.set_scope());
        let role = match node.set_role_target()? {
            ast::SetRoleTarget::SetRoleNone(_) => None,
            ast::SetRoleTarget::RoleRef(role) => Some(Self::extract_role(&role)),
            ast::SetRoleTarget::Literal(literal) => Self::resolve_string_literal(&literal)
                .filter(|name| !name.is_empty())
                .map(|name| crate::_internal::analysis::facts::RoleFact::Named {
                    name,
                    via_legacy_group_syntax: false,
                }),
        };
        if matches!(
            role,
            Some(
                crate::_internal::analysis::facts::RoleFact::CurrentUser
                    | crate::_internal::analysis::facts::RoleFact::CurrentRole
                    | crate::_internal::analysis::facts::RoleFact::SessionUser
            )
        ) {
            // PostgreSQL's SET ROLE grammar accepts a role name or NONE, not
            // the special role-specification keywords accepted by GRANT and
            // OWNER TO. Squawk currently parses these forms, so leave them
            // unsupported rather than simulating SQL PostgreSQL rejects.
            return None;
        }
        Some(StatementFact::SetRole {
            role,
            local,
            is_session_auth: false,
        })
    }

    /// Extract `SET [LOCAL] SESSION AUTHORIZATION { rolename | DEFAULT }`.
    fn extract_set_session_auth(
        node: &squawk_syntax::ast::SetSessionAuth,
    ) -> Option<StatementFact> {
        let local = Self::is_local(node.set_scope());
        let role = match node.set_session_auth_target()? {
            ast::SetSessionAuthTarget::SetSessionAuthDefault(_) => None,
            ast::SetSessionAuthTarget::RoleRef(role) => Some(Self::extract_role(&role)),
            ast::SetSessionAuthTarget::Literal(literal) => Self::resolve_string_literal(&literal)
                .filter(|name| !name.is_empty())
                .map(|name| crate::_internal::analysis::facts::RoleFact::Named {
                    name,
                    via_legacy_group_syntax: false,
                }),
        };
        if matches!(
            role,
            Some(
                crate::_internal::analysis::facts::RoleFact::CurrentUser
                    | crate::_internal::analysis::facts::RoleFact::CurrentRole
                    | crate::_internal::analysis::facts::RoleFact::SessionUser
            )
        ) {
            return None;
        }
        Some(StatementFact::SetRole {
            role,
            local,
            is_session_auth: true,
        })
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
            None if Self::is_and_chain(node.chain_clause()) => {
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
        Some(Self::identifier_from_name(
            segment.text(),
            segment.is_quoted(),
        ))
    }

    fn path_ref_to_qualified_name(path_ref: &squawk_syntax::ast::PathRef) -> Option<QualifiedName> {
        let mut segments = Vec::new();
        let mut current_ref = Some(path_ref.clone());

        while let Some(pr) = current_ref {
            if let Some(segment) = pr.segment() {
                segments.push(Self::identifier_from_name(
                    segment.text(),
                    segment.is_quoted(),
                ));
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

    fn expr_to_qualified_name(expr: ast::Expr) -> Option<QualifiedName> {
        fn collect_segments(expr: ast::Expr, segments: &mut Vec<Ident>) -> bool {
            match expr {
                ast::Expr::NameRef(name) => {
                    segments.push(AstVisitor::identifier_from_name(
                        name.text(),
                        name.is_quoted(),
                    ));
                    true
                }
                ast::Expr::FieldExpr(field) => {
                    let Some(base) = field.base() else {
                        return false;
                    };
                    if !collect_segments(base, segments) {
                        return false;
                    }
                    let Some(name) = field.field() else {
                        return false;
                    };
                    segments.push(AstVisitor::identifier_from_name(
                        name.text(),
                        name.is_quoted(),
                    ));
                    true
                }
                _ => false,
            }
        }

        let mut segments = Vec::new();
        if !collect_segments(expr, &mut segments) || segments.is_empty() {
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
                if let Some(seg) = r.segment() {
                    segments.push(Self::identifier_from_name(seg.text(), seg.is_quoted()));
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
