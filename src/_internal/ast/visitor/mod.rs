use crate::_internal::analysis::expr_ir::ExprIr;
use crate::_internal::analysis::facts::IndexStatisticsColumn;
use crate::_internal::analysis::facts::{
    AggregateArgumentFact, AggregateBindingFact, AggregateCandidateFact, AggregateOnlyClauseFact,
    AggregateReferenceFact, AggregateScopeFact, AlterIndexActionFact, AlterTableActionFact,
    AlterTypeActionFact, AlterTypeFact, ColumnFact, CreateTypeFact, FkFact, LikePropertiesFact,
    LikeSourceFact, LockModeFact, PersistenceFact, ReindexTargetKindFact, RelationTargetFact,
    ReplicaIdentityFact, ResetSettingTarget, SearchPathTarget, StatementFact, TableConstraintFact,
    TimeoutSetting, TimeoutSettingValue, TypeCreationKind,
};
use crate::_internal::ast::identifiers::{Ident, QualifiedName};
use crate::_internal::model::index::{IndexOrder, IndexPredicate, WrittenName};
use squawk_syntax::ast::{
    AlterColumnOption, AlterConstraint, AlterDomain, AlterIndex, AlterSequence, AlterTable,
    AlterTableAction, AlterTrigger, AlterType, AstNode, AttachPartition, Column, ColumnConstraint,
    Constraint, CreateDatabase, CreateDomain, CreateIndex, CreateMaterializedView, CreatePolicy,
    CreateSequence, CreateTable, CreateTableAs, CreateTrigger, CreateType, CreateView, CteName,
    DetachPartition, DropDomain, DropIndex, DropMaterializedView, DropPolicy, DropSequence,
    DropTable, DropTrigger, DropType, DropView, Grant, HasSelectTail, Lock, NameRef, PartitionBy,
    PartitionType, Path, PathRef, PathSegment, PathSegmentRef, RelationNameRef, ReleaseSavepoint,
    Revoke, RevokeCommand, Rollback, SchemaRef, SelectInto, Set, SetSchema, Stmt, TableArg,
    TableConstraint, Truncate,
};
use squawk_syntax::{SyntaxKind, ast};

mod alter_table;
mod databases;
mod grants;
mod indexes;
mod names;
mod publications;
mod roles;
mod routines;
mod schemas;
mod sequences;
mod settings;
mod tables;
mod transactions;
mod triggers_policies;
mod types;
mod views;

/// The `pg_catalog` aggregate function names. A call to one of these in a view
/// target list makes the view non-updatable; the analyzer resolves no catalog
/// functions, so the names are listed rather than looked up. An aggregate in
/// another schema is not recognised and stays unknown.
const BUILTIN_AGGREGATES: &[&str] = &[
    "any_value",
    "array_agg",
    "avg",
    "bit_and",
    "bit_or",
    "bit_xor",
    "bool_and",
    "bool_or",
    "corr",
    "count",
    "covar_pop",
    "covar_samp",
    "cume_dist",
    "dense_rank",
    "every",
    "json_agg",
    "json_agg_strict",
    "json_object_agg",
    "json_object_agg_strict",
    "json_object_agg_unique",
    "json_object_agg_unique_strict",
    "jsonb_agg",
    "jsonb_agg_strict",
    "jsonb_object_agg",
    "jsonb_object_agg_strict",
    "jsonb_object_agg_unique",
    "jsonb_object_agg_unique_strict",
    "max",
    "min",
    "mode",
    "percent_rank",
    "percentile_cont",
    "percentile_disc",
    "range_agg",
    "range_intersect_agg",
    "rank",
    "regr_avgx",
    "regr_avgy",
    "regr_count",
    "regr_intercept",
    "regr_r2",
    "regr_slope",
    "regr_sxx",
    "regr_sxy",
    "regr_syy",
    "stddev",
    "stddev_pop",
    "stddev_samp",
    "string_agg",
    "sum",
    "var_pop",
    "var_samp",
    "variance",
    "xmlagg",
];

/// A view query's updatability under two readings of its unqualified
/// aggregate-named calls, plus those calls for the resolver to place.
///
/// The visitor cannot know the search path, so it hands both readings and the
/// calls to the resolver, which can tell a built-in aggregate from a
/// same-named overload.
struct ViewUpdatabilityOutcome {
    /// The verdict when every unqualified aggregate-named call is its built-in
    /// aggregate.
    with_aggregates: crate::_internal::analysis::facts::ViewUpdatabilityFact,
    /// The verdict when none of them is.
    without_aggregates: crate::_internal::analysis::facts::ViewUpdatabilityFact,
    aggregate_candidates: Vec<AggregateCandidateFact>,
    /// The base relation's alias, or its name when no alias is written.
    select_source_name: Option<String>,
}

impl ViewUpdatabilityOutcome {
    /// A verdict no search path can change, carrying nothing to resolve.
    fn settled(verdict: crate::_internal::analysis::facts::ViewUpdatabilityFact) -> Self {
        Self {
            with_aggregates: verdict,
            without_aggregates: verdict,
            aggregate_candidates: Vec::new(),
            select_source_name: None,
        }
    }
}

pub(crate) struct AstVisitor;

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
                ExprIr::Cast { expr, .. } | ExprIr::UnaryOp { expr, .. } => walk(*expr, columns),
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
        if !literal.is_string() {
            return None;
        }
        Some(literal.decoded_value()?.into_text())
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

    pub(crate) fn extract(stmt: &Stmt) -> Option<StatementFact> {
        let syntax = stmt.syntax();
        match stmt {
            Stmt::CreateTable(node) => return Self::extract_create_table(node),
            Stmt::CreateTableAs(node) => return Self::extract_create_table_as(node),
            Stmt::SelectInto(node) => return Self::extract_select_into(node),
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
            Stmt::Lock(node) => return Self::extract_lock(node),
            Stmt::Truncate(node) => return Self::extract_truncate(node),
            Stmt::Set(node) => return Self::extract_set(node),
            Stmt::Reset(node) => return Self::extract_reset(node),
            Stmt::Grant(node) => return Self::extract_grant(node),
            Stmt::Revoke(node) => return Self::extract_revoke(node),
            Stmt::CreateUser(node) => return Self::extract_create_user(node),
            Stmt::Begin(_) => return Some(StatementFact::BeginTransaction),
            Stmt::Commit(node) => {
                return Some(match node {
                    ast::Commit::CommitPrepared(_) => StatementFact::OpaqueBlock,
                    ast::Commit::CommitTransaction(transaction)
                        if Self::is_and_chain(transaction.chain_clause()) =>
                    {
                        StatementFact::CommitAndChain
                    }
                    ast::Commit::CommitTransaction(_) => StatementFact::CommitTransaction,
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
            Stmt::Reindex(node) => return Self::extract_reindex_fact(node),
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
}
