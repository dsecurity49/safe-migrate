use crate::_internal::analysis::expr_ir::ExprIr;
use crate::_internal::analysis::facts::{
    AggregateArgumentFact, AggregateCandidateFact, AggregateOnlyClauseFact, AggregateReferenceFact,
    AggregateScopeFact, AlterDatabaseAction, AlterPublicationActionFact,
    AlterSubscriptionActionFact, AlterTableActionFact, AlterTypeActionFact, PublicationObjectFact,
    PublicationScope, ResetSettingTarget, RetTypeFact, SearchPathTarget, StatementFact,
    SubscriptionPublicationMode, TableConstraintFact, TimeoutSetting, TimeoutSettingValue,
    TypeCreationKind, ViewUpdatabilityFact,
};
use crate::_internal::ast::identifiers::{Ident, QualifiedName};
use crate::_internal::ast::visitor::AstVisitor;
use crate::_internal::model::index::{IndexOrder, IndexPredicate, WrittenName};
use crate::_internal::model::relation::ViewUpdatabilityReason;
use squawk_syntax::ast::SourceFile;

fn parse_and_extract(sql: &str) -> Vec<StatementFact> {
    let parsed = SourceFile::parse(sql);
    parsed
        .tree()
        .stmts()
        .filter_map(|stmt| AstVisitor::extract(&stmt))
        .collect()
}

fn parse_and_extract_statement(sql: &str) -> Option<StatementFact> {
    let parsed = SourceFile::parse(sql);
    parsed
        .tree()
        .stmts()
        .next()
        .and_then(|stmt| AstVisitor::extract(&stmt))
}

mod expressions;
mod grants_roles;
mod identifiers;
mod objects;
mod relations;
mod settings;
mod statements;
mod transactions;
