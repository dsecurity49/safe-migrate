use crate::common::*;
use safe_migrate::_internal::analysis::evidence::EvidenceCode;
use safe_migrate::_internal::analysis::facts::FunctionSigFact;
use safe_migrate::_internal::analysis::graph::{DependencyEdge, DependencyGraph, DependencyKind};
use safe_migrate::_internal::analysis::mutations::{
    AlterTable, AlterTableActionMutation, DropAggregateMutation, DropFunctionMutation,
    DropProcedureMutation, DropTable, Mutation,
};
use safe_migrate::_internal::analysis::namespace::SearchPathEntry;
use safe_migrate::_internal::analysis::state::{AnalysisState, Confidence, MutationResult};
use safe_migrate::_internal::ast::identifiers::{Ident, ObjectId, QualifiedName};
use safe_migrate::_internal::db::cache::{
    CatalogCoverage, CatalogFamily, ConstraintDependencyCache, GeneratedColumnDependencyCache,
    SchemaCoverage, ViewDependencyCache,
};
use safe_migrate::_internal::model::column::Column;
use safe_migrate::_internal::model::constraint::ConstraintKind;
use safe_migrate::_internal::model::function::{
    FunctionOverlay, FunctionState, ParameterMode, RoutineKind, RoutineParameter, Volatility,
};
use safe_migrate::_internal::model::index::{IndexDefinition, IndexPredicate, index_keys};
use safe_migrate::_internal::model::relation::{
    ColumnAction, Persistence, Privilege, RelationKind, RelationOverlay, RelationState,
};
use safe_migrate::_internal::model::role::{RoleOverlay, RoleState};
use safe_migrate::_internal::model::schema::SchemaState;
use safe_migrate::_internal::model::sequence::{SequenceKind, SequenceOverlay, SequenceState};
use safe_migrate::_internal::model::types::{TypeKind, TypeOverlay, TypeState};
use safe_migrate::_internal::report::violations::Violation;

fn synced_table_routine(columns: &[(&str, &str)]) -> AnalysisState {
    let id = object_id("public", "rows()");
    let mut function = FunctionState::with_inputs(id.clone(), RoutineKind::Function, Vec::new());
    function.return_type = format!(
        "TABLE({})",
        columns
            .iter()
            .map(|(name, ty)| format!("{name} {ty}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    function.returns_set = true;
    function.parameters = columns
        .iter()
        .map(|(name, ty)| RoutineParameter {
            name: Some((*name).to_string()),
            mode: ParameterMode::Table,
            ty: (*ty).to_string(),
        })
        .collect();
    let mut cache = synced_cache();
    cache.functions.insert(id, function);
    AnalysisState::new(cache)
}

fn membership_state(pg_version_num: Option<u32>) -> AnalysisState {
    let mut cache = synced_cache();
    cache.pg_version_num = pg_version_num;
    for name in ["member", "parent"] {
        let id = object_id("", name);
        cache.roles.insert(
            id.clone(),
            RoleState {
                id,
                can_login: false,
                is_superuser: false,
                inherits: true,
                member_of: Vec::new(),
                can_administer_membership: Vec::new(),
                can_inherit_from: Vec::new(),
                can_set_role_to: Vec::new(),
            },
        );
    }
    AnalysisState::new(cache)
}

fn attach_fixture(sql: &str) -> (AnalysisState, Vec<Violation>) {
    let engine = setup_engine();
    let mut state = setup_state();
    let violations = engine.analyze(sql, &mut state).unwrap();
    (state, violations)
}

mod indexes;
mod partitions;
mod roles;
mod routines;
mod scope_evidence;
mod sequences;
mod statement_semantics;
mod tables_constraints;
mod triggers_policies;
mod types;
mod views;
