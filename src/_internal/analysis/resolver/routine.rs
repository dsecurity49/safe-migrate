use super::Resolver;
use crate::_internal::analysis::facts::{
    AlterAggregateFact, AlterFunctionFact, AlterProcedureFact, AlterRoutineFact,
    AlterStatisticsFact, AnalyzeFact, CastMethodFact, CreateAggregateFact, CreateCastFact,
    CreateFunctionFact, CreateProcedureFact, CreateStatisticsFact, DropAggregateFact, DropCastFact,
    DropFunctionFact, DropProcedureFact, DropRoutineFact, DropStatisticsFact, FunctionSigFact,
    RoutineBodyDependenciesFact,
};
use crate::_internal::analysis::mutations::{
    AlterAggregateMutation, AlterFunctionMutation, AlterProcedureMutation, AlterRoutineMutation,
    AlterStatisticsMutation, AnalyzeMutation, AnalyzeTargetMutation, CastMethodMutation,
    CreateAggregateMutation, CreateCastMutation, CreateFunctionMutation, CreateProcedureMutation,
    CreateStatisticsMutation, DropAggregateMutation, DropCastMutation, DropFunctionMutation,
    DropProcedureMutation, DropRoutineMutation, DropStatisticsMutation, Mutation,
    RoutineBodyDependencies, RoutineRelationDependency,
};
use crate::_internal::analysis::state::AnalysisState;

impl Resolver {
    pub(super) fn resolve_create_function(
        fact: &CreateFunctionFact,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::CreateFunction(CreateFunctionMutation {
            id: Self::resolve_function_id(&fact.name, &fact.params, state),
            or_replace: fact.or_replace,
            params: fact.params.clone(),
            return_type: fact.return_type.clone(),
            options: fact.options.clone(),
            body_dependencies: Self::resolve_routine_body_dependencies(
                &fact.body_dependencies,
                state,
            ),
        })
    }

    pub(super) fn resolve_alter_function(
        fact: &AlterFunctionFact,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::AlterFunction(AlterFunctionMutation {
            id: Self::resolve_routine_lookup_name(&fact.name, &fact.params, state),
            action: fact.action.clone(),
        })
    }

    pub(super) fn resolve_drop_function(
        fact: &DropFunctionFact,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropFunction(DropFunctionMutation {
            signatures: Self::normalize_signatures(&fact.signatures, state),
            if_exists: fact.if_exists,
            cascade: fact.cascade,
        })
    }

    pub(super) fn resolve_create_procedure(
        fact: &CreateProcedureFact,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::CreateProcedure(CreateProcedureMutation {
            id: Self::resolve_function_id(&fact.name, &fact.params, state),
            or_replace: fact.or_replace,
            params: fact.params.clone(),
            options: fact.options.clone(),
            body_dependencies: Self::resolve_routine_body_dependencies(
                &fact.body_dependencies,
                state,
            ),
        })
    }

    pub(super) fn resolve_alter_procedure(
        fact: &AlterProcedureFact,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::AlterProcedure(AlterProcedureMutation {
            id: Self::resolve_routine_lookup_name(&fact.name, &fact.params, state),
            action: fact.action.clone(),
        })
    }

    pub(super) fn resolve_drop_procedure(
        fact: &DropProcedureFact,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropProcedure(DropProcedureMutation {
            signatures: Self::normalize_signatures(&fact.signatures, state),
            if_exists: fact.if_exists,
            cascade: fact.cascade,
        })
    }

    pub(super) fn resolve_create_aggregate(
        fact: &CreateAggregateFact,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::CreateAggregate(CreateAggregateMutation {
            id: Self::resolve_function_id(&fact.name, &fact.params, state),
            or_replace: fact.or_replace,
            params: fact.params.clone(),
            kind: fact.kind,
            direct_count: fact.direct_count,
            definition: fact.definition.clone(),
        })
    }

    pub(super) fn resolve_alter_aggregate(
        fact: &AlterAggregateFact,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::AlterAggregate(AlterAggregateMutation {
            id: Self::resolve_routine_lookup_name(&fact.name, &fact.params, state),
            action: fact.action.clone(),
        })
    }

    pub(super) fn resolve_drop_aggregate(
        fact: &DropAggregateFact,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropAggregate(DropAggregateMutation {
            signatures: Self::normalize_signatures(&fact.signatures, state),
            if_exists: fact.if_exists,
            cascade: fact.cascade,
        })
    }

    pub(super) fn resolve_alter_routine(
        fact: &AlterRoutineFact,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::AlterRoutine(AlterRoutineMutation {
            id: Self::resolve_routine_lookup_name(&fact.name, &fact.params, state),
            action: fact.action.clone(),
        })
    }

    pub(super) fn resolve_drop_routine(fact: &DropRoutineFact, state: &AnalysisState) -> Mutation {
        Mutation::DropRoutine(DropRoutineMutation {
            signatures: Self::normalize_signatures(&fact.signatures, state),
            if_exists: fact.if_exists,
            cascade: fact.cascade,
        })
    }

    fn resolve_routine_body_dependencies(
        deps: &RoutineBodyDependenciesFact,
        state: &AnalysisState,
    ) -> RoutineBodyDependencies {
        let mut relations: Vec<RoutineRelationDependency> = Vec::new();
        for rel in &deps.relations {
            let resolved = RoutineRelationDependency {
                relation: Self::resolve_relation_lookup_name(&rel.relation, state),
                column: rel.column.clone(),
            };
            if !relations.contains(&resolved) {
                relations.push(resolved);
            }
        }
        let single_source = {
            let mut distinct_rels: Vec<&crate::_internal::ast::identifiers::ObjectId> = Vec::new();
            for r in &relations {
                if !distinct_rels.contains(&&r.relation) {
                    distinct_rels.push(&r.relation);
                }
            }
            (distinct_rels.len() == 1).then(|| distinct_rels[0].clone())
        };
        RoutineBodyDependencies {
            relations,
            routines: Self::resolve_view_routines(&deps.routines, single_source.as_ref(), state),
            types: Self::resolve_cast_types(&deps.types, state),
        }
    }

    fn normalize_signatures(
        signatures: &[FunctionSigFact],
        state: &AnalysisState,
    ) -> Vec<FunctionSigFact> {
        signatures
            .iter()
            .cloned()
            .map(|mut signature| {
                signature.params = signature
                    .params
                    .into_iter()
                    .map(|param| Self::routine_arg_identity(&param, state))
                    .collect();
                signature
            })
            .collect()
    }
    pub(super) fn resolve_create_cast(fact: &CreateCastFact, state: &AnalysisState) -> Mutation {
        let method = match &fact.method {
            CastMethodFact::WithoutFunction => CastMethodMutation::WithoutFunction,
            CastMethodFact::WithInout => CastMethodMutation::WithInout,
            CastMethodFact::WithFunction(sig) => CastMethodMutation::WithFunction(
                Self::resolve_routine_lookup_name(&sig.name, &sig.params, state),
            ),
        };
        Mutation::CreateCast(CreateCastMutation {
            source_type: Self::resolve_cast_type_identity(&fact.source_type, state),
            target_type: Self::resolve_cast_type_identity(&fact.target_type, state),
            method,
            context: fact.context,
        })
    }

    pub(super) fn resolve_drop_cast(fact: &DropCastFact, state: &AnalysisState) -> Mutation {
        Mutation::DropCast(DropCastMutation {
            source_type: Self::resolve_cast_type_identity(&fact.source_type, state),
            target_type: Self::resolve_cast_type_identity(&fact.target_type, state),
            if_exists: fact.if_exists,
            cascade: fact.cascade,
        })
    }

    pub(super) fn resolve_create_statistics(
        fact: &CreateStatisticsFact,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::CreateStatistics(CreateStatisticsMutation {
            id: fact
                .name
                .as_ref()
                .map(|name| Self::resolve_creation_name(name, state)),
            if_not_exists: fact.if_not_exists,
            kinds: fact.kinds.clone(),
            columns: fact.columns.clone(),
            expression_count: fact.expression_count,
            expressions_sql: fact.expressions_sql.clone(),
            table: Self::resolve_relation_lookup_name(&fact.table, state),
        })
    }

    pub(super) fn resolve_alter_statistics(
        fact: &AlterStatisticsFact,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::AlterStatistics(AlterStatisticsMutation {
            id: Self::resolve_statistics_lookup_name(&fact.name, state),
            action: fact.action.clone(),
        })
    }

    pub(super) fn resolve_drop_statistics(
        fact: &DropStatisticsFact,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropStatistics(DropStatisticsMutation {
            ids: fact
                .names
                .iter()
                .map(|name| Self::resolve_statistics_lookup_name(name, state))
                .collect(),
            if_exists: fact.if_exists,
            cascade: fact.cascade,
        })
    }

    pub(super) fn resolve_analyze(fact: &AnalyzeFact, state: &AnalysisState) -> Mutation {
        Mutation::Analyze(AnalyzeMutation {
            targets: fact
                .targets
                .iter()
                .map(|t| AnalyzeTargetMutation {
                    table_id: Self::resolve_relation_lookup_name(&t.relation, state),
                    columns: t.columns.clone(),
                })
                .collect(),
        })
    }
}
