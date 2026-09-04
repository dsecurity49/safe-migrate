use super::Resolver;
use crate::_internal::analysis::facts::{
    AlterAggregateFact, AlterFunctionFact, AlterProcedureFact, CreateAggregateFact,
    CreateFunctionFact, CreateProcedureFact, DropAggregateFact, DropFunctionFact,
    DropProcedureFact, FunctionSigFact,
};
use crate::_internal::analysis::mutations::{
    AlterAggregateMutation, AlterFunctionMutation, AlterProcedureMutation, CreateAggregateMutation,
    CreateFunctionMutation, CreateProcedureMutation, DropAggregateMutation, DropFunctionMutation,
    DropProcedureMutation, Mutation,
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

    pub(super) fn resolve_drop_function(fact: &DropFunctionFact) -> Mutation {
        Mutation::DropFunction(DropFunctionMutation {
            signatures: Self::normalize_signatures(&fact.signatures),
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

    pub(super) fn resolve_drop_procedure(fact: &DropProcedureFact) -> Mutation {
        Mutation::DropProcedure(DropProcedureMutation {
            signatures: Self::normalize_signatures(&fact.signatures),
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

    pub(super) fn resolve_drop_aggregate(fact: &DropAggregateFact) -> Mutation {
        Mutation::DropAggregate(DropAggregateMutation {
            signatures: Self::normalize_signatures(&fact.signatures),
            if_exists: fact.if_exists,
            cascade: fact.cascade,
        })
    }

    fn normalize_signatures(signatures: &[FunctionSigFact]) -> Vec<FunctionSigFact> {
        signatures
            .iter()
            .cloned()
            .map(|mut signature| {
                signature.params = signature
                    .params
                    .into_iter()
                    .map(|param| Self::normalize_function_arg_type(&param))
                    .collect();
                signature
            })
            .collect()
    }
}
