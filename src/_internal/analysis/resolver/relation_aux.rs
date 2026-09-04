use super::Resolver;
use crate::_internal::analysis::facts::{AlterIndexActionFact, AlterViewAction, PolicyCommand};
use crate::_internal::analysis::mutations::{
    CreateIndex, CreateMaterializedView, CreatePolicyMutation, CreateTriggerMutation, CreateView,
    DropPolicyMutation, DropTriggerMutation, Mutation, OpaqueMutation,
    RefreshMaterializedViewMutation, Rename, RenameTriggerMutation,
};
use crate::_internal::analysis::state::AnalysisState;
use crate::_internal::ast::identifiers::{Ident, ObjectId, QualifiedName};

impl Resolver {
    pub(super) fn resolve_create_view(
        name: &QualifiedName,
        or_replace: bool,
        depends_on: &[QualifiedName],
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::CreateView(CreateView {
            id: Self::resolve_creation_name(name, state),
            or_replace,
            depends_on: depends_on
                .iter()
                .map(|dependency| Self::resolve_relation_lookup_name(dependency, state))
                .collect(),
        })
    }

    pub(super) fn resolve_alter_view(
        name: &QualifiedName,
        action: &AlterViewAction,
        state: &AnalysisState,
    ) -> Option<Mutation> {
        match action {
            AlterViewAction::RenameTo { new_name } => {
                let id = Self::resolve_relation_lookup_name(name, state);
                let mut new_id = ObjectId::new(id.schema.clone(), new_name.resolve());
                new_id.inferred_schema = id.inferred_schema;
                Some(Mutation::Rename(Rename { old_id: id, new_id }))
            }
            AlterViewAction::SetSchema { new_schema } => {
                let id = Self::resolve_relation_lookup_name(name, state);
                let new_id = ObjectId::new(new_schema, &id.name);
                Some(Mutation::Rename(Rename { old_id: id, new_id }))
            }
            AlterViewAction::OwnerTo { new_owner } => Some(Mutation::ChangeRelationOwner {
                id: Self::resolve_relation_lookup_name(name, state),
                new_owner: new_owner.clone(),
            }),
            AlterViewAction::RenameColumn { .. } => {
                Some(Mutation::Opaque(OpaqueMutation::UnsupportedStatement))
            }
            AlterViewAction::SetDefault { .. }
            | AlterViewAction::DropDefault { .. }
            | AlterViewAction::SetOptions { .. }
            | AlterViewAction::ResetOptions { .. } => None,
        }
    }

    pub(super) fn resolve_create_materialized_view(
        name: &QualifiedName,
        depends_on: &[QualifiedName],
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::CreateMaterializedView(CreateMaterializedView {
            id: Self::resolve_creation_name(name, state),
            depends_on: depends_on
                .iter()
                .map(|dependency| Self::resolve_relation_lookup_name(dependency, state))
                .collect(),
        })
    }

    pub(super) fn resolve_alter_materialized_view(
        name: &QualifiedName,
        new_name: Option<&Ident>,
        state: &AnalysisState,
    ) -> Option<Mutation> {
        new_name.map(|new_name| {
            let id = Self::resolve_relation_lookup_name(name, state);
            let mut new_id = ObjectId::new(id.schema.clone(), new_name.resolve());
            new_id.inferred_schema = id.inferred_schema;
            Mutation::Rename(Rename { old_id: id, new_id })
        })
    }

    pub(super) fn resolve_refresh_materialized_view(
        name: &QualifiedName,
        concurrently: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::RefreshMaterializedView(RefreshMaterializedViewMutation {
            id: Self::resolve_relation_lookup_name(name, state),
            concurrently,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn resolve_create_index(
        name: &QualifiedName,
        relation: &QualifiedName,
        if_not_exists: bool,
        concurrently: bool,
        using_method: &Option<String>,
        has_predicate: bool,
        unique: bool,
        key_columns: &[String],
        included_columns: &[String],
        has_expression_keys: bool,
        has_default_sort_order: bool,
        has_default_opclasses: bool,
        has_default_collations: bool,
        state: &AnalysisState,
    ) -> Mutation {
        let table = Self::resolve_relation_lookup_name(relation, state);
        // PostgreSQL places an unqualified index in the indexed relation's
        // schema, not the first schema in search_path.
        let id = if name.schema.is_some() {
            Self::resolve_creation_name(name, state)
        } else {
            ObjectId::new(table.schema.clone(), name.name.resolve())
        };
        Mutation::CreateIndex(CreateIndex {
            id,
            table,
            if_not_exists,
            concurrently,
            using_method: using_method.clone(),
            has_predicate,
            unique,
            key_columns: key_columns.to_vec(),
            included_columns: included_columns.to_vec(),
            has_expression_keys,
            has_default_sort_order,
            has_default_opclasses,
            has_default_collations,
        })
    }

    pub(super) fn resolve_create_policy(
        name: &str,
        table: &QualifiedName,
        permissive: bool,
        command: &PolicyCommand,
        semantics_complete: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::CreatePolicy(CreatePolicyMutation {
            name: name.to_string(),
            table: Self::resolve_relation_lookup_name(table, state),
            permissive,
            command: command.clone(),
            semantics_complete,
        })
    }

    pub(super) fn resolve_drop_policy(
        name: &str,
        table: &QualifiedName,
        if_exists: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropPolicy(DropPolicyMutation {
            name: name.to_string(),
            table: Self::resolve_relation_lookup_name(table, state),
            if_exists,
        })
    }

    pub(super) fn resolve_create_trigger(
        name: &str,
        table: &QualifiedName,
        function: &Option<QualifiedName>,
        state: &AnalysisState,
    ) -> Mutation {
        let Some(function) = function else {
            return Mutation::Opaque(OpaqueMutation::UnsupportedStatement);
        };
        let function_id = Self::resolve_routine_lookup_name(function, &[], state);
        Mutation::CreateTrigger(CreateTriggerMutation {
            name: name.to_string(),
            table: Self::resolve_relation_lookup_name(table, state),
            function_id,
        })
    }

    pub(super) fn resolve_drop_trigger(
        name: &str,
        table: &QualifiedName,
        if_exists: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropTrigger(DropTriggerMutation {
            name: name.to_string(),
            table: Self::resolve_relation_lookup_name(table, state),
            if_exists,
        })
    }

    pub(super) fn resolve_alter_trigger(
        name: &str,
        table: &QualifiedName,
        new_name: &str,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::RenameTrigger(RenameTriggerMutation {
            name: name.to_string(),
            table: Self::resolve_relation_lookup_name(table, state),
            new_name: new_name.to_string(),
        })
    }

    pub(super) fn resolve_alter_index(
        name: &QualifiedName,
        actions: &[AlterIndexActionFact],
        state: &AnalysisState,
    ) -> Vec<Mutation> {
        let id = Self::resolve_relation_lookup_name(name, state);
        actions
            .iter()
            .map(|action| match action {
                AlterIndexActionFact::RenameTo { new_name } => {
                    let mut new_id = ObjectId::new(id.schema.clone(), new_name.resolve());
                    new_id.inferred_schema = id.inferred_schema;
                    Mutation::Rename(Rename {
                        old_id: id.clone(),
                        new_id,
                    })
                }
            })
            .collect()
    }
}
