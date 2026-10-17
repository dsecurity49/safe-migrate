use super::Resolver;
use crate::_internal::analysis::expr_ir::ExprIr;
use crate::_internal::analysis::facts::{
    AlterIndexActionFact, AlterMaterializedViewActionFact, AlterViewAction, PolicyCommand,
    ReindexTargetKindFact, SelectOutputFact, StatisticsTarget,
};
use crate::_internal::analysis::mutations::{
    AlterIndexActionMutation, AlterIndexMutation, AlterViewFamily, CreateIndex,
    CreateMaterializedView, CreatePolicyMutation, CreateTriggerMutation, CreateView,
    DropPolicyMutation, DropTriggerMutation, Mutation, OpaqueMutation,
    RefreshMaterializedViewMutation, ReindexTargetMutation, ReloptionTarget, Rename,
    RenameTriggerMutation, ViewColumn, ViewRoutine,
};
use crate::_internal::analysis::state::AnalysisState;
use crate::_internal::ast::identifiers::{ObjectId, QualifiedName};
use crate::_internal::model::data_type::ParsedDataType;
use crate::_internal::model::index::{IndexOrder, IndexPredicate, WrittenName};
use crate::_internal::model::relation::RelationKind;

impl Resolver {
    pub(super) fn resolve_reindex(
        target_kind: &ReindexTargetKindFact,
        target_name: Option<&QualifiedName>,
        concurrently: bool,
        state: &AnalysisState,
    ) -> Mutation {
        let target = match (target_kind, target_name) {
            // The grammar makes the database name optional for `DATABASE` and
            // `SYSTEM` alike, so both forms carry the same identity.
            (ReindexTargetKindFact::Database, name_opt) => Some(ReindexTargetMutation::Database(
                name_opt.map(|name| name.name.resolve()).unwrap_or_default(),
            )),
            (ReindexTargetKindFact::Schema, Some(name)) => {
                Some(ReindexTargetMutation::Schema(name.name.resolve()))
            }
            (ReindexTargetKindFact::System, name_opt) => Some(ReindexTargetMutation::System(
                name_opt.map(|n| n.name.resolve()),
            )),
            (ReindexTargetKindFact::Table, Some(name)) => Some(ReindexTargetMutation::Table(
                Self::resolve_relation_lookup_name(name, state),
            )),
            (ReindexTargetKindFact::Index, Some(name)) => Some(ReindexTargetMutation::Index(
                Self::resolve_relation_lookup_name(name, state),
            )),
            _ => None, // Syntax error recovery states (missing required names)
        };

        Mutation::Reindex {
            target,
            concurrently,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn resolve_create_view(
        name: &QualifiedName,
        or_replace: bool,
        depends_on: &[QualifiedName],
        select_outputs: &[SelectOutputFact],
        projection_complete: bool,
        select_source: Option<&QualifiedName>,
        routines: &[crate::_internal::analysis::facts::RoutineReferenceFact],
        cast_types: &[crate::_internal::analysis::facts::CastTypeReferenceFact],
        state: &AnalysisState,
    ) -> Mutation {
        let source = select_source.map(|source| Self::resolve_relation_lookup_name(source, state));
        let columns = Self::resolve_view_columns(select_outputs, source.as_ref(), state);
        Mutation::CreateView(CreateView {
            id: Self::resolve_creation_name(name, state),
            or_replace,
            depends_on: depends_on
                .iter()
                .map(|dependency| Self::resolve_relation_lookup_name(dependency, state))
                .collect(),
            columns,
            projection_complete,
            routines: Self::resolve_view_routines(routines, source.as_ref(), state),
            cast_types: Self::resolve_cast_types(cast_types, state),
        })
    }

    /// Project a view's output list, taking types from the source relation
    /// where the output is a plain column reference.
    ///
    /// Types are normalised the way `format_type` reports them, so a view
    /// created from DDL matches the same view synchronized from the catalog.
    fn resolve_view_columns(
        select_outputs: &[SelectOutputFact],
        source: Option<&ObjectId>,
        state: &AnalysisState,
    ) -> Vec<ViewColumn> {
        let source_columns = source
            .and_then(|id| state.relation_column_types(id))
            .unwrap_or_default();
        let find = |source_name: &str| {
            source_columns
                .iter()
                .find(|(name, _)| name == source_name)
                .and_then(|(_, data_type)| data_type.as_deref())
        };
        let view_column = |output_name: String, declared: Option<&str>| ViewColumn {
            name: output_name,
            // `format_type` spelling, typmod included, so a view built from
            // DDL carries the same string the catalog reports.
            data_type: declared
                .map(|declared| ParsedDataType::parse(declared, state.builtin_types()).to_string()),
            type_modifier: declared.and_then(|declared| {
                ParsedDataType::parse(declared, state.builtin_types()).atttypmod()
            }),
        };

        let mut columns = Vec::new();
        for output in select_outputs {
            match output {
                SelectOutputFact::AllColumns => columns.extend(
                    source_columns
                        .iter()
                        .map(|(name, data_type)| view_column(name.clone(), data_type.as_deref())),
                ),
                SelectOutputFact::Column {
                    source_name,
                    output_name,
                } => columns.push(view_column(output_name.clone(), find(source_name))),
            }
        }
        columns
    }

    /// The routines a view calls, as identities the drop path can match.
    ///
    /// A call whose arguments are all plain column references of the source
    /// resolves to the exact routine identity. Any other call falls back to the
    /// lone routine of that name when the modeled universe holds one; only a
    /// call that is still ambiguous keeps just the qualified name.
    fn resolve_view_routines(
        routines: &[crate::_internal::analysis::facts::RoutineReferenceFact],
        source: Option<&ObjectId>,
        state: &AnalysisState,
    ) -> Vec<ViewRoutine> {
        let source_columns = source
            .and_then(|id| state.relation_column_types(id))
            .unwrap_or_default();
        routines
            .iter()
            .map(|reference| {
                let name = Self::resolve_routine_namespace_name(&reference.name, state);
                let signature = reference.argument_types.as_ref().and_then(|arguments| {
                    arguments
                        .iter()
                        .map(|argument| {
                            source_columns
                                .iter()
                                .find(|(column, _)| column == argument)
                                .and_then(|(_, data_type)| data_type.clone())
                        })
                        .collect::<Option<Vec<String>>>()
                });
                ViewRoutine {
                    name: name.clone(),
                    signature: signature
                        .map(|arguments| {
                            ObjectId::new(
                                name.schema.clone(),
                                format!(
                                    "{}({})",
                                    name.name,
                                    arguments
                                        .iter()
                                        .map(|argument| {
                                            Resolver::normalize_function_arg_type(
                                                argument,
                                                state.builtin_types(),
                                            )
                                            .render()
                                        })
                                        .collect::<Vec<_>>()
                                        .join(",")
                                ),
                            )
                        })
                        .or_else(|| {
                            // The argument types did not resolve, but a lone routine
                            // of this name is still the one PostgreSQL picked.
                            state.unique_routine_named(&ObjectId::new(
                                name.schema.clone(),
                                name.name.clone(),
                            ))
                        }),
                }
            })
            .collect()
    }

    /// The types a view body casts to, as identities the drop path can match.
    fn resolve_cast_types(
        cast_types: &[crate::_internal::analysis::facts::CastTypeReferenceFact],
        state: &AnalysisState,
    ) -> Vec<ObjectId> {
        let mut resolved: Vec<ObjectId> = Vec::new();
        for reference in cast_types {
            let id = Self::resolve_type_lookup_name(&reference.name, state);
            if !resolved.contains(&id) {
                resolved.push(id);
            }
        }
        resolved
    }

    pub(super) fn resolve_alter_view(
        name: &QualifiedName,
        action: &AlterViewAction,
        if_exists: bool,
        state: &AnalysisState,
    ) -> Mutation {
        let action = match action {
            AlterViewAction::RenameTo { new_name } => {
                let id = Self::resolve_relation_lookup_name(name, state);
                let mut new_id = ObjectId::new(id.schema.clone(), new_name.resolve());
                new_id.inferred_schema = id.inferred_schema;
                Mutation::Rename(Rename { old_id: id, new_id })
            }
            AlterViewAction::SetSchema { new_schema } => {
                let id = Self::resolve_relation_lookup_name(name, state);
                let new_id = ObjectId::new(new_schema, &id.name);
                Mutation::Rename(Rename { old_id: id, new_id })
            }
            AlterViewAction::OwnerTo { new_owner } => Mutation::ChangeRelationOwner {
                id: Self::resolve_relation_lookup_name(name, state),
                new_owner: new_owner.clone(),
            },
            AlterViewAction::RenameColumn { .. } => {
                Mutation::Opaque(OpaqueMutation::UnsupportedStatement)
            }
            AlterViewAction::SetDefault { column, default } => Mutation::SetColumnDefault {
                id: Self::resolve_relation_lookup_name(name, state),
                column: column.clone(),
                default: default.clone(),
            },
            AlterViewAction::DropDefault { column } => Mutation::SetColumnDefault {
                id: Self::resolve_relation_lookup_name(name, state),
                column: column.clone(),
                default: None,
            },
            AlterViewAction::SetOptions { options } => Mutation::SetReloptions {
                id: Self::resolve_relation_lookup_name(name, state),
                kind: ReloptionTarget::View,
                attributes: options.clone(),
            },
            AlterViewAction::ResetOptions { options } => Mutation::ResetReloptions {
                id: Self::resolve_relation_lookup_name(name, state),
                kind: ReloptionTarget::View,
                names: options.iter().map(|option| option.name.clone()).collect(),
            },
        };
        Mutation::AlterViewFamily(AlterViewFamily {
            id: Self::resolve_relation_lookup_name(name, state),
            kind: RelationKind::View,
            if_exists,
            actions: vec![action],
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn resolve_create_materialized_view(
        name: &QualifiedName,
        depends_on: &[QualifiedName],
        if_not_exists: bool,
        with_no_data: bool,
        column_list: &[String],
        access_method: &Option<String>,
        tablespace: &Option<String>,
        options: &[crate::_internal::analysis::facts::AttributeFact],
        select_outputs: &[SelectOutputFact],
        projection_complete: bool,
        select_source: Option<&QualifiedName>,
        view_routines: &[crate::_internal::analysis::facts::RoutineReferenceFact],
        cast_types: &[crate::_internal::analysis::facts::CastTypeReferenceFact],
        state: &AnalysisState,
    ) -> Mutation {
        let source = select_source.map(|source| Self::resolve_relation_lookup_name(source, state));
        let mut columns = Self::resolve_view_columns(select_outputs, source.as_ref(), state);
        // An explicit column list renames the outputs in order.
        if !column_list.is_empty() {
            if column_list.len() == columns.len() {
                for (column, name) in columns.iter_mut().zip(column_list) {
                    column.name = name.clone();
                }
            } else {
                // PostgreSQL refuses a list that does not match the projection,
                // and the mismatch is not modelled, so claim nothing.
                columns.clear();
            }
        }
        Mutation::CreateMaterializedView(CreateMaterializedView {
            id: Self::resolve_creation_name(name, state),
            depends_on: depends_on
                .iter()
                .map(|dependency| Self::resolve_relation_lookup_name(dependency, state))
                .collect(),
            if_not_exists,
            with_no_data,
            columns,
            projection_complete,
            routines: Self::resolve_view_routines(view_routines, source.as_ref(), state),
            cast_types: Self::resolve_cast_types(cast_types, state),
            access_method: access_method.clone(),
            tablespace: tablespace.clone(),
            options: options.to_vec(),
        })
    }

    pub(super) fn resolve_alter_materialized_view(
        name: &QualifiedName,
        actions: &[AlterMaterializedViewActionFact],
        if_exists: bool,
        state: &AnalysisState,
    ) -> Mutation {
        let actions = actions
            .iter()
            .map(|action| Self::resolve_alter_materialized_view_action(name, action, state))
            .collect();
        Mutation::AlterViewFamily(AlterViewFamily {
            id: Self::resolve_relation_lookup_name(name, state),
            kind: RelationKind::MaterializedView,
            if_exists,
            actions,
        })
    }

    fn resolve_alter_materialized_view_action(
        name: &QualifiedName,
        action: &AlterMaterializedViewActionFact,
        state: &AnalysisState,
    ) -> Mutation {
        match action {
            AlterMaterializedViewActionFact::RenameTo { new_name } => {
                let id = Self::resolve_relation_lookup_name(name, state);
                let mut new_id = ObjectId::new(id.schema.clone(), new_name.resolve());
                new_id.inferred_schema = id.inferred_schema;
                Mutation::Rename(Rename { old_id: id, new_id })
            }
            AlterMaterializedViewActionFact::SetSchema { new_schema } => {
                let id = Self::resolve_relation_lookup_name(name, state);
                let new_id = ObjectId::new(new_schema, &id.name);
                Mutation::Rename(Rename { old_id: id, new_id })
            }
            AlterMaterializedViewActionFact::OwnerTo { new_owner } => {
                Mutation::ChangeRelationOwner {
                    id: Self::resolve_relation_lookup_name(name, state),
                    new_owner: new_owner.clone(),
                }
            }
            AlterMaterializedViewActionFact::RenameColumn { .. }
            | AlterMaterializedViewActionFact::SetTablespace { .. }
            | AlterMaterializedViewActionFact::SetAccessMethod { .. }
            | AlterMaterializedViewActionFact::ClusterOn { .. }
            | AlterMaterializedViewActionFact::SetWithoutCluster
            | AlterMaterializedViewActionFact::SetStorage { .. }
            | AlterMaterializedViewActionFact::SetCompression { .. }
            | AlterMaterializedViewActionFact::DependsOnExtension { .. }
            | AlterMaterializedViewActionFact::NoDependsOnExtension { .. } => {
                Mutation::Opaque(OpaqueMutation::UnsupportedStatement)
            }
            AlterMaterializedViewActionFact::SetOptions { options } => Mutation::SetReloptions {
                id: Self::resolve_relation_lookup_name(name, state),
                kind: ReloptionTarget::MaterializedView,
                attributes: options.clone(),
            },
            AlterMaterializedViewActionFact::ResetOptions { options } => {
                Mutation::ResetReloptions {
                    id: Self::resolve_relation_lookup_name(name, state),
                    kind: ReloptionTarget::MaterializedView,
                    names: options.iter().map(|option| option.name.clone()).collect(),
                }
            }
        }
    }

    pub(super) fn resolve_refresh_materialized_view(
        name: &QualifiedName,
        concurrently: bool,
        with_no_data: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::RefreshMaterializedView(RefreshMaterializedViewMutation {
            id: Self::resolve_relation_lookup_name(name, state),
            concurrently,
            with_no_data,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn resolve_create_index(
        name: &QualifiedName,
        relation: &QualifiedName,
        if_not_exists: bool,
        concurrently: bool,
        using_method: &Option<String>,
        predicate: &IndexPredicate,
        unique: bool,
        nulls_not_distinct: bool,
        key_columns: &[String],
        key_expressions: &[Option<ExprIr>],
        key_orders: &[IndexOrder],
        key_opclasses: &[Option<WrittenName>],
        key_collations: &[Option<WrittenName>],
        included_columns: &[String],
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
            predicate: predicate.clone(),
            unique,
            nulls_not_distinct,
            key_columns: key_columns.to_vec(),
            key_expressions: key_expressions.to_vec(),
            key_orders: key_orders.to_vec(),
            key_opclasses: key_opclasses.to_vec(),
            key_collations: key_collations.to_vec(),
            included_columns: included_columns.to_vec(),
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
        row_level: bool,
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
            row_level,
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
        if_exists: bool,
        actions: &[AlterIndexActionFact],
        state: &AnalysisState,
    ) -> Mutation {
        let index_id = Self::resolve_relation_lookup_name(name, state);
        let resolved_actions = actions
            .iter()
            .map(|action| match action {
                AlterIndexActionFact::RenameTo { new_name } => {
                    let mut new_id = ObjectId::new(index_id.schema.clone(), new_name.resolve());
                    new_id.inferred_schema = index_id.inferred_schema;
                    AlterIndexActionMutation::RenameTo { new_id }
                }
                AlterIndexActionFact::SetTablespace { new_tablespace } => {
                    AlterIndexActionMutation::SetTablespace {
                        tablespace_name: new_tablespace.resolve(),
                    }
                }
                AlterIndexActionFact::AttachPartition { partition_name } => {
                    let partition_id = Self::resolve_relation_lookup_name(partition_name, state);
                    AlterIndexActionMutation::AttachPartition { partition_id }
                }
                AlterIndexActionFact::DependsOnExtension { extension_name } => {
                    AlterIndexActionMutation::DependsOnExtension {
                        extension_name: extension_name.resolve(),
                    }
                }
                AlterIndexActionFact::NoDependsOnExtension { extension_name } => {
                    AlterIndexActionMutation::NoDependsOnExtension {
                        extension_name: extension_name.resolve(),
                    }
                }
                AlterIndexActionFact::SetStatistics { column, target } => {
                    AlterIndexActionMutation::SetStatistics {
                        column: column.clone(),
                        target: match target {
                            StatisticsTarget::Default => StatisticsTarget::Default,
                            StatisticsTarget::Value(n) => StatisticsTarget::Value(*n),
                        },
                    }
                }
                AlterIndexActionFact::SetOptions { options } => {
                    AlterIndexActionMutation::SetOptions {
                        options: options.clone(),
                    }
                }
                AlterIndexActionFact::ResetOptions { options } => {
                    AlterIndexActionMutation::ResetOptions {
                        options: options.clone(),
                    }
                }
            })
            .collect();

        Mutation::AlterIndex(AlterIndexMutation {
            index_id,
            if_exists,
            actions: resolved_actions,
        })
    }
}
