use super::Resolver;
use crate::_internal::analysis::facts::{
    AlterTableActionFact, ColumnFact, FkFact, PersistenceFact, SelectOutputFact,
    TableConstraintFact,
};
use crate::_internal::analysis::mutations::{
    AlterTable, AlterTableActionMutation, ColumnMutation, CreateTable, DropIndex,
    DropMaterializedViewMutation, DropTable, DropViewMutation, FkMutation, LikeSourceMutation,
    Mutation, PersistenceMutation, Rename,
};
use crate::_internal::analysis::state::AnalysisState;
use crate::_internal::ast::identifiers::{ObjectId, QualifiedName};

impl Resolver {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn resolve_create_table(
        name: &QualifiedName,
        if_not_exists: bool,
        as_select: bool,
        persistence: &PersistenceFact,
        on_commit: Option<crate::_internal::analysis::facts::OnCommitFact>,
        columns: &[ColumnFact],
        foreign_keys: &[FkFact],
        table_constraints: &[TableConstraintFact],
        partition_by: &Option<String>,
        partition_strategy: &Option<String>,
        partition_of: &Option<QualifiedName>,
        partition_bound: &Option<String>,
        inherits: &[QualifiedName],
        like_sources: &[crate::_internal::analysis::facts::LikeSourceFact],
        of_type: &Option<QualifiedName>,
        select_source: &Option<QualifiedName>,
        select_outputs: &[SelectOutputFact],
        select_projection_complete: bool,
        state: &AnalysisState,
    ) -> Mutation {
        let persistence = match persistence {
            PersistenceFact::Permanent => PersistenceMutation::Permanent,
            PersistenceFact::Temporary => PersistenceMutation::Temporary,
            PersistenceFact::Unlogged => PersistenceMutation::Unlogged,
        };
        let on_commit = on_commit.map(|action| match action {
            crate::_internal::analysis::facts::OnCommitFact::PreserveRows => {
                crate::_internal::analysis::mutations::OnCommitMutation::PreserveRows
            }
            crate::_internal::analysis::facts::OnCommitFact::DeleteRows => {
                crate::_internal::analysis::mutations::OnCommitMutation::DeleteRows
            }
            crate::_internal::analysis::facts::OnCommitFact::Drop => {
                crate::_internal::analysis::mutations::OnCommitMutation::Drop
            }
        });
        let mut columns: Vec<ColumnMutation> = columns
            .iter()
            .map(|column| ColumnMutation {
                name: column.name.clone(),
                ty: column.ty.clone(),
                type_modifier: None,
                not_null: column.not_null,
                is_primary_key: column.is_primary_key,
                primary_key_constraint_name: column.primary_key_constraint_name.clone(),
                is_unique: column.is_unique,
                unique_constraint_name: column.unique_constraint_name.clone(),
                default: column.default.clone(),
                generation: column.generation,
                identity_sequence: column.identity_sequence.as_ref().map(|options| {
                    crate::_internal::analysis::mutations::IdentitySequenceOptionsMutation {
                        data_type: options.data_type.clone(),
                        start_value: options.start_value,
                        increment: options.increment,
                        min_value: options.min_value,
                        max_value: options.max_value,
                        cache_size: options.cache_size,
                        cycle: options.cycle,
                        persistence: options.persistence,
                        sequence_name: options
                            .sequence_name
                            .as_ref()
                            .map(|name| Self::resolve_creation_name(name, state)),
                    }
                }),
                generated_expr: column.generated_expr.clone(),
                generated_expr_sql: column.generated_expr_sql.clone(),
            })
            .collect();
        let of_type = of_type
            .as_ref()
            .map(|name| Self::resolve_type_lookup_name(name, state));
        if let Some(type_id) = &of_type
            && let Some(crate::_internal::model::types::TypeOverlay::Present(
                crate::_internal::model::types::TypeState {
                    kind: crate::_internal::model::types::TypeKind::Composite { fields },
                    ..
                },
            )) = state.local.types.get(type_id)
        {
            columns.extend(fields.iter().map(|field| ColumnMutation {
                name: field.name.clone(),
                ty: Some(field.data_type.clone()),
                type_modifier: None,
                not_null: false,
                is_primary_key: false,
                primary_key_constraint_name: None,
                is_unique: false,
                unique_constraint_name: None,
                default: None,
                generation: crate::_internal::analysis::facts::ColumnGeneration::Ordinary,
                identity_sequence: None,
                generated_expr: None,
                generated_expr_sql: None,
            }));
        }
        let mut as_select_columns_known = !as_select;
        if as_select && select_projection_complete {
            let source_id = select_source
                .as_ref()
                .map(|source| Self::resolve_relation_lookup_name(source, state));
            if let Some(source_id) = source_id
                && let Some(crate::_internal::model::relation::RelationOverlay::Present(source)) =
                    state.local.relations.get(&source_id)
            {
                let mut projected = Vec::new();
                let mut complete = true;
                for output in select_outputs {
                    match output {
                        SelectOutputFact::AllColumns => {
                            projected.extend(source.columns.iter().map(|column| ColumnMutation {
                                name: column.name.clone(),
                                ty: column.data_type.clone(),
                                type_modifier: column.type_modifier,
                                not_null: false,
                                is_primary_key: false,
                                primary_key_constraint_name: None,
                                is_unique: false,
                                unique_constraint_name: None,
                                default: None,
                                generation:
                                    crate::_internal::analysis::facts::ColumnGeneration::Ordinary,
                                identity_sequence: None,
                                generated_expr: None,
                                generated_expr_sql: None,
                            }));
                        }
                        SelectOutputFact::Column {
                            source_name,
                            output_name,
                        } => {
                            let Some(column) = source.get_column(source_name) else {
                                complete = false;
                                break;
                            };
                            projected.push(ColumnMutation {
                                name: output_name.clone(),
                                ty: column.data_type.clone(),
                                type_modifier: column.type_modifier,
                                not_null: false,
                                is_primary_key: false,
                                primary_key_constraint_name: None,
                                is_unique: false,
                                unique_constraint_name: None,
                                default: None,
                                generation:
                                    crate::_internal::analysis::facts::ColumnGeneration::Ordinary,
                                identity_sequence: None,
                                generated_expr: None,
                                generated_expr_sql: None,
                            });
                        }
                    }
                }
                if complete {
                    columns = projected;
                    as_select_columns_known = true;
                }
            }
        }
        let foreign_keys = foreign_keys
            .iter()
            .map(|foreign_key| FkMutation {
                constraint_name: foreign_key.constraint_name.clone(),
                to_table: Self::resolve_relation_lookup_name(&foreign_key.references, state),
                from_columns: foreign_key.from_columns.clone(),
                to_columns: foreign_key.to_columns.clone(),
            })
            .collect();
        Mutation::CreateTable(CreateTable {
            id: Self::resolve_creation_name(name, state),
            if_not_exists,
            as_select,
            as_select_columns_known,
            persistence,
            on_commit,
            columns,
            foreign_keys,
            table_constraints: table_constraints.to_vec(),
            partition_by: partition_by.clone(),
            partition_strategy: partition_strategy.clone(),
            partition_of: partition_of
                .as_ref()
                .map(|parent| Self::resolve_relation_lookup_name(parent, state)),
            partition_bound: partition_bound.clone(),
            inherits: inherits
                .iter()
                .map(|parent| Self::resolve_relation_lookup_name(parent, state))
                .collect(),
            like_sources: like_sources
                .iter()
                .map(|source| LikeSourceMutation {
                    relation: Self::resolve_relation_lookup_name(&source.relation, state),
                    properties: source.properties,
                })
                .collect(),
            of_type,
        })
    }

    pub(super) fn resolve_alter_table(
        name: &QualifiedName,
        only: bool,
        actions: &[AlterTableActionFact],
        state: &AnalysisState,
    ) -> Vec<Mutation> {
        let id = Self::resolve_relation_lookup_name(name, state);
        let mut mutations = Vec::with_capacity(actions.len());
        for action_fact in actions {
            let action = match action_fact {
                AlterTableActionFact::AddColumn {
                    name,
                    ty,
                    if_not_exists,
                    not_null,
                    default,
                    generation,
                    identity_sequence,
                    generated_expr,
                    generated_expr_sql,
                } => AlterTableActionMutation::AddColumn {
                    name: name.clone(),
                    ty: ty.clone(),
                    if_not_exists: *if_not_exists,
                    not_null: *not_null,
                    default: default.clone(),
                    depends_on: None,
                    generation: *generation,
                    identity_sequence: identity_sequence.as_ref().map(|options| {
                        crate::_internal::analysis::mutations::IdentitySequenceOptionsMutation {
                            data_type: options.data_type.clone(),
                            start_value: options.start_value,
                            increment: options.increment,
                            min_value: options.min_value,
                            max_value: options.max_value,
                            cache_size: options.cache_size,
                            cycle: options.cycle,
                            persistence: options.persistence,
                            sequence_name: options.sequence_name.as_ref().map(|name| {
                                Self::resolve_creation_name(name, state)
                            }),
                        }
                    }),
                    generated_expr: generated_expr.clone(),
                    generated_expr_sql: generated_expr_sql.clone(),
                },
                AlterTableActionFact::DropColumn {
                    name,
                    if_exists,
                    cascade,
                } => AlterTableActionMutation::DropColumn {
                    name: name.clone(),
                    if_exists: *if_exists,
                    cascade: *cascade,
                },
                AlterTableActionFact::RenameColumn { from, to } => {
                    AlterTableActionMutation::RenameColumn {
                        from: from.resolve(),
                        to: to.resolve(),
                    }
                }
                AlterTableActionFact::RenameTo { new_name } => {
                    let mut new_id = ObjectId::new(id.schema.clone(), new_name.resolve());
                    new_id.inferred_schema = id.inferred_schema;
                    mutations.push(Mutation::Rename(Rename {
                        old_id: id.clone(),
                        new_id,
                    }));
                    continue;
                }
                AlterTableActionFact::SetSchema { new_schema } => {
                    mutations.push(Mutation::Rename(Rename {
                        old_id: id.clone(),
                        new_id: ObjectId::new(new_schema, &id.name),
                    }));
                    continue;
                }
                AlterTableActionFact::AddForeignKey {
                    constraint_name,
                    references,
                    from_columns,
                    to_columns,
                    not_valid,
                } => {
                    let to_table = Self::resolve_relation_lookup_name(references, state);
                    AlterTableActionMutation::AddForeignKey {
                        constraint_name: constraint_name.clone(),
                        to_table,
                        from_columns: from_columns.clone(),
                        to_columns: to_columns.clone(),
                        not_valid: *not_valid,
                    }
                }
                AlterTableActionFact::AlterConstraint { name, deferrable } => {
                    AlterTableActionMutation::AlterConstraint {
                        name: name.clone(),
                        deferrable: *deferrable,
                    }
                }
                AlterTableActionFact::RenameConstraint { old_name, new_name } => {
                    AlterTableActionMutation::RenameConstraint {
                        old_name: old_name.clone(),
                        new_name: new_name.clone(),
                    }
                }
                AlterTableActionFact::DropConstraint {
                    name,
                    if_exists,
                    cascade,
                } => AlterTableActionMutation::DropConstraint {
                    name: name.clone(),
                    if_exists: *if_exists,
                    cascade: *cascade,
                },
                AlterTableActionFact::AddCheckConstraint {
                    constraint_name,
                    definition,
                    columns,
                    columns_complete,
                    not_valid,
                } => AlterTableActionMutation::AddCheckConstraint {
                    constraint_name: constraint_name.clone(),
                    definition: definition.clone(),
                    columns: columns.clone(),
                    columns_complete: *columns_complete,
                    not_valid: *not_valid,
                },
                AlterTableActionFact::AddUniqueConstraint {
                    constraint_name,
                    columns,
                    using_index,
                } => AlterTableActionMutation::AddUniqueConstraint {
                    constraint_name: constraint_name.clone(),
                    columns: columns.clone(),
                    using_index: using_index
                        .as_ref()
                        .map(|name| Self::resolve_constraint_index_name(name, &id)),
                },
                AlterTableActionFact::AddPrimaryKeyConstraint {
                    constraint_name,
                    columns,
                    using_index,
                } => AlterTableActionMutation::AddPrimaryKeyConstraint {
                    constraint_name: constraint_name.clone(),
                    columns: columns.clone(),
                    using_index: using_index
                        .as_ref()
                        .map(|name| Self::resolve_constraint_index_name(name, &id)),
                },
                AlterTableActionFact::AddExcludeConstraint {
                    constraint_name,
                    columns,
                    columns_complete,
                } => AlterTableActionMutation::AddExcludeConstraint {
                    constraint_name: constraint_name.clone(),
                    columns: columns.clone(),
                    columns_complete: *columns_complete,
                },
                AlterTableActionFact::SetNotNull { column } => {
                    AlterTableActionMutation::SetNotNull {
                        column: column.clone(),
                    }
                }
                AlterTableActionFact::DropNotNull { column } => {
                    AlterTableActionMutation::DropNotNull {
                        column: column.clone(),
                    }
                }
                AlterTableActionFact::SetType {
                    column,
                    ty,
                    has_using,
                } => AlterTableActionMutation::SetType {
                    column: column.clone(),
                    ty: ty.clone(),
                    has_using: *has_using,
                },
                AlterTableActionFact::SetDefault { column, default } => {
                    AlterTableActionMutation::SetDefault {
                        column: column.clone(),
                        default: default.clone(),
                    }
                }
                AlterTableActionFact::ValidateConstraint { constraint_name } => {
                    AlterTableActionMutation::ValidateConstraint {
                        constraint_name: constraint_name.clone(),
                    }
                }
                AlterTableActionFact::AttachPartition { child, strategy, bound } => {
                    AlterTableActionMutation::AttachPartition {
                        child: Self::resolve_relation_lookup_name(child, state),
                        strategy: strategy.clone(),
                        bound: bound.clone(),
                    }
                }
                AlterTableActionFact::DetachPartition { child, mode } => {
                    AlterTableActionMutation::DetachPartition {
                        child: Self::resolve_relation_lookup_name(child, state),
                        mode: *mode,
                    }
                }
                AlterTableActionFact::SetStorage { column, mode } => {
                    AlterTableActionMutation::SetStorage {
                        column: column.clone(),
                        mode: mode.clone(),
                    }
                }
                AlterTableActionFact::SetCompression { column, method } => {
                    AlterTableActionMutation::SetCompression {
                        column: column.clone(),
                        method: method.clone(),
                    }
                }
                AlterTableActionFact::SetStatistics { column, target } => {
                    AlterTableActionMutation::SetStatistics {
                        column: column.clone(),
                        target: *target,
                    }
                }
                AlterTableActionFact::DropExpression { column, if_exists } => {
                    AlterTableActionMutation::DropGeneratedExpression {
                        column: column.clone(),
                        if_exists: *if_exists,
                    }
                }
                AlterTableActionFact::SetAccessMethod { access_method } => {
                    AlterTableActionMutation::SetAccessMethod {
                        access_method: access_method.clone(),
                    }
                }
                AlterTableActionFact::DisableTrigger { trigger_name } => {
                    AlterTableActionMutation::DisableTrigger {
                        trigger_name: trigger_name.clone(),
                    }
                }
                AlterTableActionFact::EnableTrigger { trigger_name } => {
                    AlterTableActionMutation::EnableTrigger {
                        trigger_name: trigger_name.clone(),
                    }
                }
                AlterTableActionFact::EnableAlwaysTrigger { trigger_name } => {
                    AlterTableActionMutation::SetTriggerMode {
                        trigger_name: trigger_name.clone(),
                        mode: crate::_internal::model::trigger::TriggerEnableMode::Always,
                    }
                }
                AlterTableActionFact::EnableReplicaTrigger { trigger_name } => {
                    AlterTableActionMutation::SetTriggerMode {
                        trigger_name: trigger_name.clone(),
                        mode: crate::_internal::model::trigger::TriggerEnableMode::Replica,
                    }
                }
                AlterTableActionFact::SetRuleMode { rule_name, mode } => {
                    AlterTableActionMutation::SetRuleMode {
                        rule_name: rule_name.clone(),
                        mode: match mode {
                            crate::_internal::analysis::facts::RuleEnableModeFact::Origin => {
                                crate::_internal::model::relation::RuleEnableMode::Origin
                            }
                            crate::_internal::analysis::facts::RuleEnableModeFact::Disabled => {
                                crate::_internal::model::relation::RuleEnableMode::Disabled
                            }
                            crate::_internal::analysis::facts::RuleEnableModeFact::Replica => {
                                crate::_internal::model::relation::RuleEnableMode::Replica
                            }
                            crate::_internal::analysis::facts::RuleEnableModeFact::Always => {
                                crate::_internal::model::relation::RuleEnableMode::Always
                            }
                        },
                    }
                }
                AlterTableActionFact::SetTablespace { tablespace } => {
                    AlterTableActionMutation::SetTablespace {
                        tablespace: tablespace.clone(),
                    }
                }
                AlterTableActionFact::SetLogged => AlterTableActionMutation::SetPersistence {
                    persistence: crate::_internal::model::relation::Persistence::Permanent,
                },
                AlterTableActionFact::SetUnlogged => AlterTableActionMutation::SetPersistence {
                    persistence: crate::_internal::model::relation::Persistence::Unlogged,
                },
                AlterTableActionFact::ClusterOn { index } => AlterTableActionMutation::SetCluster {
                    index: Some(Self::resolve_constraint_index_name(index, &id)),
                },
                AlterTableActionFact::SetWithoutCluster => {
                    AlterTableActionMutation::SetCluster { index: None }
                }
                AlterTableActionFact::ReplicaIdentity { option } => {
                    AlterTableActionMutation::SetReplicaIdentity {
                        option: match option {
                            crate::_internal::analysis::facts::ReplicaIdentityFact::Default =>
                                crate::_internal::analysis::mutations::ReplicaIdentityMutation::Default,
                            crate::_internal::analysis::facts::ReplicaIdentityFact::Full =>
                                crate::_internal::analysis::mutations::ReplicaIdentityMutation::Full,
                            crate::_internal::analysis::facts::ReplicaIdentityFact::Nothing =>
                                crate::_internal::analysis::mutations::ReplicaIdentityMutation::Nothing,
                            crate::_internal::analysis::facts::ReplicaIdentityFact::UsingIndex(index) =>
                                crate::_internal::analysis::mutations::ReplicaIdentityMutation::UsingIndex(
                                    Self::resolve_constraint_index_name(index, &id),
                                ),
                        },
                    }
                }
                AlterTableActionFact::ForceRls => {
                    AlterTableActionMutation::SetForceRowSecurity { enabled: true }
                }
                AlterTableActionFact::NoForceRls => {
                    AlterTableActionMutation::SetForceRowSecurity { enabled: false }
                }
                AlterTableActionFact::EnableRls => {
                    AlterTableActionMutation::SetRowSecurity { enabled: true }
                }
                AlterTableActionFact::DisableRls => {
                    AlterTableActionMutation::SetRowSecurity { enabled: false }
                }
                AlterTableActionFact::SetExpression { column, expr, expression_sql } => {
                    AlterTableActionMutation::SetGeneratedExpression {
                        column: column.clone(),
                        expr: expr.clone(),
                        expression_sql: expression_sql.clone(),
                    }
                }
                AlterTableActionFact::InheritTable { parent } => {
                    AlterTableActionMutation::InheritTable {
                        parent: Self::resolve_relation_lookup_name(parent, state),
                    }
                }
                AlterTableActionFact::NoInheritTable { parent } => {
                    AlterTableActionMutation::NoInheritTable {
                        parent: Self::resolve_relation_lookup_name(parent, state),
                    }
                }
                AlterTableActionFact::OfType { type_name } => {
                    AlterTableActionMutation::SetOfType {
                        type_id: Some(Self::resolve_type_lookup_name(type_name, state)),
                    }
                }
                AlterTableActionFact::NotOf => AlterTableActionMutation::SetOfType { type_id: None },
                AlterTableActionFact::SetOptions { column, attributes } => {
                    AlterTableActionMutation::SetColumnOptions {
                        column: column.clone(),
                        attributes: attributes.clone(),
                    }
                }
                AlterTableActionFact::ResetOptions { column, names } => {
                    AlterTableActionMutation::ResetColumnOptions {
                        column: column.clone(),
                        names: names.clone(),
                    }
                }
                AlterTableActionFact::SetTableOptions { attributes } => {
                    AlterTableActionMutation::SetTableOptions {
                        attributes: attributes.clone(),
                    }
                }
                AlterTableActionFact::ResetTableOptions { names } => {
                    AlterTableActionMutation::ResetTableOptions {
                        names: names.clone(),
                    }
                }
                AlterTableActionFact::Inherit { .. } | AlterTableActionFact::NoInherit { .. } => {
                    AlterTableActionMutation::AlterColumnInheritance
                }
                AlterTableActionFact::MergePartitions { .. }
                | AlterTableActionFact::SplitPartition => {
                    AlterTableActionMutation::PartitionReshape
                }
                AlterTableActionFact::OwnerTo { new_owner } => AlterTableActionMutation::OwnerTo {
                    new_owner: new_owner.clone(),
                },
            };
            mutations.push(Mutation::AlterTable(AlterTable {
                id: id.clone(),
                only,
                action,
            }));
        }
        mutations
    }

    pub(super) fn resolve_drop_table(
        names: &[QualifiedName],
        if_exists: bool,
        cascade: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropTable(DropTable {
            ids: names
                .iter()
                .map(|name| Self::resolve_relation_lookup_name(name, state))
                .collect(),
            if_exists,
            cascade,
        })
    }

    pub(super) fn resolve_drop_view(
        names: &[QualifiedName],
        if_exists: bool,
        cascade: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropView(DropViewMutation {
            ids: names
                .iter()
                .map(|name| Self::resolve_relation_lookup_name(name, state))
                .collect(),
            if_exists,
            cascade,
        })
    }

    pub(super) fn resolve_drop_materialized_view(
        names: &[QualifiedName],
        if_exists: bool,
        cascade: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropMaterializedView(DropMaterializedViewMutation {
            ids: names
                .iter()
                .map(|name| Self::resolve_relation_lookup_name(name, state))
                .collect(),
            if_exists,
            cascade,
        })
    }

    pub(super) fn resolve_drop_indexes(
        names: &[QualifiedName],
        if_exists: bool,
        concurrently: bool,
        cascade: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropIndex(DropIndex {
            ids: names
                .iter()
                .map(|name| Self::resolve_relation_lookup_name(name, state))
                .collect(),
            if_exists,
            concurrently,
            cascade,
        })
    }
}
