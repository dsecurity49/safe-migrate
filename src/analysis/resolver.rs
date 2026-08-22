use crate::analysis::facts::{
    AlterIndexActionFact, AlterTableActionFact, PersistenceFact, StatementFact, TypeCreationKind,
};
use crate::analysis::mutations::{
    AlterAggregateMutation, AlterDatabaseMutation, AlterDomainMutation, AlterFunctionMutation,
    AlterProcedureMutation, AlterPublicationMutation, AlterRoleMutation, AlterSchemaMutation,
    AlterSequenceActionMutation, AlterSequenceMutation, AlterSubscriptionMutation, AlterTable,
    AlterTableActionMutation, AlterTypeActionMutation, AlterTypeMutation, ColumnMutation,
    CreateAggregateMutation, CreateDatabaseMutation, CreateDomainMutation, CreateFunctionMutation,
    CreateIndex, CreateMaterializedView, CreatePolicyMutation, CreateProcedureMutation,
    CreatePublicationMutation, CreateRoleMutation, CreateSchemaMutation, CreateSequenceMutation,
    CreateSubscriptionMutation, CreateTable, CreateTriggerMutation, CreateTypeMutation, CreateView,
    DropAggregateMutation, DropDatabaseMutation, DropDomainMutation, DropFunctionMutation,
    DropIndex, DropMaterializedViewMutation, DropPolicyMutation, DropProcedureMutation,
    DropPublicationMutation, DropRoleMutation, DropSchemaMutation, DropSequenceMutation,
    DropSubscriptionMutation, DropTable, DropTriggerMutation, DropTypeMutation, DropViewMutation,
    FkMutation, GrantMutation, Mutation, OpaqueMutation, PersistenceMutation,
    RefreshMaterializedViewMutation, ReleaseSavepointMutation, Rename, RenameTriggerMutation,
    ResolvedGrantTarget, RevokeMutation, RollbackToSavepointMutation, SavepointMutation,
    SearchPathChange, TimeoutSettingChange,
};
use crate::analysis::state::AnalysisState;
use crate::ast::identifiers::{ObjectId, QualifiedName};
use crate::model::types::TypeKind;

pub struct Resolver;

impl Resolver {
    fn resolve_creation_name(name: &QualifiedName, state: &AnalysisState) -> ObjectId {
        let schema = name
            .schema
            .as_ref()
            .map(|i| i.resolve())
            .unwrap_or_else(|| {
                state
                    .local
                    .search_path
                    .first()
                    .map(|s| s.as_str())
                    .unwrap_or("public")
                    .to_string()
            });

        ObjectId::new(schema, name.name.resolve())
    }

    fn resolve_lookup_name(name: &QualifiedName, state: &AnalysisState) -> ObjectId {
        if let Some(schema_ident) = &name.schema {
            return ObjectId::new(schema_ident.resolve(), name.name.resolve());
        }

        let resolved_name = name.name.resolve();

        for schema in &state.local.search_path {
            let mut candidate = ObjectId::new(schema.clone(), resolved_name.clone());
            if state.local.relations.contains_key(&candidate)
                || state.local.types.contains_key(&candidate)
                || state.local.sequences.contains_key(&candidate)
                || state.local.functions.keys().any(|k| {
                    k.schema == candidate.schema
                        && (k.name == candidate.name
                            || k.name.starts_with(&format!("{}(", candidate.name)))
                })
            {
                candidate.inferred_schema = true;
                return candidate;
            }
        }

        let schema = state
            .local
            .search_path
            .first()
            .map(|s| s.as_str())
            .unwrap_or("public")
            .to_string();
        let mut id = ObjectId::new(schema, resolved_name);
        id.inferred_schema = true;
        id
    }

    fn resolve_type_lookup_name(name: &QualifiedName, state: &AnalysisState) -> ObjectId {
        if let Some(schema_ident) = &name.schema {
            return ObjectId::new(schema_ident.resolve(), name.name.resolve());
        }

        let resolved_name = name.name.resolve();
        for schema in &state.local.search_path {
            let mut candidate = ObjectId::new(schema.clone(), resolved_name.clone());
            if matches!(
                state.local.types.get(&candidate),
                Some(crate::model::types::TypeOverlay::Present(_))
            ) {
                candidate.inferred_schema = true;
                return candidate;
            }
        }

        let schema = state
            .local
            .search_path
            .first()
            .cloned()
            .unwrap_or_else(|| "public".to_string());
        let mut id = ObjectId::new(schema, resolved_name);
        id.inferred_schema = true;
        id
    }

    fn resolve_constraint_index_name(name: &QualifiedName, table: &ObjectId) -> ObjectId {
        let schema = name
            .schema
            .as_ref()
            .map(|schema| schema.resolve())
            .unwrap_or_else(|| table.schema.clone());
        ObjectId::new(schema, name.name.resolve())
    }

    fn resolve_function_id(
        name: &QualifiedName,
        params: &[crate::analysis::facts::ParamFact],
        state: &AnalysisState,
    ) -> ObjectId {
        let base_id = Self::resolve_creation_name(name, state);
        let sig = params
            .iter()
            .filter(|p| !matches!(&p.mode, crate::analysis::facts::ParamModeFact::Out))
            .map(|p| p.ty.clone())
            .collect::<Vec<_>>()
            .join(",");
        Self::resolve_function_id_by_sig(&base_id, &sig)
    }

    fn resolve_function_id_by_sig(base_id: &ObjectId, sig: &str) -> ObjectId {
        // Normalize types in signature to match pg_proc standard names
        let normalized_sig = sig
            .split(',')
            .map(Self::normalize_function_arg_type)
            .collect::<Vec<_>>()
            .join(",");

        let mut id = ObjectId::new(
            base_id.schema.clone(),
            format!("{}({})", base_id.name, normalized_sig),
        );
        id.inferred_schema = base_id.inferred_schema;
        id
    }

    fn resolve_publication_object(
        object: &crate::analysis::facts::PublicationObjectFact,
        state: &AnalysisState,
    ) -> crate::analysis::facts::PublicationObjectFact {
        match object {
            crate::analysis::facts::PublicationObjectFact::Table {
                name,
                only,
                include_partitions,
                columns,
                row_filter,
            } => {
                let id = Self::resolve_lookup_name(name, state);
                crate::analysis::facts::PublicationObjectFact::Table {
                    name: crate::ast::identifiers::QualifiedName::new(
                        Some(crate::ast::identifiers::Ident::new(id.schema, true)),
                        crate::ast::identifiers::Ident::new(id.name, true),
                    ),
                    only: *only,
                    include_partitions: *include_partitions,
                    columns: columns.clone(),
                    row_filter: row_filter.clone(),
                }
            }
            crate::analysis::facts::PublicationObjectFact::CurrentSchemaShorthand => {
                crate::analysis::facts::PublicationObjectFact::SchemaTables {
                    schema: state
                        .local
                        .search_path
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "public".to_string()),
                    row_filter: None,
                }
            }
            other => other.clone(),
        }
    }

    fn resolve_publication_scope(
        scope: &crate::analysis::facts::PublicationScope,
        state: &AnalysisState,
    ) -> crate::analysis::facts::PublicationScope {
        match scope {
            crate::analysis::facts::PublicationScope::AllTables { except } => {
                crate::analysis::facts::PublicationScope::AllTables {
                    except: except.clone(),
                }
            }
            crate::analysis::facts::PublicationScope::Explicit(objects) => {
                crate::analysis::facts::PublicationScope::Explicit(
                    objects
                        .iter()
                        .map(|object| Self::resolve_publication_object(object, state))
                        .collect(),
                )
            }
        }
    }

    fn resolve_alter_publication_action(
        action: &crate::analysis::facts::AlterPublicationActionFact,
        state: &AnalysisState,
    ) -> crate::analysis::facts::AlterPublicationActionFact {
        use crate::analysis::facts::AlterPublicationActionFact;
        match action {
            AlterPublicationActionFact::AddObjects(objects) => {
                AlterPublicationActionFact::AddObjects(
                    objects
                        .iter()
                        .map(|object| Self::resolve_publication_object(object, state))
                        .collect(),
                )
            }
            AlterPublicationActionFact::DropObjects(objects) => {
                AlterPublicationActionFact::DropObjects(
                    objects
                        .iter()
                        .map(|object| Self::resolve_publication_object(object, state))
                        .collect(),
                )
            }
            AlterPublicationActionFact::SetObjects(scope) => {
                AlterPublicationActionFact::SetObjects(Self::resolve_publication_scope(
                    scope, state,
                ))
            }
            other => other.clone(),
        }
    }

    pub(crate) fn normalize_function_arg_type(raw: &str) -> String {
        let normalized = Self::fold_unquoted_identifier_case(raw.trim());
        if let Some(element_type) = normalized.strip_suffix("[]") {
            return format!("{}[]", Self::normalize_function_arg_type(element_type));
        }
        match normalized.as_str() {
            "int" | "int4" => "integer".to_string(),
            "int8" => "bigint".to_string(),
            "int2" => "smallint".to_string(),
            "float8" => "double precision".to_string(),
            "float4" => "real".to_string(),
            "bool" => "boolean".to_string(),
            "varchar" => "character varying".to_string(),
            "char" => "character".to_string(),
            "time" => "time without time zone".to_string(),
            "timestamp" => "timestamp without time zone".to_string(),
            "timestamptz" => "timestamp with time zone".to_string(),
            "decimal" => "numeric".to_string(),
            _ => normalized,
        }
    }

    fn fold_unquoted_identifier_case(raw: &str) -> String {
        let mut folded = String::with_capacity(raw.len());
        let mut quoted = false;
        let mut chars = raw.chars().peekable();
        while let Some(character) = chars.next() {
            match character {
                '"' if quoted && chars.peek() == Some(&'"') => {
                    folded.push('"');
                    folded.push('"');
                    chars.next();
                }
                '"' => {
                    quoted = !quoted;
                    folded.push(character);
                }
                character if quoted => folded.push(character),
                character => folded.extend(character.to_lowercase()),
            }
        }
        folded
    }

    fn resolve_grant_target(
        target: &crate::analysis::facts::GrantTarget,
        state: &AnalysisState,
    ) -> ResolvedGrantTarget {
        match target {
            crate::analysis::facts::GrantTarget::Tables(names) => ResolvedGrantTarget::Tables(
                names
                    .iter()
                    .map(|n| Self::resolve_lookup_name(n, state))
                    .collect(),
            ),
            crate::analysis::facts::GrantTarget::AllTablesInSchema(schemas) => {
                ResolvedGrantTarget::AllTablesInSchema(schemas.clone())
            }
        }
    }

    pub fn resolve(fact: &StatementFact, state: &AnalysisState) -> Vec<Mutation> {
        let mut mutations = Vec::new();
        match fact {
            StatementFact::CreateSchema {
                name,
                if_not_exists,
                authorization,
            } => {
                mutations.push(Mutation::CreateSchema(CreateSchemaMutation {
                    name: name.name.resolve(),
                    if_not_exists: *if_not_exists,
                    authorization: authorization.clone(),
                }));
            }
            StatementFact::SchemaNeutralNoop => {}
            StatementFact::AlterSchema { name, action } => {
                let name = name.name.resolve();
                let action = match action {
                    crate::analysis::facts::AlterSchemaActionFact::RenameTo { new_name } => {
                        AlterSchemaMutation::Rename {
                            old_name: name,
                            new_name: new_name.resolve(),
                        }
                    }
                    crate::analysis::facts::AlterSchemaActionFact::OwnerTo { new_owner } => {
                        AlterSchemaMutation::OwnerTo {
                            name,
                            new_owner: new_owner.clone(),
                        }
                    }
                };
                mutations.push(Mutation::AlterSchema(action));
            }
            StatementFact::DropSchema {
                names,
                if_exists,
                cascade,
            } => {
                mutations.push(Mutation::DropSchema(DropSchemaMutation {
                    names: names.iter().map(|n| n.name.resolve()).collect(),
                    if_exists: *if_exists,
                    cascade: *cascade,
                }));
            }
            StatementFact::CreateTable {
                name,
                if_not_exists,
                as_select,
                persistence,
                columns,
                foreign_keys,
                table_constraints,
                partition_by,
                partition_of,
                partition_type,
            } => {
                let id = Self::resolve_creation_name(name, state);

                let resolved_persistence = match persistence {
                    PersistenceFact::Permanent => PersistenceMutation::Permanent,
                    PersistenceFact::Temporary => PersistenceMutation::Temporary,
                    PersistenceFact::Unlogged => PersistenceMutation::Unlogged,
                };

                let col_mutations: Vec<ColumnMutation> = columns
                    .iter()
                    .map(|c| ColumnMutation {
                        name: c.name.clone(),
                        ty: c.ty.clone(),
                        not_null: c.not_null,
                        is_primary_key: c.is_primary_key,
                        primary_key_constraint_name: c.primary_key_constraint_name.clone(),
                        is_unique: c.is_unique,
                        unique_constraint_name: c.unique_constraint_name.clone(),
                        default: c.default.clone(),
                        generation: c.generation,
                    })
                    .collect();

                let mut fk_mutations = Vec::new();
                for fk in foreign_keys {
                    let to_table = Self::resolve_lookup_name(&fk.references, state);

                    fk_mutations.push(FkMutation {
                        constraint_name: fk.constraint_name.clone(),
                        to_table,
                        from_columns: fk.from_columns.clone(),
                        to_columns: fk.to_columns.clone(),
                    });
                }

                let partition_of_id = partition_of
                    .as_ref()
                    .map(|n| Self::resolve_lookup_name(n, state));

                mutations.push(Mutation::CreateTable(CreateTable {
                    id,
                    if_not_exists: *if_not_exists,
                    as_select: *as_select,
                    persistence: resolved_persistence,
                    columns: col_mutations,
                    foreign_keys: fk_mutations,
                    table_constraints: table_constraints.clone(),
                    partition_by: partition_by.clone(),
                    partition_of: partition_of_id,
                    partition_type: partition_type.clone(),
                }));
            }
            StatementFact::CreateView {
                name,
                or_replace,
                depends_on,
            } => {
                let id = Self::resolve_creation_name(name, state);

                let resolved_depends = depends_on
                    .iter()
                    .map(|n| Self::resolve_lookup_name(n, state))
                    .collect();

                mutations.push(Mutation::CreateView(CreateView {
                    id,
                    or_replace: *or_replace,
                    depends_on: resolved_depends,
                }));
            }
            StatementFact::AlterView { name, action } => {
                match action {
                    crate::analysis::facts::AlterViewAction::RenameTo { new_name } => {
                        let id = Self::resolve_lookup_name(name, state);
                        let mut new_id = ObjectId::new(id.schema.clone(), new_name.resolve());
                        new_id.inferred_schema = id.inferred_schema;
                        mutations.push(Mutation::Rename(Rename { old_id: id, new_id }));
                    }
                    crate::analysis::facts::AlterViewAction::SetSchema { new_schema } => {
                        let id = Self::resolve_lookup_name(name, state);
                        let new_id = ObjectId::new(new_schema, &id.name);
                        mutations.push(Mutation::Rename(Rename { old_id: id, new_id }));
                    }
                    crate::analysis::facts::AlterViewAction::OwnerTo { new_owner } => {
                        mutations.push(Mutation::ChangeRelationOwner {
                            id: Self::resolve_lookup_name(name, state),
                            new_owner: new_owner.clone(),
                        });
                    }
                    crate::analysis::facts::AlterViewAction::SetDefault { .. }
                    | crate::analysis::facts::AlterViewAction::DropDefault { .. }
                    | crate::analysis::facts::AlterViewAction::RenameColumn { .. }
                    | crate::analysis::facts::AlterViewAction::SetOptions { .. }
                    | crate::analysis::facts::AlterViewAction::ResetOptions { .. } => {
                        // These are opaque from the state machine's perspective —
                        // they don't create or destroy objects, just modify metadata.
                        // No mutation emitted; rules can still check the StatementFact.
                    }
                }
            }
            StatementFact::CreateMaterializedView { name, depends_on } => {
                let id = Self::resolve_creation_name(name, state);

                let resolved_depends = depends_on
                    .iter()
                    .map(|n| Self::resolve_lookup_name(n, state))
                    .collect();

                mutations.push(Mutation::CreateMaterializedView(CreateMaterializedView {
                    id,
                    depends_on: resolved_depends,
                }));
            }
            StatementFact::AlterMaterializedView { name, new_name } => {
                if let Some(new_name) = new_name {
                    let id = Self::resolve_lookup_name(name, state);
                    let mut new_id = ObjectId::new(id.schema.clone(), new_name.resolve());
                    new_id.inferred_schema = id.inferred_schema;
                    mutations.push(Mutation::Rename(Rename { old_id: id, new_id }));
                }
            }
            StatementFact::RefreshMaterializedView { name, concurrently } => {
                mutations.push(Mutation::RefreshMaterializedView(
                    RefreshMaterializedViewMutation {
                        id: Self::resolve_lookup_name(name, state),
                        concurrently: *concurrently,
                    },
                ));
            }
            StatementFact::CreateIndex {
                name,
                relation,
                if_not_exists,
                concurrently,
                using_method,
                has_predicate,
                unique,
            } => {
                let table = Self::resolve_lookup_name(relation, state);
                // PostgreSQL places an unqualified index in the indexed
                // relation's schema, not the first schema in search_path.
                let id = if name.schema.is_some() {
                    Self::resolve_creation_name(name, state)
                } else {
                    ObjectId::new(table.schema.clone(), name.name.resolve())
                };

                mutations.push(Mutation::CreateIndex(CreateIndex {
                    id,
                    table,
                    if_not_exists: *if_not_exists,
                    concurrently: *concurrently,
                    using_method: using_method.clone(),
                    has_predicate: *has_predicate,
                    unique: *unique,
                }));
            }
            StatementFact::CreatePolicy {
                name,
                table,
                permissive,
                command,
            } => {
                mutations.push(Mutation::CreatePolicy(CreatePolicyMutation {
                    name: name.clone(),
                    table: Self::resolve_lookup_name(table, state),
                    permissive: *permissive,
                    command: command.clone(),
                }));
            }
            StatementFact::DropPolicy {
                name,
                table,
                if_exists,
            } => {
                mutations.push(Mutation::DropPolicy(DropPolicyMutation {
                    name: name.clone(),
                    table: Self::resolve_lookup_name(table, state),
                    if_exists: *if_exists,
                }));
            }
            StatementFact::CreateTrigger {
                name,
                table,
                function,
            } => {
                // Function references in triggers are bare names (e.g., "notify_func")
                // but functions are stored with signature (e.g., "notify_func()").
                // Use resolve_function_id_by_sig with empty params for consistent lookup.
                let function_base = function
                    .as_ref()
                    .map(|f| Self::resolve_lookup_name(f, state))
                    .unwrap_or_else(|| ObjectId::new("public", "unknown_function"));
                let function_id = Self::resolve_function_id_by_sig(&function_base, "");
                mutations.push(Mutation::CreateTrigger(CreateTriggerMutation {
                    name: name.clone(),
                    table: Self::resolve_lookup_name(table, state),
                    function_id,
                }));
            }
            StatementFact::DropTrigger {
                name,
                table,
                if_exists,
            } => {
                mutations.push(Mutation::DropTrigger(DropTriggerMutation {
                    name: name.clone(),
                    table: Self::resolve_lookup_name(table, state),
                    if_exists: *if_exists,
                }));
            }
            StatementFact::AlterTrigger {
                name,
                table,
                new_name,
            } => mutations.push(Mutation::RenameTrigger(RenameTriggerMutation {
                name: name.clone(),
                table: Self::resolve_lookup_name(table, state),
                new_name: new_name.clone(),
            })),
            StatementFact::AlterIndex { name, actions } => {
                let id = Self::resolve_lookup_name(name, state);
                for action in actions {
                    match action {
                        AlterIndexActionFact::RenameTo { new_name } => {
                            let mut new_id = ObjectId::new(id.schema.clone(), new_name.resolve());
                            new_id.inferred_schema = id.inferred_schema;
                            mutations.push(Mutation::Rename(Rename {
                                old_id: id.clone(),
                                new_id,
                            }));
                        }
                    }
                }
            }
            StatementFact::CreateType(create_type) => {
                let id = Self::resolve_creation_name(&create_type.name, state);

                let mapped_kind = match &create_type.kind {
                    TypeCreationKind::Enum { variants } => TypeKind::Enum {
                        variants: variants.clone(),
                    },
                    TypeCreationKind::Range => TypeKind::Range,
                    TypeCreationKind::Composite => TypeKind::Composite,
                    TypeCreationKind::Base => TypeKind::Base,
                };

                mutations.push(Mutation::CreateType(CreateTypeMutation {
                    id,
                    kind: mapped_kind,
                }));
            }
            StatementFact::AlterType(alter_type) => {
                let id = Self::resolve_type_lookup_name(&alter_type.name, state);
                for action_fact in &alter_type.actions {
                    match action_fact {
                        crate::analysis::facts::AlterTypeActionFact::RenameTo { new_name } => {
                            let mut new_id = ObjectId::new(id.schema.clone(), new_name.resolve());
                            new_id.inferred_schema = id.inferred_schema;
                            mutations.push(Mutation::RenameType(Rename {
                                old_id: id.clone(),
                                new_id,
                            }));
                        }
                        crate::analysis::facts::AlterTypeActionFact::SetSchema { new_schema } => {
                            mutations.push(Mutation::RenameType(Rename {
                                old_id: id.clone(),
                                new_id: ObjectId::new(new_schema, &id.name),
                            }));
                        }
                        crate::analysis::facts::AlterTypeActionFact::AddValue {
                            new_value,
                            neighbor,
                            before,
                        } => {
                            mutations.push(Mutation::AlterType(AlterTypeMutation {
                                id: id.clone(),
                                action: AlterTypeActionMutation::AddValue {
                                    new_value: new_value.clone(),
                                    neighbor: neighbor.clone(),
                                    before: *before,
                                },
                            }));
                        }
                        crate::analysis::facts::AlterTypeActionFact::RenameValue {
                            old_value,
                            new_value,
                        } => {
                            mutations.push(Mutation::AlterType(AlterTypeMutation {
                                id: id.clone(),
                                action: AlterTypeActionMutation::RenameValue {
                                    old_value: old_value.clone(),
                                    new_value: new_value.clone(),
                                },
                            }));
                        }
                    }
                }
            }
            StatementFact::CreateDomain { name, base_type } => {
                let id = Self::resolve_creation_name(name, state);

                mutations.push(Mutation::CreateDomain(CreateDomainMutation {
                    id,
                    base_type: base_type.clone(),
                }));
            }
            StatementFact::AlterDomain { name, action } => {
                mutations.push(Mutation::AlterDomain(AlterDomainMutation {
                    id: Self::resolve_lookup_name(name, state),
                    action: action.clone(),
                }));
            }
            StatementFact::DropDomain {
                names,
                if_exists,
                cascade,
            } => {
                let ids = names
                    .iter()
                    .map(|n| Self::resolve_lookup_name(n, state))
                    .collect();
                mutations.push(Mutation::DropDomain(DropDomainMutation {
                    ids,
                    if_exists: *if_exists,
                    cascade: *cascade,
                }));
            }
            StatementFact::DropType {
                names,
                if_exists,
                cascade,
            } => {
                let ids = names
                    .iter()
                    .map(|n| Self::resolve_lookup_name(n, state))
                    .collect();
                mutations.push(Mutation::DropType(DropTypeMutation {
                    ids,
                    if_exists: *if_exists,
                    cascade: *cascade,
                }));
            }
            StatementFact::CreateSequence {
                name,
                if_not_exists,
                owned_by,
            } => {
                let id = Self::resolve_creation_name(name, state);

                let resolved_owned_by = owned_by.as_ref().map(|(table_name, col)| {
                    (Self::resolve_lookup_name(table_name, state), col.clone())
                });
                mutations.push(Mutation::CreateSequence(CreateSequenceMutation {
                    id,
                    if_not_exists: *if_not_exists,
                    owned_by: resolved_owned_by,
                }));
            }
            StatementFact::AlterSequence {
                name,
                if_exists,
                action,
            } => {
                let id = Self::resolve_lookup_name(name, state);
                let action = match action {
                    crate::analysis::facts::AlterSequenceActionFact::OwnedBy(owned_by) => {
                        AlterSequenceActionMutation::OwnedBy(owned_by.as_ref().map(
                            |(table_name, col)| {
                                (Self::resolve_lookup_name(table_name, state), col.clone())
                            },
                        ))
                    }
                    crate::analysis::facts::AlterSequenceActionFact::OwnerTo(owner) => {
                        AlterSequenceActionMutation::OwnerTo(owner.clone())
                    }
                    crate::analysis::facts::AlterSequenceActionFact::RenameTo(new_name) => {
                        AlterSequenceActionMutation::RenameTo(ObjectId::new(
                            &id.schema,
                            new_name.resolve(),
                        ))
                    }
                    crate::analysis::facts::AlterSequenceActionFact::SetSchema(schema) => {
                        AlterSequenceActionMutation::SetSchema(ObjectId::new(schema, &id.name))
                    }
                    crate::analysis::facts::AlterSequenceActionFact::Other => {
                        AlterSequenceActionMutation::Other
                    }
                };
                mutations.push(Mutation::AlterSequence(AlterSequenceMutation {
                    id,
                    if_exists: *if_exists,
                    action,
                }));
            }
            StatementFact::DropSequence {
                names,
                if_exists,
                cascade,
            } => {
                let ids = names
                    .iter()
                    .map(|n| Self::resolve_lookup_name(n, state))
                    .collect();
                mutations.push(Mutation::DropSequence(DropSequenceMutation {
                    ids,
                    if_exists: *if_exists,
                    cascade: *cascade,
                }));
            }
            StatementFact::AlterTable { name, actions } => {
                let id = Self::resolve_lookup_name(name, state);
                for action_fact in actions {
                    let action = match action_fact {
                        AlterTableActionFact::AddColumn {
                            name: col_name,
                            ty,
                            if_not_exists,
                            not_null,
                            default,
                            generation,
                        } => AlterTableActionMutation::AddColumn {
                            name: col_name.clone(),
                            ty: ty.clone(),
                            if_not_exists: *if_not_exists,
                            not_null: *not_null,
                            default: default.clone(),
                            depends_on: None, // Logic for extraction can be added later if needed
                            generation: *generation,
                        },
                        AlterTableActionFact::DropColumn {
                            name: col_name,
                            if_exists,
                        } => AlterTableActionMutation::DropColumn {
                            name: col_name.clone(),
                            if_exists: *if_exists,
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
                            let new_id = ObjectId::new(new_schema, &id.name);
                            mutations.push(Mutation::Rename(Rename {
                                old_id: id.clone(),
                                new_id,
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
                            let to_table = Self::resolve_lookup_name(references, state);
                            if !state.relation_is_present(&to_table) {
                                return vec![Mutation::Opaque(
                                    OpaqueMutation::UnresolvedReference {
                                        object_kind: crate::report::violations::ObjectKind::Table,
                                        object_name: to_table.to_string(),
                                    },
                                )];
                            }
                            AlterTableActionMutation::AddForeignKey {
                                constraint_name: constraint_name.clone(),
                                to_table,
                                from_columns: from_columns.clone(),
                                to_columns: to_columns.clone(),
                                not_valid: *not_valid,
                            }
                        }
                        AlterTableActionFact::AlterConstraint {
                            name: c_name,
                            deferrable,
                        } => AlterTableActionMutation::AlterConstraint {
                            name: c_name.clone(),
                            deferrable: *deferrable,
                        },
                        AlterTableActionFact::RenameConstraint { old_name, new_name } => {
                            AlterTableActionMutation::RenameConstraint {
                                old_name: old_name.clone(),
                                new_name: new_name.clone(),
                            }
                        }
                        AlterTableActionFact::DropConstraint { name: c_name } => {
                            AlterTableActionMutation::DropConstraint {
                                name: c_name.clone(),
                            }
                        }
                        AlterTableActionFact::AddCheckConstraint {
                            constraint_name,
                            not_valid,
                        } => AlterTableActionMutation::AddCheckConstraint {
                            constraint_name: constraint_name.clone(),
                            not_valid: *not_valid,
                        },
                        AlterTableActionFact::AddUniqueConstraint {
                            constraint_name,
                            using_index,
                        } => AlterTableActionMutation::AddUniqueConstraint {
                            constraint_name: constraint_name.clone(),
                            using_index: using_index
                                .as_ref()
                                .map(|name| Self::resolve_constraint_index_name(name, &id)),
                        },
                        AlterTableActionFact::AddPrimaryKeyConstraint {
                            constraint_name,
                            using_index,
                        } => AlterTableActionMutation::AddPrimaryKeyConstraint {
                            constraint_name: constraint_name.clone(),
                            using_index: using_index
                                .as_ref()
                                .map(|name| Self::resolve_constraint_index_name(name, &id)),
                        },
                        AlterTableActionFact::AddExcludeConstraint { constraint_name } => {
                            AlterTableActionMutation::AddExcludeConstraint {
                                constraint_name: constraint_name.clone(),
                            }
                        }
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
                        AlterTableActionFact::AttachPartition { child, strategy } => {
                            let child_id = Self::resolve_lookup_name(child, state);

                            AlterTableActionMutation::AttachPartition {
                                child: child_id,
                                strategy: strategy.clone(),
                            }
                        }
                        AlterTableActionFact::DetachPartition { child } => {
                            AlterTableActionMutation::DetachPartition {
                                child: Self::resolve_lookup_name(child, state),
                            }
                        }
                        AlterTableActionFact::SetStorage { column } => {
                            AlterTableActionMutation::SetStorage {
                                column: column.clone(),
                            }
                        }
                        AlterTableActionFact::SetAccessMethod => {
                            AlterTableActionMutation::SetAccessMethod
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
                        AlterTableActionFact::SetExpression { .. }
                        | AlterTableActionFact::SetOptions { .. }
                        | AlterTableActionFact::Inherit { .. }
                        | AlterTableActionFact::NoInherit { .. }
                        | AlterTableActionFact::ClusterOn { .. }
                        | AlterTableActionFact::InheritTable { .. }
                        | AlterTableActionFact::NoInheritTable { .. }
                        | AlterTableActionFact::MergePartitions { .. }
                        | AlterTableActionFact::SplitPartition
                        | AlterTableActionFact::SetTablespace { .. }
                        | AlterTableActionFact::SetLogged
                        | AlterTableActionFact::SetUnlogged
                        | AlterTableActionFact::ReplicaIdentity { .. }
                        | AlterTableActionFact::ForceRls
                        | AlterTableActionFact::EnableRls
                        | AlterTableActionFact::DisableRls
                        | AlterTableActionFact::EnableAlwaysTrigger { .. }
                        | AlterTableActionFact::EnableReplicaTrigger { .. } => {
                            AlterTableActionMutation::Opaque
                        }
                        AlterTableActionFact::OwnerTo { new_owner } => {
                            AlterTableActionMutation::OwnerTo {
                                new_owner: new_owner.clone(),
                            }
                        }
                    };
                    mutations.push(Mutation::AlterTable(AlterTable {
                        id: id.clone(),
                        action,
                    }));
                }
            }
            StatementFact::DropTable {
                name,
                if_exists,
                cascade,
            } => {
                let id = Self::resolve_lookup_name(name, state);

                // Still emit a DropTable mutation for rule evaluation (e.g. DriftDetectionRule)
                // even when the table is not present locally. The state machine will handle
                // tainting confidence in apply().
                mutations.push(Mutation::DropTable(DropTable {
                    id,
                    if_exists: *if_exists,
                    cascade: *cascade,
                }));
            }
            StatementFact::DropView {
                name,
                if_exists,
                cascade,
            } => {
                mutations.push(Mutation::DropView(DropViewMutation {
                    ids: vec![Self::resolve_lookup_name(name, state)],
                    if_exists: *if_exists,
                    cascade: *cascade,
                }));
            }
            StatementFact::DropMaterializedView {
                names,
                if_exists,
                cascade,
            } => {
                let ids = names
                    .iter()
                    .map(|n| Self::resolve_lookup_name(n, state))
                    .collect();
                mutations.push(Mutation::DropMaterializedView(
                    DropMaterializedViewMutation {
                        ids,
                        if_exists: *if_exists,
                        cascade: *cascade,
                    },
                ));
            }
            StatementFact::DropIndex {
                names,
                if_exists,
                concurrently,
            } => {
                for name in names {
                    mutations.push(Mutation::DropIndex(DropIndex {
                        id: Self::resolve_lookup_name(name, state),
                        if_exists: *if_exists,
                        concurrently: *concurrently,
                    }));
                }
            }
            StatementFact::SetSearchPath { target, local } => {
                mutations.push(Mutation::SearchPath(SearchPathChange {
                    target: target.clone(),
                    local: *local,
                }))
            }
            StatementFact::SetTimeout {
                setting,
                value,
                local,
            } => mutations.push(Mutation::TimeoutSetting(TimeoutSettingChange {
                setting: *setting,
                value: value.clone(),
                local: *local,
            })),
            StatementFact::ResetSettings { target } => {
                mutations.push(Mutation::ResetSettings(*target))
            }
            StatementFact::BeginTransaction => mutations.push(Mutation::BeginTransaction),
            StatementFact::CommitTransaction => mutations.push(Mutation::CommitTransaction),
            StatementFact::CommitAndChain => mutations.push(Mutation::CommitAndChain),
            StatementFact::RollbackTransaction => mutations.push(Mutation::RollbackTransaction),
            StatementFact::RollbackAndChain => mutations.push(Mutation::RollbackAndChain),
            StatementFact::RollbackToSavepoint { name } => {
                mutations.push(Mutation::RollbackToSavepoint(RollbackToSavepointMutation {
                    name: name.clone(),
                }))
            }
            StatementFact::Savepoint { name } => {
                mutations.push(Mutation::Savepoint(SavepointMutation {
                    name: name.clone(),
                }))
            }
            StatementFact::ReleaseSavepoint { name } => {
                mutations.push(Mutation::ReleaseSavepoint(ReleaseSavepointMutation {
                    name: name.clone(),
                }))
            }
            StatementFact::PrepareTransaction { .. } => {
                mutations.push(Mutation::Opaque(OpaqueMutation::PrepareTransaction))
            }
            StatementFact::SetTransaction => {
                mutations.push(Mutation::Opaque(OpaqueMutation::SetTransaction))
            }
            StatementFact::SetConstraints => {
                mutations.push(Mutation::Opaque(OpaqueMutation::SetConstraints))
            }
            StatementFact::OpaqueBlock => mutations.push(Mutation::Opaque(OpaqueMutation::DoBlock)),
            StatementFact::Execute => mutations.push(Mutation::Opaque(OpaqueMutation::Execute)),
            StatementFact::Vacuum { relation, is_full } => {
                let table_id = relation
                    .as_ref()
                    .map(|r| Self::resolve_lookup_name(r, state));
                mutations.push(Mutation::Vacuum {
                    table_id,
                    is_full: *is_full,
                })
            }
            StatementFact::CreateFunction(f) => {
                let id = Self::resolve_function_id(&f.name, &f.params, state);
                mutations.push(Mutation::CreateFunction(CreateFunctionMutation {
                    id,
                    or_replace: f.or_replace,
                    params: f.params.clone(),
                    return_type: f.return_type.clone(),
                    options: f.options.clone(),
                }));
            }
            StatementFact::AlterFunction(f) => {
                let base_id = Self::resolve_lookup_name(&f.name, state);
                let sig = f.params.join(",");
                let id = Self::resolve_function_id_by_sig(&base_id, &sig);
                mutations.push(Mutation::AlterFunction(AlterFunctionMutation {
                    id,
                    action: f.action.clone(),
                }));
            }
            StatementFact::DropFunction(f) => {
                let mut signatures = Vec::new();
                for sig in &f.signatures {
                    let mut normalized_sig = sig.clone();
                    normalized_sig.params = normalized_sig
                        .params
                        .into_iter()
                        .map(|p| Self::normalize_function_arg_type(&p))
                        .collect();
                    signatures.push(normalized_sig);
                }
                mutations.push(Mutation::DropFunction(DropFunctionMutation {
                    signatures,
                    if_exists: f.if_exists,
                    cascade: f.cascade,
                }));
            }
            StatementFact::CreateProcedure(p) => {
                let id = Self::resolve_function_id(&p.name, &p.params, state);
                mutations.push(Mutation::CreateProcedure(CreateProcedureMutation {
                    id,
                    or_replace: p.or_replace,
                    params: p.params.clone(),
                    options: p.options.clone(),
                }));
            }
            StatementFact::AlterProcedure(p) => {
                let base_id = Self::resolve_lookup_name(&p.name, state);
                let sig = p
                    .params
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let id = Self::resolve_function_id_by_sig(&base_id, &sig);
                mutations.push(Mutation::AlterProcedure(AlterProcedureMutation {
                    id,
                    action: p.action.clone(),
                }));
            }
            StatementFact::DropProcedure(p) => {
                let signatures = p
                    .signatures
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
                    .collect();
                mutations.push(Mutation::DropProcedure(DropProcedureMutation {
                    signatures,
                    if_exists: p.if_exists,
                    cascade: p.cascade,
                }));
            }
            StatementFact::CreateAggregate(a) => {
                let id = Self::resolve_function_id(&a.name, &a.params, state);
                mutations.push(Mutation::CreateAggregate(CreateAggregateMutation {
                    id,
                    or_replace: a.or_replace,
                    params: a.params.clone(),
                }));
            }
            StatementFact::AlterAggregate(a) => {
                let base_id = Self::resolve_lookup_name(&a.name, state);
                let signature = a
                    .params
                    .iter()
                    .map(|param| Self::normalize_function_arg_type(param))
                    .collect::<Vec<_>>()
                    .join(",");
                let id = Self::resolve_function_id_by_sig(&base_id, &signature);
                mutations.push(Mutation::AlterAggregate(AlterAggregateMutation {
                    id,
                    action: a.action.clone(),
                }));
            }
            StatementFact::DropAggregate(a) => {
                let signatures = a
                    .signatures
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
                    .collect();
                mutations.push(Mutation::DropAggregate(DropAggregateMutation {
                    signatures,
                    if_exists: a.if_exists,
                    cascade: a.cascade,
                }));
            }
            StatementFact::CreatePublication(p) => {
                mutations.push(Mutation::CreatePublication(CreatePublicationMutation {
                    name: p.name.clone(),
                    scope: Self::resolve_publication_scope(&p.scope, state),
                    params: p.params.clone(),
                }));
            }
            StatementFact::AlterPublication(p) => {
                mutations.push(Mutation::AlterPublication(AlterPublicationMutation {
                    name: p.name.clone(),
                    action: Self::resolve_alter_publication_action(&p.action, state),
                }));
            }
            StatementFact::DropPublication(p) => {
                mutations.push(Mutation::DropPublication(DropPublicationMutation {
                    names: p.names.clone(),
                    if_exists: p.if_exists,
                    cascade: p.cascade,
                }));
            }
            StatementFact::CreateSubscription(s) => {
                mutations.push(Mutation::CreateSubscription(CreateSubscriptionMutation {
                    name: s.name.clone(),
                    connection: s.connection.clone(),
                    publications: s.publications.clone(),
                    params: s.params.clone(),
                }));
            }
            StatementFact::AlterSubscription(s) => {
                mutations.push(Mutation::AlterSubscription(AlterSubscriptionMutation {
                    name: s.name.clone(),
                    action: s.action.clone(),
                }));
            }
            StatementFact::DropSubscription(s) => {
                mutations.push(Mutation::DropSubscription(DropSubscriptionMutation {
                    name: s.name.clone(),
                    if_exists: s.if_exists,
                }));
            }
            StatementFact::CreateRole(r) => {
                mutations.push(Mutation::CreateRole(CreateRoleMutation {
                    name: r.name.clone(),
                    inherits: r.inherits,
                    can_login: r.can_login,
                }));
            }
            StatementFact::AlterRole(r) => {
                mutations.push(Mutation::AlterRole(AlterRoleMutation {
                    name: r.name.clone(),
                    inherits: r.inherits,
                }));
            }
            StatementFact::DropRole(r) => {
                mutations.push(Mutation::DropRole(DropRoleMutation {
                    names: r.names.clone(),
                    if_exists: r.if_exists,
                }));
            }
            StatementFact::Grant(g) => {
                mutations.push(Mutation::Grant(GrantMutation {
                    privileges: g.privileges.clone(),
                    target: Self::resolve_grant_target(&g.target, state),
                    grantees: g.grantees.clone(),
                    with_grant_option: g.with_grant_option,
                    granted_by: g.granted_by.clone(),
                }));
            }
            StatementFact::Revoke(r) => {
                mutations.push(Mutation::Revoke(RevokeMutation {
                    grant_option_only: r.grant_option_only,
                    privileges: r.privileges.clone(),
                    target: Self::resolve_grant_target(&r.target, state),
                    revokees: r.revokees.clone(),
                    granted_by: r.granted_by.clone(),
                    cascade: r.cascade,
                }));
            }
            StatementFact::CreateDatabase(d) => {
                mutations.push(Mutation::CreateDatabase(CreateDatabaseMutation {
                    name: d.name.clone(),
                    options: d.options.clone(),
                }));
            }
            StatementFact::AlterDatabase(d) => {
                let id = Self::resolve_lookup_name(&d.name, state);
                mutations.push(Mutation::AlterDatabase(AlterDatabaseMutation {
                    id,
                    action: d.action.clone(),
                }));
            }
            StatementFact::DropDatabase(d) => {
                let id = Self::resolve_lookup_name(&d.name, state);
                mutations.push(Mutation::DropDatabase(DropDatabaseMutation {
                    id,
                    if_exists: d.if_exists,
                }));
            }
            StatementFact::SetRole {
                role,
                local,
                is_session_auth,
            } => {
                mutations.push(Mutation::SwitchRole {
                    role: role.clone(),
                    local: *local,
                    is_session_auth: *is_session_auth,
                });
            }
        }
        mutations
    }
}
