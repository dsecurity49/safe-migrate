use crate::_internal::analysis::facts::StatementFact;
use crate::_internal::analysis::mutations::{Mutation, OpaqueMutation};
use crate::_internal::analysis::namespace::{SearchPathEntry, temp_object_id};
use crate::_internal::analysis::state::AnalysisState;
use crate::_internal::ast::identifiers::{ObjectId, QualifiedName};
use crate::_internal::model::builtin_type::BuiltinTypeCatalogue;
use crate::_internal::model::data_type::{ParsedDataType, TypeIdentity};
use crate::_internal::report::violations::ObjectKind;

mod relation;
mod relation_aux;
mod replication;
mod routine;
mod schema;
mod security;
mod sequence;
mod session;
mod types;

pub(crate) struct Resolver;

impl Resolver {
    fn resolve_creation_name(name: &QualifiedName, state: &AnalysisState) -> ObjectId {
        if let Some(schema) = &name.schema {
            return ObjectId::new(schema.resolve(), name.name.resolve());
        }

        // An unqualified creation targets the first already-existing path
        // schema.  An empty or unresolved path leaves no provable target, so
        // the state machine taints or rejects it where the answer matters.
        let schema = state
            .creation_schema()
            .map(str::to_string)
            .or_else(|| {
                state
                    .search_path()
                    .first()
                    .and_then(SearchPathEntry::name)
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let mut id = ObjectId::new(schema, name.name.resolve());
        id.inferred_schema = true;
        id
    }

    /// Creation target for a relation declared `TEMPORARY`, which PostgreSQL
    /// always places in the session schema rather than the path.
    ///
    /// An explicitly named schema is kept so the state machine can reject it,
    /// as PostgreSQL does for a temporary relation in a permanent schema.
    pub(super) fn resolve_temp_creation_name(
        name: &QualifiedName,
        _state: &AnalysisState,
    ) -> ObjectId {
        match &name.schema {
            Some(schema) => ObjectId::new(schema.resolve(), name.name.resolve()),
            None => temp_object_id(&name.name.resolve()),
        }
    }

    fn resolve_in_namespace(
        name: &QualifiedName,
        object_name: String,
        state: &AnalysisState,
        present: impl Fn(&AnalysisState, &ObjectId) -> bool,
        search: impl Fn(&AnalysisState) -> Vec<SearchPathEntry>,
    ) -> ObjectId {
        if let Some(schema_ident) = &name.schema {
            return ObjectId::new(schema_ident.resolve(), object_name);
        }

        for entry in search(state) {
            let Some(schema) = entry.searched_schema() else {
                continue;
            };
            let mut candidate = ObjectId::new(schema, object_name.clone());
            if present(state, &candidate) {
                candidate.inferred_schema = true;
                return candidate;
            }
        }

        // An empty path searches nothing, so no schema may be inferred. The
        // inference follows the path the lookup actually searched.
        let path = search(state);
        let schema = path
            .first()
            .and_then(SearchPathEntry::name)
            .unwrap_or_default();
        let mut id = ObjectId::new(schema, object_name);
        id.inferred_schema = true;
        id
    }

    fn resolve_relation_lookup_name(name: &QualifiedName, state: &AnalysisState) -> ObjectId {
        Self::resolve_in_namespace(
            name,
            name.name.resolve(),
            state,
            AnalysisState::relation_namespace_object_is_present,
            AnalysisState::relation_search_path,
        )
    }

    /// A `schema-drift` diagnostic for an object the baseline provably lacks.
    pub(super) fn unresolved_reference(
        kind: ObjectKind,
        id: &ObjectId,
        state: &AnalysisState,
    ) -> Option<Mutation> {
        // A miss only proves absence with a synced baseline; an object created
        // earlier in the migration is present locally.
        let absent = !state.relation_namespace_object_is_present(id)
            && state.relation_absence_is_authoritative(id);
        absent.then(|| {
            Mutation::Opaque(OpaqueMutation::UnresolvedReference {
                object_kind: kind,
                object_name: id.to_string(),
            })
        })
    }

    fn resolve_type_lookup_name(name: &QualifiedName, state: &AnalysisState) -> ObjectId {
        if name.schema.is_none() {
            // An array type is never independently addressable: it resolves
            // through its element, whose schema decides the identity. The
            // namespace walk cannot see that, because no overlay carries an
            // array name.
            let reference = name.name.resolve();
            if reference.ends_with("[]")
                && let Some(array) = state.resolve_type_reference(&reference)
            {
                return array;
            }
        }
        Self::resolve_in_namespace(
            name,
            name.name.resolve(),
            state,
            AnalysisState::type_is_present,
            AnalysisState::relation_search_path,
        )
    }

    /// A routine reference that carries no argument types: the namespace is
    /// the routine one, and the presence test matches any overload.
    pub(super) fn resolve_routine_namespace_name(
        name: &QualifiedName,
        state: &AnalysisState,
    ) -> ObjectId {
        Self::resolve_in_namespace(
            name,
            name.name.resolve(),
            state,
            AnalysisState::routine_named_is_present,
            AnalysisState::routine_search_path,
        )
    }

    fn resolve_routine_lookup_name(
        name: &QualifiedName,
        params: &[String],
        state: &AnalysisState,
    ) -> ObjectId {
        let signature = params
            .iter()
            .map(|param| Self::routine_arg_identity(param, state))
            .collect::<Vec<_>>()
            .join(",");
        let object_name = format!("{}({signature})", name.name.resolve());
        Self::resolve_in_namespace(
            name,
            object_name,
            state,
            AnalysisState::routine_is_present,
            AnalysisState::routine_search_path,
        )
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
        params: &[crate::_internal::analysis::facts::ParamFact],
        state: &AnalysisState,
    ) -> ObjectId {
        let base_id = Self::resolve_creation_name(name, state);
        let sig = params
            .iter()
            .filter(|p| {
                !matches!(
                    &p.mode,
                    crate::_internal::analysis::facts::ParamModeFact::Out
                )
            })
            .map(|p| p.ty.clone())
            .collect::<Vec<_>>()
            .join(",");
        Self::resolve_function_id_by_sig(&base_id, &sig, state)
    }

    fn resolve_function_id_by_sig(
        base_id: &ObjectId,
        sig: &str,
        state: &AnalysisState,
    ) -> ObjectId {
        let normalized_sig = sig
            .split(',')
            .map(|raw| Self::routine_arg_identity(raw, state))
            .collect::<Vec<_>>()
            .join(",");

        let mut id = ObjectId::new(
            base_id.schema.clone(),
            format!("{}({})", base_id.name, normalized_sig),
        );
        id.inferred_schema = base_id.inferred_schema;
        id
    }

    /// PostgreSQL identifies a routine by its argument type OIDs, so two
    /// spellings of one type are one signature. Resolve against state where
    /// possible and fall back to the canonical spelling otherwise.
    fn routine_arg_identity(raw: &str, state: &AnalysisState) -> String {
        if let Some(id) = state.resolve_type_reference(raw) {
            return id.to_string();
        }
        let identity = Self::normalize_function_arg_type(raw, state.builtin_types());
        // An unresolved custom type renders to nothing, so two distinct ones
        // would collapse into one signature. Keep its written name instead.
        if identity.is_unknown() {
            return ParsedDataType::parse(raw, state.builtin_types()).to_string();
        }
        identity.render()
    }

    pub(crate) fn normalize_function_arg_type(
        raw: &str,
        catalogue: &BuiltinTypeCatalogue,
    ) -> TypeIdentity {
        TypeIdentity::from_syntax(&ParsedDataType::parse(raw, catalogue))
    }

    pub(crate) fn resolve(fact: &StatementFact, state: &AnalysisState) -> Vec<Mutation> {
        let mut mutations = Vec::new();
        match fact {
            StatementFact::CreateSchema {
                name,
                if_not_exists,
                authorization,
            } => {
                mutations.push(Self::resolve_create_schema(
                    name,
                    *if_not_exists,
                    authorization,
                ));
            }
            StatementFact::SchemaNeutralNoop => mutations.push(Mutation::NoStateChange {
                reason: "metadata outside the modeled schema state",
            }),
            StatementFact::Reindex {
                target_kind,
                target_name,
                concurrently,
            } => mutations.push(Self::resolve_reindex(
                target_kind,
                target_name.as_ref(),
                *concurrently,
                state,
            )),
            StatementFact::AlterSchema { name, action } => {
                mutations.push(Self::resolve_alter_schema(name, action));
            }
            StatementFact::DropSchema {
                names,
                if_exists,
                cascade,
            } => {
                mutations.push(Self::resolve_drop_schema(names, *if_exists, *cascade));
            }
            StatementFact::CreateTable {
                name,
                if_not_exists,
                as_select,
                persistence,
                on_commit,
                columns,
                foreign_keys,
                table_constraints,
                partition_by,
                partition_keys,
                partition_strategy,
                partition_of,
                partition_bound,
                inherits,
                like_sources,
                of_type,
                select_source,
                select_outputs,
                select_projection_complete,
            } => {
                mutations.push(Self::resolve_create_table(
                    name,
                    *if_not_exists,
                    *as_select,
                    persistence,
                    *on_commit,
                    columns,
                    foreign_keys,
                    table_constraints,
                    partition_by,
                    partition_keys,
                    partition_strategy,
                    partition_of,
                    partition_bound,
                    inherits,
                    like_sources,
                    of_type,
                    select_source,
                    select_outputs,
                    *select_projection_complete,
                    state,
                ));
            }
            StatementFact::CreateView {
                name,
                or_replace,
                depends_on,
                column_list,
                select_outputs,
                select_projection_complete,
                select_source,
                routines,
                cast_types,
            } => {
                mutations.push(Self::resolve_create_view(
                    name,
                    *or_replace,
                    depends_on,
                    column_list,
                    select_outputs,
                    *select_projection_complete,
                    select_source.as_ref(),
                    routines,
                    cast_types,
                    state,
                ));
            }
            StatementFact::AlterView {
                name,
                action,
                if_exists,
            } => {
                mutations.push(Self::resolve_alter_view(name, action, *if_exists, state));
            }
            StatementFact::CreateMaterializedView {
                name,
                depends_on,
                if_not_exists,
                with_no_data,
                column_list,
                access_method,
                tablespace,
                options,
                select_outputs,
                select_projection_complete,
                select_source,
                routines,
                cast_types,
            } => {
                mutations.push(Self::resolve_create_materialized_view(
                    name,
                    depends_on,
                    *if_not_exists,
                    *with_no_data,
                    column_list,
                    access_method,
                    tablespace,
                    options,
                    select_outputs,
                    *select_projection_complete,
                    select_source.as_ref(),
                    routines,
                    cast_types,
                    state,
                ));
            }
            StatementFact::AlterMaterializedView {
                name,
                actions,
                if_exists,
            } => {
                mutations.push(Self::resolve_alter_materialized_view(
                    name, actions, *if_exists, state,
                ));
            }
            StatementFact::RefreshMaterializedView {
                name,
                concurrently,
                with_no_data,
            } => {
                mutations.push(Self::resolve_refresh_materialized_view(
                    name,
                    *concurrently,
                    *with_no_data,
                    state,
                ));
            }
            StatementFact::CreateIndex {
                name,
                relation,
                if_not_exists,
                concurrently,
                only,
                using_method,
                predicate,
                unique,
                nulls_not_distinct,
                key_columns,
                key_expressions,
                key_orders,
                key_opclasses,
                key_collations,
                included_columns,
            } => {
                mutations.push(Self::resolve_create_index(
                    name,
                    relation,
                    *if_not_exists,
                    *concurrently,
                    *only,
                    using_method,
                    predicate,
                    *unique,
                    *nulls_not_distinct,
                    key_columns,
                    key_expressions,
                    key_orders,
                    key_opclasses,
                    key_collations,
                    included_columns,
                    state,
                ));
            }
            StatementFact::CreatePolicy {
                name,
                table,
                permissive,
                command,
                semantics_complete,
            } => {
                mutations.push(Self::resolve_create_policy(
                    name,
                    table,
                    *permissive,
                    command,
                    *semantics_complete,
                    state,
                ));
            }
            StatementFact::DropPolicy {
                name,
                table,
                if_exists,
            } => {
                mutations.push(Self::resolve_drop_policy(name, table, *if_exists, state));
            }
            StatementFact::CreateTrigger {
                name,
                table,
                function,
                row_level,
            } => {
                mutations.push(Self::resolve_create_trigger(
                    name, table, function, *row_level, state,
                ));
            }
            StatementFact::DropTrigger {
                name,
                table,
                if_exists,
            } => {
                mutations.push(Self::resolve_drop_trigger(name, table, *if_exists, state));
            }
            StatementFact::AlterTrigger {
                name,
                table,
                new_name,
            } => mutations.push(Self::resolve_alter_trigger(name, table, new_name, state)),
            StatementFact::AlterIndex {
                name,
                if_exists,
                actions,
            } => {
                mutations.push(Self::resolve_alter_index(name, *if_exists, actions, state));
            }
            StatementFact::AlterIndexAllInTablespace {
                source_tablespace,
                target_tablespace,
            } => mutations.push(Mutation::AlterIndexAllInTablespace(
                crate::_internal::analysis::mutations::AlterIndexAllInTablespaceMutation {
                    source_tablespace: source_tablespace.resolve(),
                    target_tablespace: target_tablespace.resolve(),
                },
            )),
            StatementFact::CreateType(create_type) => {
                mutations.push(Self::resolve_create_type(create_type, state));
            }
            StatementFact::AlterType(alter_type) => {
                mutations.extend(Self::resolve_alter_type(alter_type, state));
            }
            StatementFact::CreateDomain { name, base_type } => {
                mutations.push(Self::resolve_create_domain(name, base_type, state));
            }
            StatementFact::AlterDomain { name, action } => {
                mutations.push(Self::resolve_alter_domain(name, action, state));
            }
            StatementFact::DropDomain {
                names,
                if_exists,
                cascade,
            } => {
                mutations.push(Self::resolve_drop_domain(
                    names, *if_exists, *cascade, state,
                ));
            }
            StatementFact::DropType {
                names,
                if_exists,
                cascade,
            } => {
                mutations.push(Self::resolve_drop_type(names, *if_exists, *cascade, state));
            }
            StatementFact::CreateSequence {
                name,
                if_not_exists,
                owned_by,
                persistence,
                options,
            } => {
                mutations.push(Self::resolve_create_sequence(
                    name,
                    *if_not_exists,
                    owned_by,
                    persistence,
                    options,
                    state,
                ));
            }
            StatementFact::AlterSequence {
                name,
                if_exists,
                options,
                action,
            } => {
                mutations.push(Self::resolve_alter_sequence(
                    name,
                    *if_exists,
                    options,
                    action.as_ref(),
                    state,
                ));
            }
            StatementFact::DropSequence {
                names,
                if_exists,
                cascade,
            } => {
                mutations.push(Self::resolve_drop_sequence(
                    names, *if_exists, *cascade, state,
                ));
            }
            StatementFact::AlterTable {
                name,
                only,
                actions,
            } => {
                mutations.extend(Self::resolve_alter_table(name, *only, actions, state));
            }
            StatementFact::DropTable {
                names,
                if_exists,
                cascade,
            } => {
                mutations.push(Self::resolve_drop_table(names, *if_exists, *cascade, state));
            }
            StatementFact::DropView {
                names,
                if_exists,
                cascade,
            } => {
                mutations.push(Self::resolve_drop_view(names, *if_exists, *cascade, state));
            }
            StatementFact::DropMaterializedView {
                names,
                if_exists,
                cascade,
            } => {
                mutations.push(Self::resolve_drop_materialized_view(
                    names, *if_exists, *cascade, state,
                ));
            }
            StatementFact::DropIndex {
                names,
                if_exists,
                concurrently,
                cascade,
            } => {
                mutations.push(Self::resolve_drop_indexes(
                    names,
                    *if_exists,
                    *concurrently,
                    *cascade,
                    state,
                ));
            }
            StatementFact::Lock {
                targets,
                mode,
                nowait,
            } => mutations.push(Self::resolve_lock(targets, *mode, *nowait, state)),
            StatementFact::Truncate {
                targets,
                cascade,
                restart_identity,
            } => mutations.push(Self::resolve_truncate(
                targets,
                *cascade,
                *restart_identity,
                state,
            )),
            StatementFact::SetSearchPath { target, local } => {
                mutations.push(Self::resolve_search_path(target, *local))
            }
            StatementFact::SetTimeout {
                setting,
                value,
                local,
            } => mutations.push(Self::resolve_timeout(*setting, value, *local)),
            StatementFact::ResetSettings { target } => {
                mutations.push(Mutation::ResetSettings(*target))
            }
            StatementFact::BeginTransaction => mutations.push(Mutation::BeginTransaction),
            StatementFact::CommitTransaction => mutations.push(Mutation::CommitTransaction),
            StatementFact::CommitAndChain => mutations.push(Mutation::CommitAndChain),
            StatementFact::RollbackTransaction => mutations.push(Mutation::RollbackTransaction),
            StatementFact::RollbackAndChain => mutations.push(Mutation::RollbackAndChain),
            StatementFact::RollbackToSavepoint { name } => {
                mutations.push(Self::resolve_rollback_to_savepoint(name))
            }
            StatementFact::Savepoint { name } => mutations.push(Self::resolve_savepoint(name)),
            StatementFact::ReleaseSavepoint { name } => {
                mutations.push(Self::resolve_release_savepoint(name))
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
                mutations.push(Self::resolve_vacuum(relation.as_ref(), *is_full, state))
            }
            StatementFact::CreateFunction(f) => {
                mutations.push(Self::resolve_create_function(f, state));
            }
            StatementFact::AlterFunction(f) => {
                mutations.push(Self::resolve_alter_function(f, state));
            }
            StatementFact::DropFunction(f) => {
                mutations.push(Self::resolve_drop_function(f, state));
            }
            StatementFact::CreateProcedure(p) => {
                mutations.push(Self::resolve_create_procedure(p, state));
            }
            StatementFact::AlterProcedure(p) => {
                mutations.push(Self::resolve_alter_procedure(p, state));
            }
            StatementFact::DropProcedure(p) => {
                mutations.push(Self::resolve_drop_procedure(p, state));
            }
            StatementFact::CreateAggregate(a) => {
                mutations.push(Self::resolve_create_aggregate(a, state));
            }
            StatementFact::AlterAggregate(a) => {
                mutations.push(Self::resolve_alter_aggregate(a, state));
            }
            StatementFact::DropAggregate(a) => {
                mutations.push(Self::resolve_drop_aggregate(a, state));
            }
            StatementFact::CreatePublication(p) => {
                mutations.push(Self::resolve_create_publication(p, state));
            }
            StatementFact::AlterPublication(p) => {
                mutations.push(Self::resolve_alter_publication(p, state));
            }
            StatementFact::DropPublication(p) => {
                mutations.push(Self::resolve_drop_publication(p));
            }
            StatementFact::CreateSubscription(s) => {
                mutations.push(Self::resolve_create_subscription(s));
            }
            StatementFact::AlterSubscription(s) => {
                mutations.push(Self::resolve_alter_subscription(s));
            }
            StatementFact::DropSubscription(s) => {
                mutations.push(Self::resolve_drop_subscription(s));
            }
            StatementFact::CreateRole(r) => {
                mutations.push(Self::resolve_create_role(r));
            }
            StatementFact::AlterRole(r) => {
                mutations.push(Self::resolve_alter_role(r));
            }
            StatementFact::DropRole(r) => {
                mutations.push(Self::resolve_drop_role(r));
            }
            StatementFact::Grant(g) => {
                mutations.push(Self::resolve_grant(g, state));
            }
            StatementFact::Revoke(r) => {
                mutations.push(Self::resolve_revoke(r, state));
            }
            StatementFact::CreateDatabase(d) => {
                mutations.push(Self::resolve_create_database(d));
            }
            StatementFact::AlterDatabase(d) => {
                mutations.push(Self::resolve_alter_database(d));
            }
            StatementFact::DropDatabase(d) => {
                mutations.push(Self::resolve_drop_database(d));
            }
            StatementFact::SetRole {
                role,
                local,
                is_session_auth,
            } => {
                mutations.push(Self::resolve_set_role(role, *local, *is_session_auth));
            }
        }
        debug_assert!(
            !mutations.is_empty(),
            "a recognized statement must produce at least one mutation; \
             a statement that changes nothing modeled needs NoStateChange"
        );
        mutations
    }
}
