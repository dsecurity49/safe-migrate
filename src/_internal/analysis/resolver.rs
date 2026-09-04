use crate::_internal::analysis::facts::StatementFact;
use crate::_internal::analysis::mutations::{Mutation, OpaqueMutation};
use crate::_internal::analysis::state::AnalysisState;
use crate::_internal::ast::identifiers::{ObjectId, QualifiedName};

mod relation;
mod relation_aux;
mod replication;
mod routine;
mod schema;
mod security;
mod sequence;
mod session;
mod types;

pub struct Resolver;

impl Resolver {
    fn resolve_creation_name(name: &QualifiedName, state: &AnalysisState) -> ObjectId {
        let schema = name
            .schema
            .as_ref()
            .map(|i| i.resolve())
            .unwrap_or_else(|| {
                state
                    .search_path()
                    .first()
                    .map(|s| s.as_str())
                    .unwrap_or("public")
                    .to_string()
            });

        ObjectId::new(schema, name.name.resolve())
    }

    fn resolve_in_namespace(
        name: &QualifiedName,
        object_name: String,
        state: &AnalysisState,
        present: impl Fn(&AnalysisState, &ObjectId) -> bool,
    ) -> ObjectId {
        if let Some(schema_ident) = &name.schema {
            return ObjectId::new(schema_ident.resolve(), object_name);
        }

        for schema in state.search_path() {
            let mut candidate = ObjectId::new(schema.clone(), object_name.clone());
            if present(state, &candidate) {
                candidate.inferred_schema = true;
                return candidate;
            }
        }

        let schema = state
            .search_path()
            .first()
            .cloned()
            .unwrap_or_else(|| "public".to_string());
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
        )
    }

    fn resolve_type_lookup_name(name: &QualifiedName, state: &AnalysisState) -> ObjectId {
        Self::resolve_in_namespace(
            name,
            name.name.resolve(),
            state,
            AnalysisState::type_is_present,
        )
    }

    fn resolve_routine_lookup_name(
        name: &QualifiedName,
        params: &[String],
        state: &AnalysisState,
    ) -> ObjectId {
        let signature = params
            .iter()
            .map(|param| Self::normalize_function_arg_type(param))
            .collect::<Vec<_>>()
            .join(",");
        let object_name = format!("{}({signature})", name.name.resolve());
        Self::resolve_in_namespace(name, object_name, state, AnalysisState::routine_is_present)
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

    pub fn resolve(fact: &StatementFact, state: &AnalysisState) -> Vec<Mutation> {
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
            StatementFact::SchemaNeutralNoop => {}
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
                columns,
                foreign_keys,
                table_constraints,
                partition_by,
                partition_of,
                partition_type,
            } => {
                mutations.push(Self::resolve_create_table(
                    name,
                    *if_not_exists,
                    *as_select,
                    persistence,
                    columns,
                    foreign_keys,
                    table_constraints,
                    partition_by,
                    partition_of,
                    partition_type,
                    state,
                ));
            }
            StatementFact::CreateView {
                name,
                or_replace,
                depends_on,
            } => {
                mutations.push(Self::resolve_create_view(
                    name,
                    *or_replace,
                    depends_on,
                    state,
                ));
            }
            StatementFact::AlterView { name, action } => {
                if let Some(mutation) = Self::resolve_alter_view(name, action, state) {
                    mutations.push(mutation);
                }
            }
            StatementFact::CreateMaterializedView { name, depends_on } => {
                mutations.push(Self::resolve_create_materialized_view(
                    name, depends_on, state,
                ));
            }
            StatementFact::AlterMaterializedView { name, new_name } => {
                if let Some(mutation) =
                    Self::resolve_alter_materialized_view(name, new_name.as_ref(), state)
                {
                    mutations.push(mutation);
                }
            }
            StatementFact::RefreshMaterializedView { name, concurrently } => {
                mutations.push(Self::resolve_refresh_materialized_view(
                    name,
                    *concurrently,
                    state,
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
                key_columns,
                included_columns,
                has_expression_keys,
                has_default_sort_order,
                has_default_opclasses,
                has_default_collations,
            } => {
                mutations.push(Self::resolve_create_index(
                    name,
                    relation,
                    *if_not_exists,
                    *concurrently,
                    using_method,
                    *has_predicate,
                    *unique,
                    key_columns,
                    included_columns,
                    *has_expression_keys,
                    *has_default_sort_order,
                    *has_default_opclasses,
                    *has_default_collations,
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
            } => {
                mutations.push(Self::resolve_create_trigger(name, table, function, state));
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
            StatementFact::AlterIndex { name, actions } => {
                mutations.extend(Self::resolve_alter_index(name, actions, state));
            }
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
            } => {
                mutations.push(Self::resolve_create_sequence(
                    name,
                    *if_not_exists,
                    owned_by,
                    state,
                ));
            }
            StatementFact::AlterSequence {
                name,
                if_exists,
                action,
            } => {
                mutations.push(Self::resolve_alter_sequence(
                    name, *if_exists, action, state,
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
            StatementFact::AlterTable { name, actions } => {
                mutations.extend(Self::resolve_alter_table(name, actions, state));
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
                mutations.push(Self::resolve_drop_function(f));
            }
            StatementFact::CreateProcedure(p) => {
                mutations.push(Self::resolve_create_procedure(p, state));
            }
            StatementFact::AlterProcedure(p) => {
                mutations.push(Self::resolve_alter_procedure(p, state));
            }
            StatementFact::DropProcedure(p) => {
                mutations.push(Self::resolve_drop_procedure(p));
            }
            StatementFact::CreateAggregate(a) => {
                mutations.push(Self::resolve_create_aggregate(a, state));
            }
            StatementFact::AlterAggregate(a) => {
                mutations.push(Self::resolve_alter_aggregate(a, state));
            }
            StatementFact::DropAggregate(a) => {
                mutations.push(Self::resolve_drop_aggregate(a));
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
        mutations
    }
}
