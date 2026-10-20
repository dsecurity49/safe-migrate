use super::*;

impl AnalysisState {
    pub(crate) fn apply(
        &mut self,
        mutation: &Mutation,
        precomputed_cascade: Option<&CascadeResult>,
    ) -> MutationResult {
        if self.local.transaction_aborted
            && !matches!(
                mutation,
                Mutation::CommitTransaction
                    | Mutation::CommitAndChain
                    | Mutation::RollbackTransaction
                    | Mutation::RollbackAndChain
                    | Mutation::RollbackToSavepoint(_)
            )
        {
            return MutationResult::NotExecuted;
        }

        let result = self.apply_inner(mutation, precomputed_cascade);
        if matches!(result, MutationResult::Conflict(_)) && !self.local.transactions.is_empty() {
            self.local.transaction_aborted = true;
        }
        // Keep the derived dependency indexes inside their invariant boundary
        // while the state-delta migration is in progress. This is debug-only
        // and therefore does not add release overhead, but catches a missed
        // invalidation immediately after the transition that caused it.
        debug_assert!(self.local.graph.indexes_are_valid());
        result
    }

    pub(super) fn apply_inner(
        &mut self,
        mutation: &Mutation,
        precomputed_cascade: Option<&CascadeResult>,
    ) -> MutationResult {
        match mutation {
            Mutation::CreateSchema(create_schema) => self.apply_create_schema(create_schema),
            Mutation::AlterSchema(alter_schema) => self.apply_alter_schema(alter_schema),
            Mutation::DropSchema(drop_schema) => self.apply_drop_schema(drop_schema),
            Mutation::DropTable(drop) => self.apply_drop_table(drop, precomputed_cascade),
            Mutation::CreateTable(create) => self.apply_create_table(create),
            Mutation::CreateView(create) => self.apply_create_view(create),
            Mutation::CreateMaterializedView(create) => self.apply_create_materialized_view(create),
            Mutation::RefreshMaterializedView(refresh) => {
                self.apply_refresh_materialized_view(refresh)
            }
            Mutation::AlterViewFamily(alter) => self.apply_alter_view_family(alter),
            Mutation::CreateIndex(create) => self.apply_create_index(create),
            Mutation::CreatePolicy(create_policy) => self.apply_create_policy(create_policy),
            Mutation::DropPolicy(drop_policy) => self.apply_drop_policy(drop_policy),
            Mutation::CreateTrigger(create_trigger) => self.apply_create_trigger(create_trigger),
            Mutation::DropTrigger(drop_trigger) => self.apply_drop_trigger(drop_trigger),
            Mutation::RenameTrigger(rename_trigger) => self.apply_rename_trigger(rename_trigger),
            Mutation::AlterTable(alter) => self.apply_alter_table(alter),
            Mutation::CreateType(create) => self.apply_create_type(create),
            Mutation::RenameType(rename) => self.apply_rename_type(rename),
            Mutation::AlterType(alter) => self.apply_alter_type(alter),
            Mutation::CreateDomain(create) => self.apply_create_domain(create),
            Mutation::AlterDomain(alter) => self.apply_alter_domain(alter),
            Mutation::DropDomain(drop) => self.apply_drop_domain(drop),
            Mutation::DropType(drop) => self.apply_drop_type(drop),
            Mutation::CreateSequence(create) => self.apply_create_sequence(create),
            Mutation::AlterSequence(alter) => self.apply_alter_sequence(alter),
            Mutation::DropSequence(drop) => self.apply_drop_sequence(drop),
            Mutation::Rename(rename) => self.apply_rename_relation(rename),
            Mutation::DropView(drop) => self.apply_drop_view(drop),
            Mutation::DropMaterializedView(drop) => self.apply_drop_materialized_view(drop),
            Mutation::AlterIndex(alter) => self.apply_alter_index(alter),
            Mutation::AlterIndexAllInTablespace(all_in) => {
                self.apply_alter_index_all_in_tablespace(all_in)
            }
            Mutation::DropIndex(drop) => self.apply_drop_index(drop),
            Mutation::LockTable(lock) => self.apply_lock_table(lock),
            Mutation::Truncate(truncate) => self.apply_truncate(truncate),
            Mutation::ChangeRelationOwner { id, new_owner } => {
                self.apply_change_relation_owner(id, new_owner)
            }
            Mutation::SetReloptions {
                id,
                kind,
                attributes,
            } => self.apply_set_reloptions(id, *kind, attributes),
            Mutation::SetColumnDefault {
                id,
                column,
                default,
            } => self.apply_set_column_default(id, column, default.as_ref()),
            Mutation::NoStateChange { .. } => MutationResult::Applied,
            Mutation::ResetReloptions {
                id,
                kind,
                attributes,
            } => self.apply_reset_reloptions(id, *kind, attributes),
            Mutation::SearchPath(search_path) => self.apply_search_path(search_path),
            Mutation::TimeoutSetting(timeout) => self.apply_timeout_setting(timeout),
            Mutation::ResetSettings(target) => self.apply_reset_settings(target),
            Mutation::CheckTimeouts { .. } => self.apply_check_timeouts(),
            Mutation::SwitchRole {
                role,
                local,
                is_session_auth,
            } => self.apply_switch_role(role, *local, *is_session_auth),
            Mutation::BeginTransaction => self.apply_begin_transaction(),
            Mutation::CommitTransaction => self.apply_commit_transaction(false),
            Mutation::CommitAndChain => self.apply_commit_transaction(true),
            Mutation::RollbackTransaction => self.apply_rollback_transaction(false),
            Mutation::RollbackAndChain => self.apply_rollback_transaction(true),
            Mutation::RollbackToSavepoint(rollback) => self.apply_rollback_to_savepoint(rollback),
            Mutation::Savepoint(savepoint) => self.apply_savepoint(savepoint),
            Mutation::ReleaseSavepoint(release) => self.apply_release_savepoint(release),
            Mutation::Opaque(opaque) => self.apply_opaque(opaque),
            Mutation::CreateFunction(function) => self.apply_create_function(function),
            Mutation::AlterFunction(function) => self.apply_alter_function(function),
            Mutation::DropFunction(function) => self.apply_drop_function(function),
            Mutation::CreateProcedure(procedure) => self.apply_create_procedure(procedure),
            Mutation::AlterProcedure(procedure) => self.apply_alter_procedure(procedure),
            Mutation::DropProcedure(procedure) => self.apply_drop_procedure(procedure),
            Mutation::CreateAggregate(aggregate) => self.apply_create_aggregate(aggregate),
            Mutation::AlterAggregate(aggregate) => self.apply_alter_aggregate(aggregate),
            Mutation::DropAggregate(aggregate) => self.apply_drop_aggregate(aggregate),
            Mutation::CreatePublication(publication) => self.apply_create_publication(publication),
            Mutation::AlterPublication(publication) => self.apply_alter_publication(publication),
            Mutation::DropPublication(publication) => self.apply_drop_publication(publication),
            Mutation::CreateSubscription(subscription) => {
                self.apply_create_subscription(subscription)
            }
            Mutation::AlterSubscription(subscription) => {
                self.apply_alter_subscription(subscription)
            }
            Mutation::DropSubscription(subscription) => self.apply_drop_subscription(subscription),
            Mutation::CreateRole(role) => self.apply_create_role(role),
            Mutation::AlterRole(role) => self.apply_alter_role(role),
            Mutation::DropRole(role) => self.apply_drop_role(role),
            Mutation::Grant(grant) => self.apply_grant(grant),
            Mutation::Revoke(revoke) => self.apply_revoke(revoke),
            Mutation::CreateDatabase(create_database) => {
                self.apply_create_database(create_database)
            }
            Mutation::AlterDatabase(alter_database) => self.apply_alter_database(alter_database),
            Mutation::DropDatabase(drop_database) => self.apply_drop_database(drop_database),
            Mutation::Vacuum { table_id, is_full } => self.apply_vacuum(table_id, *is_full),
            Mutation::Reindex {
                target,
                concurrently,
            } => self.apply_reindex(target, *concurrently),
        }
    }
}
