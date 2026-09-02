use super::Resolver;
use crate::analysis::facts::{
    AlterDatabaseFact, AlterRoleFact, CreateDatabaseFact, CreateRoleFact, DropDatabaseFact,
    DropRoleFact, GrantFact, GrantTarget, RevokeFact, RoleFact,
};
use crate::analysis::mutations::{
    AlterDatabaseMutation, AlterRoleMutation, CreateDatabaseMutation, CreateRoleMutation,
    DropDatabaseMutation, DropRoleMutation, GrantMutation, Mutation, ResolvedGrantTarget,
    RevokeMutation,
};
use crate::analysis::state::AnalysisState;
use crate::ast::identifiers::ObjectId;

impl Resolver {
    fn resolve_grant_target(target: &GrantTarget, state: &AnalysisState) -> ResolvedGrantTarget {
        match target {
            GrantTarget::Tables(names) => ResolvedGrantTarget::Tables(
                names
                    .iter()
                    .map(|name| Self::resolve_relation_lookup_name(name, state))
                    .collect(),
            ),
            GrantTarget::AllTablesInSchema(schemas) => {
                ResolvedGrantTarget::AllTablesInSchema(schemas.clone())
            }
            GrantTarget::Roles(names) => ResolvedGrantTarget::Roles(
                names.iter().map(|name| ObjectId::new("", name)).collect(),
            ),
        }
    }

    pub(super) fn resolve_create_role(fact: &CreateRoleFact) -> Mutation {
        Mutation::CreateRole(CreateRoleMutation {
            name: fact.name.clone(),
            inherits: fact.inherits,
            can_login: fact.can_login,
        })
    }

    pub(super) fn resolve_alter_role(fact: &AlterRoleFact) -> Mutation {
        Mutation::AlterRole(AlterRoleMutation {
            name: fact.name.clone(),
            inherits: fact.inherits,
        })
    }

    pub(super) fn resolve_drop_role(fact: &DropRoleFact) -> Mutation {
        Mutation::DropRole(DropRoleMutation {
            names: fact.names.clone(),
            if_exists: fact.if_exists,
        })
    }

    pub(super) fn resolve_grant(fact: &GrantFact, state: &AnalysisState) -> Mutation {
        Mutation::Grant(GrantMutation {
            privileges: fact.privileges.clone(),
            target: Self::resolve_grant_target(&fact.target, state),
            grantees: fact.grantees.clone(),
            with_grant_option: fact.with_grant_option,
            role_options: fact.role_options.clone(),
            granted_by: fact.granted_by.clone(),
        })
    }

    pub(super) fn resolve_revoke(fact: &RevokeFact, state: &AnalysisState) -> Mutation {
        Mutation::Revoke(RevokeMutation {
            grant_option_only: fact.grant_option_only,
            role_option: fact.role_option.clone(),
            privileges: fact.privileges.clone(),
            target: Self::resolve_grant_target(&fact.target, state),
            revokees: fact.revokees.clone(),
            granted_by: fact.granted_by.clone(),
            cascade: fact.cascade,
        })
    }

    pub(super) fn resolve_create_database(fact: &CreateDatabaseFact) -> Mutation {
        Mutation::CreateDatabase(CreateDatabaseMutation {
            name: fact.name.clone(),
            options: fact.options.clone(),
        })
    }

    pub(super) fn resolve_alter_database(fact: &AlterDatabaseFact) -> Mutation {
        Mutation::AlterDatabase(AlterDatabaseMutation {
            id: ObjectId::new("", fact.name.name.resolve()),
            action: fact.action.clone(),
        })
    }

    pub(super) fn resolve_drop_database(fact: &DropDatabaseFact) -> Mutation {
        Mutation::DropDatabase(DropDatabaseMutation {
            id: ObjectId::new("", fact.name.name.resolve()),
            if_exists: fact.if_exists,
        })
    }

    pub(super) fn resolve_set_role(
        role: &Option<RoleFact>,
        local: bool,
        is_session_auth: bool,
    ) -> Mutation {
        Mutation::SwitchRole {
            role: role.clone(),
            local,
            is_session_auth,
        }
    }
}
