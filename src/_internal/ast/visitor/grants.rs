use super::*;

impl AstVisitor {
    pub(super) fn extract_grant(node: &Grant) -> Option<StatementFact> {
        let privileges = match node.privileges() {
            Some(ast::Privileges::AllPrivileges(_)) => {
                crate::_internal::analysis::facts::PrivilegeSpec::All
            }
            Some(ast::Privileges::RevokeCommandList(commands)) => {
                crate::_internal::analysis::facts::PrivilegeSpec::List(
                    commands
                        .revoke_commands()
                        .map(|command| Self::extract_privilege_from_revoke_command(&command))
                        .collect(),
                )
            }
            None => crate::_internal::analysis::facts::PrivilegeSpec::List(Vec::new()),
        };

        let target = if let Some(objects) = node
            .on_privilege_objects_clause()
            .and_then(|clause| clause.privilege_objects())
        {
            Self::extract_grant_target_from_privilege_objects(Some(objects), node.syntax())?
        } else {
            let crate::_internal::analysis::facts::PrivilegeSpec::List(items) = &privileges else {
                return None;
            };
            let roles = items
                .iter()
                .map(|item| match item {
                    crate::_internal::analysis::facts::PrivilegeFact::RoleMembership(name) => {
                        Some(name.clone())
                    }
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()?;
            if roles.is_empty() {
                return None;
            }
            crate::_internal::analysis::facts::GrantTarget::Roles(roles)
        };

        let grantees = node
            .role_ref_list()
            .map(|rrl| rrl.role_refs().map(|r| Self::extract_role(&r)).collect())
            .unwrap_or_default();
        let (with_grant_option, role_options) = match node.grant_with_clause() {
            None => (false, Vec::new()),
            Some(clause) if clause.grant_option().is_some() => (true, Vec::new()),
            Some(clause) => {
                let list = clause.grant_role_option_list()?;
                let options = list
                    .grant_role_options()
                    .map(|option| Self::extract_role_membership_option(&option))
                    .collect::<Option<Vec<_>>>()?;
                (false, options)
            }
        };
        let granted_by = node
            .granted_by_clause()
            .and_then(|clause| clause.role_ref())
            .map(|role| Self::extract_role(&role));

        Some(StatementFact::Grant(
            crate::_internal::analysis::facts::GrantFact {
                privileges,
                target,
                grantees,
                with_grant_option,
                role_options,
                granted_by,
            },
        ))
    }

    pub(super) fn extract_revoke(node: &Revoke) -> Option<StatementFact> {
        let (grant_option_only, role_option) = match node.revoke_option_for() {
            None => (false, None),
            Some(ast::RevokeOptionFor::GrantOptionFor(_)) => (true, None),
            Some(ast::RevokeOptionFor::AdminOptionFor(_)) => (
                false,
                Some(crate::_internal::analysis::facts::RoleMembershipOptionFact::Admin(false)),
            ),
            Some(ast::RevokeOptionFor::InheritOptionFor(_)) => (
                false,
                Some(crate::_internal::analysis::facts::RoleMembershipOptionFact::Inherit(false)),
            ),
            Some(ast::RevokeOptionFor::SetOptionFor(_)) => (
                false,
                Some(crate::_internal::analysis::facts::RoleMembershipOptionFact::Set(false)),
            ),
        };

        let privileges = match node.privileges() {
            Some(ast::Privileges::AllPrivileges(_)) => {
                crate::_internal::analysis::facts::PrivilegeSpec::All
            }
            Some(ast::Privileges::RevokeCommandList(commands)) => {
                crate::_internal::analysis::facts::PrivilegeSpec::List(
                    commands
                        .revoke_commands()
                        .map(|command| Self::extract_privilege_from_revoke_command(&command))
                        .collect(),
                )
            }
            None => crate::_internal::analysis::facts::PrivilegeSpec::List(Vec::new()),
        };

        let target = if let Some(objects) = node
            .on_privilege_objects_clause()
            .and_then(|clause| clause.privilege_objects())
        {
            Self::extract_grant_target_from_privilege_objects(Some(objects), node.syntax())?
        } else {
            let ast::Privileges::RevokeCommandList(commands) = node.privileges()? else {
                return None;
            };
            let roles = commands
                .revoke_commands()
                .map(
                    |command| match Self::extract_privilege_from_revoke_command(&command) {
                        crate::_internal::analysis::facts::PrivilegeFact::RoleMembership(name) => {
                            Some(name)
                        }
                        _ => None,
                    },
                )
                .collect::<Option<Vec<_>>>()?;
            if roles.is_empty() {
                return None;
            }
            crate::_internal::analysis::facts::GrantTarget::Roles(roles)
        };

        let revokees = node
            .role_ref_list()
            .map(|rrl| rrl.role_refs().map(|r| Self::extract_role(&r)).collect())
            .unwrap_or_default();
        let granted_by = node
            .granted_by_clause()
            .and_then(|clause| clause.role_ref())
            .map(|role| Self::extract_role(&role));
        let cascade = Self::is_cascade(node.drop_behavior());

        Some(StatementFact::Revoke(
            crate::_internal::analysis::facts::RevokeFact {
                grant_option_only,
                role_option,
                privileges,
                target,
                revokees,
                granted_by,
                cascade,
            },
        ))
    }
}
