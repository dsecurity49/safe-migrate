use super::*;

impl AstVisitor {
    pub(super) fn extract_role(
        role_ref: &squawk_syntax::ast::RoleRef,
    ) -> crate::_internal::analysis::facts::RoleFact {
        let via_legacy_group_syntax = role_ref.group_token().is_some();
        if let Some(value) = role_ref.role_ref_value() {
            match value {
                squawk_syntax::ast::RoleRefValue::RoleNameRef(r) => {
                    if let Some(token) = r.ident_token() {
                        return crate::_internal::analysis::facts::RoleFact::Named {
                            name: Self::resolve_identifier_token(token.text()),
                            via_legacy_group_syntax,
                        };
                    }
                }
                squawk_syntax::ast::RoleRefValue::RoleRefCurrentRole(_) => {
                    return crate::_internal::analysis::facts::RoleFact::CurrentRole;
                }
                squawk_syntax::ast::RoleRefValue::RoleRefCurrentUser(_) => {
                    return crate::_internal::analysis::facts::RoleFact::CurrentUser;
                }
                squawk_syntax::ast::RoleRefValue::RoleRefSessionUser(_) => {
                    return crate::_internal::analysis::facts::RoleFact::SessionUser;
                }
            }
        }
        if let Some(token) = role_ref
            .syntax()
            .descendants_with_tokens()
            .filter_map(|x| x.into_token())
            .find(|t| t.kind() != SyntaxKind::WHITESPACE && t.kind() != SyntaxKind::COMMENT)
        {
            let name = Self::resolve_identifier_token(token.text());
            return crate::_internal::analysis::facts::RoleFact::Named {
                name,
                via_legacy_group_syntax,
            };
        }
        crate::_internal::analysis::facts::RoleFact::Unknown
    }

    pub(super) fn extract_role_node(
        role: &squawk_syntax::ast::Role,
    ) -> crate::_internal::analysis::facts::RoleFact {
        let is_group = role.syntax().parent().is_some_and(|p| {
            use squawk_syntax::SyntaxKind::*;
            matches!(p.kind(), CREATE_GROUP | DROP_GROUP | ALTER_GROUP)
        });
        if let Some(token) = role.ident_token() {
            return crate::_internal::analysis::facts::RoleFact::Named {
                name: Self::resolve_identifier_token(token.text()),
                via_legacy_group_syntax: is_group,
            };
        }
        if role.current_role_token().is_some() {
            return crate::_internal::analysis::facts::RoleFact::CurrentRole;
        }
        if role.current_user_token().is_some() {
            return crate::_internal::analysis::facts::RoleFact::CurrentUser;
        }
        if role.session_user_token().is_some() {
            return crate::_internal::analysis::facts::RoleFact::SessionUser;
        }
        crate::_internal::analysis::facts::RoleFact::Unknown
    }

    pub(super) fn extract_create_role(
        node: &squawk_syntax::ast::CreateRole,
    ) -> Option<StatementFact> {
        let name = Self::resolve_identifier_token(node.role()?.ident_token()?.text());
        let (inherits, can_login, unsupported) =
            Self::extract_create_role_options(node.role_option_list(), false);
        if unsupported {
            return None;
        }
        Some(StatementFact::CreateRole(
            crate::_internal::analysis::facts::CreateRoleFact {
                name,
                inherits,
                can_login,
            },
        ))
    }

    pub(super) fn extract_create_user(
        node: &squawk_syntax::ast::CreateUser,
    ) -> Option<StatementFact> {
        let name = Self::resolve_identifier_token(node.role()?.ident_token()?.text());
        let (inherits, can_login, unsupported) =
            Self::extract_create_role_options(node.role_option_list(), true);
        if unsupported {
            return None;
        }
        Some(StatementFact::CreateRole(
            crate::_internal::analysis::facts::CreateRoleFact {
                name,
                inherits,
                can_login,
            },
        ))
    }

    pub(super) fn extract_create_role_options(
        options: Option<squawk_syntax::ast::RoleOptionList>,
        default_login: bool,
    ) -> (bool, bool, bool) {
        let mut inherits = true;
        let mut can_login = default_login;
        let mut unsupported = false;
        if let Some(options) = options {
            for option in options.role_options() {
                match option {
                    ast::RoleOption::RoleOptionInherit(_) => inherits = true,
                    ast::RoleOption::RoleOptionGeneric(option) => {
                        let option = option.syntax().text().to_string().to_ascii_lowercase();
                        match option.trim() {
                            "inherit" => inherits = true,
                            "noinherit" => inherits = false,
                            "login" => can_login = true,
                            "nologin" => can_login = false,
                            _ => unsupported = true,
                        }
                    }
                    _ => unsupported = true,
                }
            }
        }
        (inherits, can_login, unsupported)
    }

    pub(super) fn extract_alter_role(
        node: &squawk_syntax::ast::AlterRole,
    ) -> Option<StatementFact> {
        let name = Self::extract_role(&node.role_ref()?);
        let inherits = node.action().and_then(|a| match a {
            ast::AlterRoleAction::RoleOptionList(ol) => {
                let mut found = None;
                for o in ol.role_options() {
                    match o {
                        ast::RoleOption::RoleOptionInherit(_) => found = Some(true),
                        ast::RoleOption::RoleOptionGeneric(option) => {
                            match option
                                .ident_token()
                                .map(|token| token.text().to_ascii_lowercase())
                                .as_deref()
                            {
                                Some("inherit") => found = Some(true),
                                Some("noinherit") => found = Some(false),
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
                found
            }
            _ => None,
        });
        Some(StatementFact::AlterRole(
            crate::_internal::analysis::facts::AlterRoleFact { name, inherits },
        ))
    }

    pub(super) fn extract_drop_role(node: &squawk_syntax::ast::DropRole) -> Option<StatementFact> {
        let names = node
            .role_refs()
            .map(|r| {
                let ident = if let Some(squawk_syntax::ast::RoleRefValue::RoleNameRef(name)) =
                    r.role_ref_value()
                {
                    name.ident_token()
                } else {
                    None
                };
                ident
                    .map(|t| Self::resolve_identifier_token(t.text()))
                    .unwrap_or_default()
            })
            .collect();
        Some(StatementFact::DropRole(
            crate::_internal::analysis::facts::DropRoleFact {
                names,
                if_exists: node.if_exists().is_some(),
            },
        ))
    }

    pub(super) fn extract_privilege_from_revoke_command(
        cmd: &RevokeCommand,
    ) -> crate::_internal::analysis::facts::PrivilegeFact {
        if cmd.select_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Select
        } else if cmd.insert_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Insert
        } else if cmd.update_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Update
        } else if cmd.delete_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Delete
        } else if cmd.truncate_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Truncate
        } else if cmd.references_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::References
        } else if cmd.trigger_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Trigger
        } else if cmd.execute_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Execute
        } else if cmd.create_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Create
        } else if cmd.temp_token().is_some() || cmd.temporary_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::Temporary
        } else if cmd.alter_token().is_some() && cmd.system_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::AlterSystem
        } else if cmd.all_token().is_some() {
            crate::_internal::analysis::facts::PrivilegeFact::All
        } else if let Some(ident) = cmd.ident_token() {
            let raw = ident.text().to_string();
            let name = Self::resolve_identifier_token(&raw);
            if !Self::identifier_from_token(&raw).quoted && name == "maintain" {
                crate::_internal::analysis::facts::PrivilegeFact::Maintain
            } else {
                crate::_internal::analysis::facts::PrivilegeFact::RoleMembership(name)
            }
        } else if let Some(role_ref) = cmd.role_ref() {
            if let Some(squawk_syntax::ast::RoleRefValue::RoleNameRef(r)) =
                role_ref.role_ref_value()
            {
                // Squawk 2.65.0 models each DML/session privilege that is also
                // an SQL keyword (INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER,
                // EXECUTE, TEMP, TEMPORARY) as a keyword token inside the
                // grammar's generic name slot rather than as a direct child of
                // the command, so match on the token kind first. PostgreSQL 17
                // MAINTAIN and legacy role-membership names arrive as IDENT.
                match r
                    .syntax()
                    .descendants_with_tokens()
                    .find_map(|t| t.into_token())
                {
                    Some(tok) if !tok.kind().is_trivia() => {
                        use SyntaxKind::*;
                        match tok.kind() {
                            INSERT_KW => {
                                return crate::_internal::analysis::facts::PrivilegeFact::Insert;
                            }
                            UPDATE_KW => {
                                return crate::_internal::analysis::facts::PrivilegeFact::Update;
                            }
                            DELETE_KW => {
                                return crate::_internal::analysis::facts::PrivilegeFact::Delete;
                            }
                            TRUNCATE_KW => {
                                return crate::_internal::analysis::facts::PrivilegeFact::Truncate;
                            }
                            TRIGGER_KW => {
                                return crate::_internal::analysis::facts::PrivilegeFact::Trigger;
                            }
                            EXECUTE_KW => {
                                return crate::_internal::analysis::facts::PrivilegeFact::Execute;
                            }
                            TEMP_KW | TEMPORARY_KW => {
                                return crate::_internal::analysis::facts::PrivilegeFact::Temporary;
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
                if let Some(ident) = r.ident_token() {
                    let raw = ident.text().to_string();
                    let name = Self::resolve_identifier_token(&raw);
                    if !Self::identifier_from_token(&raw).quoted {
                        match name.as_str() {
                            "insert" => {
                                return crate::_internal::analysis::facts::PrivilegeFact::Insert;
                            }
                            "update" => {
                                return crate::_internal::analysis::facts::PrivilegeFact::Update;
                            }
                            "delete" => {
                                return crate::_internal::analysis::facts::PrivilegeFact::Delete;
                            }
                            "maintain" => {
                                return crate::_internal::analysis::facts::PrivilegeFact::Maintain;
                            }
                            _ => {}
                        }
                    }
                    crate::_internal::analysis::facts::PrivilegeFact::RoleMembership(name)
                } else {
                    crate::_internal::analysis::facts::PrivilegeFact::Unknown
                }
            } else {
                let text = role_ref.syntax().text().to_string();
                match text.to_lowercase().as_str() {
                    "insert" => crate::_internal::analysis::facts::PrivilegeFact::Insert,
                    "update" => crate::_internal::analysis::facts::PrivilegeFact::Update,
                    "delete" => crate::_internal::analysis::facts::PrivilegeFact::Delete,
                    "maintain" => crate::_internal::analysis::facts::PrivilegeFact::Maintain,
                    _ => crate::_internal::analysis::facts::PrivilegeFact::Unknown,
                }
            }
        } else if let Some(ident) = cmd.syntax().descendants().find_map(PathSegment::cast) {
            crate::_internal::analysis::facts::PrivilegeFact::Named(ident.text().to_string())
        } else {
            crate::_internal::analysis::facts::PrivilegeFact::Unknown
        }
    }

    pub(super) fn extract_grant_target_from_privilege_objects(
        po: Option<squawk_syntax::ast::PrivilegeObjects>,
        _syntax: &squawk_syntax::SyntaxNode,
    ) -> Option<crate::_internal::analysis::facts::GrantTarget> {
        use squawk_syntax::ast::PrivilegeObjects;
        let names: Vec<_> = match po? {
            PrivilegeObjects::PrivilegeTable(obj) => obj
                .relation_name_refs()
                .filter_map(|rn| {
                    rn.path_ref()
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                })
                .collect(),
            PrivilegeObjects::PrivilegeDefault(obj) => obj
                .relation_name_refs()
                .filter_map(|rn| {
                    rn.path_ref()
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                })
                .collect(),
            PrivilegeObjects::PrivilegeAllTablesInSchema(pais) => {
                let schemas: Vec<_> = pais
                    .schema_refs()
                    .filter_map(|sr| {
                        sr.ident_token()
                            .map(|t| Self::resolve_identifier_token(t.text()))
                    })
                    .collect();
                return if schemas.is_empty() {
                    None
                } else {
                    Some(crate::_internal::analysis::facts::GrantTarget::AllTablesInSchema(schemas))
                };
            }
            _ => return None,
        };
        if names.is_empty() {
            None
        } else {
            Some(crate::_internal::analysis::facts::GrantTarget::Tables(
                names,
            ))
        }
    }

    pub(super) fn extract_role_membership_option(
        option: &squawk_syntax::ast::GrantRoleOption,
    ) -> Option<crate::_internal::analysis::facts::RoleMembershipOptionFact> {
        let name = option
            .grant_role_option_name()?
            .syntax()
            .text()
            .to_string()
            .trim()
            .to_ascii_lowercase();
        let value = if option.false_token().is_some() {
            false
        } else if option.true_token().is_some() || option.option_token().is_some() {
            true
        } else {
            return None;
        };
        match name.as_str() {
            "admin" => {
                Some(crate::_internal::analysis::facts::RoleMembershipOptionFact::Admin(value))
            }
            "inherit" => {
                Some(crate::_internal::analysis::facts::RoleMembershipOptionFact::Inherit(value))
            }
            "set" => Some(crate::_internal::analysis::facts::RoleMembershipOptionFact::Set(value)),
            _ => None,
        }
    }
}
