use super::*;

impl AstVisitor {
    pub(super) fn extract_set(node: &Set) -> Option<StatementFact> {
        use squawk_syntax::ast::SetTarget;
        let target = node.set_target()?;
        match target {
            SetTarget::SetConfig(sc) => {
                let setting_name = sc
                    .config_parameter_ref()
                    .and_then(|cpr| cpr.path_ref())
                    .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                    .filter(|qn| qn.schema.is_none())?
                    .name
                    .resolve()
                    .to_lowercase();
                let local = Self::is_local(node.set_scope());

                if setting_name == "search_path" {
                    return match sc.config_assignment() {
                        Some(ast::ConfigAssignment::ToConfigValue(assignment))
                            if assignment.default_token().is_some() =>
                        {
                            Some(StatementFact::SetSearchPath {
                                target: SearchPathTarget::Default,
                                local,
                            })
                        }
                        Some(ast::ConfigAssignment::ToConfigValue(assignment)) => {
                            let schemas: Vec<String> = assignment
                                .config_values()
                                .filter_map(|value| match value {
                                    ast::ConfigValue::ConfigValueName(name) => name
                                        .ident_token()
                                        .map(|token| Self::resolve_identifier_token(token.text())),
                                    ast::ConfigValue::Literal(literal) => {
                                        Self::resolve_string_literal(&literal)
                                    }
                                    ast::ConfigValue::PrefixExpr(_) => None,
                                })
                                .collect();
                            (!schemas.is_empty()).then_some(StatementFact::SetSearchPath {
                                target: SearchPathTarget::Schemas(schemas),
                                local,
                            })
                        }
                        Some(ast::ConfigAssignment::FromCurrent(_)) | None => None,
                    };
                }

                if setting_name == "application_name" {
                    return Some(StatementFact::SchemaNeutralNoop);
                }

                let timeout_setting = match setting_name.as_str() {
                    "lock_timeout" => TimeoutSetting::Lock,
                    "statement_timeout" => TimeoutSetting::Statement,
                    _ => return None,
                };
                let value = match sc.config_assignment() {
                    Some(ast::ConfigAssignment::FromCurrent(_)) => TimeoutSettingValue::Current,
                    Some(ast::ConfigAssignment::ToConfigValue(assignment))
                        if assignment.default_token().is_some() =>
                    {
                        TimeoutSettingValue::Default
                    }
                    Some(ast::ConfigAssignment::ToConfigValue(assignment)) => {
                        let values: Vec<String> = assignment
                            .config_values()
                            .filter_map(|value| match value {
                                ast::ConfigValue::ConfigValueName(name) => {
                                    name.ident_token().map(|token| token.text().to_string())
                                }
                                ast::ConfigValue::Literal(literal) => {
                                    Self::resolve_string_literal(&literal)
                                        .or_else(|| Some(literal.syntax().text().to_string()))
                                }
                                ast::ConfigValue::PrefixExpr(expr) => {
                                    Some(expr.syntax().text().to_string())
                                }
                            })
                            .collect();
                        if values.len() != 1 {
                            TimeoutSettingValue::Invalid(sc.syntax().text().to_string())
                        } else {
                            match crate::_internal::analysis::settings::parse_timeout_ms(&values[0])
                            {
                                Ok(milliseconds) => TimeoutSettingValue::Milliseconds(milliseconds),
                                Err(error) => TimeoutSettingValue::Invalid(error),
                            }
                        }
                    }
                    None => TimeoutSettingValue::Invalid(sc.syntax().text().to_string()),
                };
                Some(StatementFact::SetTimeout {
                    setting: timeout_setting,
                    value,
                    local,
                })
            }
            _ => None,
        }
    }

    pub(super) fn extract_reset(node: &ast::Reset) -> Option<StatementFact> {
        use squawk_syntax::ast::ResetTarget;

        let target = match node.reset_target()? {
            ResetTarget::All(_) => ResetSettingTarget::All,
            ResetTarget::ConfigParameterRef(parameter) => {
                let name = parameter
                    .path_ref()
                    .and_then(|path| Self::path_ref_to_qualified_name(&path))
                    .filter(|name| name.schema.is_none())?
                    .name
                    .resolve()
                    .to_lowercase();
                match name.as_str() {
                    "search_path" => ResetSettingTarget::SearchPath,
                    "lock_timeout" => ResetSettingTarget::LockTimeout,
                    "statement_timeout" => ResetSettingTarget::StatementTimeout,
                    "application_name" => return Some(StatementFact::SchemaNeutralNoop),
                    // An unknown GUC may affect DDL behavior (for example
                    // replication or constraint enforcement). Keep it on the
                    // explicit opaque path instead of silently claiming no
                    // state impact.
                    _ => return None,
                }
            }
            ResetTarget::ResetTimeZone(_) | ResetTarget::ResetTransactionIsolation(_) => {
                return Some(StatementFact::SchemaNeutralNoop);
            }
        };
        Some(StatementFact::ResetSettings { target })
    }

    /// Extract `SET [LOCAL] ROLE { rolename | NONE }`.
    pub(super) fn extract_set_role(node: &squawk_syntax::ast::SetRole) -> Option<StatementFact> {
        let local = Self::is_local(node.set_scope());
        let role = match node.set_role_target()? {
            ast::SetRoleTarget::SetRoleNone(_) => None,
            ast::SetRoleTarget::RoleRef(role) => Some(Self::extract_role(&role)),
            ast::SetRoleTarget::Literal(literal) => Self::resolve_string_literal(&literal)
                .filter(|name| !name.is_empty())
                .map(|name| crate::_internal::analysis::facts::RoleFact::Named {
                    name,
                    via_legacy_group_syntax: false,
                }),
        };
        if matches!(
            role,
            Some(
                crate::_internal::analysis::facts::RoleFact::CurrentUser
                    | crate::_internal::analysis::facts::RoleFact::CurrentRole
                    | crate::_internal::analysis::facts::RoleFact::SessionUser
            )
        ) {
            // PostgreSQL's SET ROLE grammar accepts a role name or NONE, not
            // the special role-specification keywords accepted by GRANT and
            // OWNER TO. Squawk currently parses these forms, so leave them
            // unsupported rather than simulating SQL PostgreSQL rejects.
            return None;
        }
        Some(StatementFact::SetRole {
            role,
            local,
            is_session_auth: false,
        })
    }

    /// Extract `SET [LOCAL] SESSION AUTHORIZATION { rolename | DEFAULT }`.
    pub(super) fn extract_set_session_auth(
        node: &squawk_syntax::ast::SetSessionAuth,
    ) -> Option<StatementFact> {
        let local = Self::is_local(node.set_scope());
        let role = match node.set_session_auth_target()? {
            ast::SetSessionAuthTarget::SetSessionAuthDefault(_) => None,
            ast::SetSessionAuthTarget::RoleRef(role) => Some(Self::extract_role(&role)),
            ast::SetSessionAuthTarget::Literal(literal) => Self::resolve_string_literal(&literal)
                .filter(|name| !name.is_empty())
                .map(|name| crate::_internal::analysis::facts::RoleFact::Named {
                    name,
                    via_legacy_group_syntax: false,
                }),
        };
        if matches!(
            role,
            Some(
                crate::_internal::analysis::facts::RoleFact::CurrentUser
                    | crate::_internal::analysis::facts::RoleFact::CurrentRole
                    | crate::_internal::analysis::facts::RoleFact::SessionUser
            )
        ) {
            return None;
        }
        Some(StatementFact::SetRole {
            role,
            local,
            is_session_auth: true,
        })
    }
}
