use super::*;

impl AstVisitor {
    pub(super) fn extract_db_option(
        opt: squawk_syntax::ast::DatabaseOption,
    ) -> crate::_internal::analysis::facts::DatabaseOptionFact {
        let value_for = |default: bool, literal: Option<ast::Literal>| {
            if default {
                crate::_internal::analysis::facts::DatabaseOptionValue::Default
            } else {
                crate::_internal::analysis::facts::DatabaseOptionValue::Literal(literal.and_then(
                    |literal| {
                        if literal.is_string() {
                            literal.decoded_value().map(|text| text.into_text())
                        } else {
                            Some(literal.syntax().text().to_string())
                        }
                    },
                ))
            }
        };

        match opt {
            ast::DatabaseOption::DatabaseOptionOwner(opt) => {
                crate::_internal::analysis::facts::DatabaseOptionFact::Owner(value_for(
                    opt.default_token().is_some(),
                    opt.literal(),
                ))
            }
            ast::DatabaseOption::DatabaseOptionTemplate(opt) => {
                crate::_internal::analysis::facts::DatabaseOptionFact::Template(value_for(
                    opt.default_token().is_some(),
                    opt.literal(),
                ))
            }
            ast::DatabaseOption::DatabaseOptionEncoding(opt) => {
                crate::_internal::analysis::facts::DatabaseOptionFact::Encoding(value_for(
                    opt.default_token().is_some(),
                    opt.literal(),
                ))
            }
            ast::DatabaseOption::DatabaseOptionTablespace(opt) => {
                crate::_internal::analysis::facts::DatabaseOptionFact::Tablespace(value_for(
                    opt.default_token().is_some(),
                    opt.literal(),
                ))
            }
            ast::DatabaseOption::DatabaseOptionConnectionLimit(opt) => {
                crate::_internal::analysis::facts::DatabaseOptionFact::ConnectionLimit(value_for(
                    opt.default_token().is_some(),
                    opt.literal(),
                ))
            }
            ast::DatabaseOption::DatabaseOptionGeneric(opt) => {
                let value = value_for(opt.default_token().is_some(), opt.literal());
                opt.ident_token()
                    .map(|ident| {
                        crate::_internal::analysis::facts::DatabaseOptionFact::Named(
                            ident.text().to_string(),
                            value.clone(),
                        )
                    })
                    .unwrap_or(
                        crate::_internal::analysis::facts::DatabaseOptionFact::Unknown(value),
                    )
            }
        }
    }

    pub(super) fn extract_create_database(node: &CreateDatabase) -> Option<StatementFact> {
        let name = node
            .database()
            .and_then(|d| d.ident_token())
            .map(|t| Self::resolve_identifier_token(t.text()))
            .unwrap_or_default();
        let options = node
            .database_option_list()
            .map(|ol| ol.database_options().map(Self::extract_db_option).collect())
            .unwrap_or_default();
        Some(StatementFact::CreateDatabase(
            crate::_internal::analysis::facts::CreateDatabaseFact { name, options },
        ))
    }

    pub(super) fn extract_alter_database(node: &ast::AlterDatabase) -> Option<StatementFact> {
        use squawk_syntax::ast::AlterDatabaseAction;
        let name = node
            .database_ref()
            .and_then(|dr| dr.ident_token())
            .map(|t| Self::identifier_from_token(t.text()))
            .unwrap_or_else(|| Ident::new(String::new(), false));
        let name = QualifiedName::new(None, name);

        let action = match node.action()? {
            AlterDatabaseAction::DatabaseRenameTo(rt) => {
                crate::_internal::analysis::facts::AlterDatabaseAction::Rename {
                    to: rt
                        .database()
                        .and_then(|d| d.ident_token())
                        .map(|t| Self::resolve_identifier_token(t.text()))
                        .unwrap_or_default(),
                }
            }
            AlterDatabaseAction::OwnerTo(ot) => {
                crate::_internal::analysis::facts::AlterDatabaseAction::OwnerChange(
                    Self::extract_role(&ot.role_ref()?),
                )
            }
            AlterDatabaseAction::SetTablespace(st) => {
                crate::_internal::analysis::facts::AlterDatabaseAction::TablespaceChange {
                    new_tablespace: st
                        .tablespace_ref()
                        .and_then(|tr| tr.ident_token())
                        .map(|t| Self::resolve_identifier_token(t.text()))
                        .unwrap_or_default(),
                }
            }
            AlterDatabaseAction::SetConfigParam(scp) => {
                crate::_internal::analysis::facts::AlterDatabaseAction::SetConfigParam {
                    param: scp
                        .config_parameter_ref()
                        .and_then(|cpr| cpr.path_ref())
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                        .map(|qn| qn.name.resolve())
                        .unwrap_or_default(),
                }
            }
            AlterDatabaseAction::ResetConfigParam(rcp) => {
                crate::_internal::analysis::facts::AlterDatabaseAction::ResetConfigParam {
                    param: rcp
                        .config_parameter_ref()
                        .and_then(|cpr| cpr.path_ref())
                        .and_then(|pr| Self::path_ref_to_qualified_name(&pr))
                        .map(|qn| qn.name.resolve()),
                }
            }
            AlterDatabaseAction::RefreshCollationVersion(_) => {
                crate::_internal::analysis::facts::AlterDatabaseAction::RefreshCollationVersion
            }
            AlterDatabaseAction::DatabaseOptionList(ol) => {
                crate::_internal::analysis::facts::AlterDatabaseAction::OptionChanges(
                    ol.database_options().map(Self::extract_db_option).collect(),
                )
            }
        };

        Some(StatementFact::AlterDatabase(
            crate::_internal::analysis::facts::AlterDatabaseFact { name, action },
        ))
    }

    pub(super) fn extract_drop_database(node: &ast::DropDatabase) -> Option<StatementFact> {
        let name = node
            .database_ref()
            .and_then(|dr| dr.ident_token())
            .map(|t| Self::identifier_from_token(t.text()))
            .unwrap_or_else(|| Ident::new(String::new(), false));
        let name = QualifiedName::new(None, name);
        Some(StatementFact::DropDatabase(
            crate::_internal::analysis::facts::DropDatabaseFact {
                name,
                if_exists: node.if_exists().is_some(),
            },
        ))
    }
}
