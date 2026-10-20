use super::*;

impl AstVisitor {
    pub(super) fn extract_attribute_list(
        list: Option<ast::AttributeList>,
    ) -> Vec<crate::_internal::analysis::facts::AttributeFact> {
        list.map(|list| {
            list.attribute_options()
                .map(|option| crate::_internal::analysis::facts::AttributeFact {
                    name: option
                        .name()
                        .map(|name| {
                            Self::resolve_identifier_token(name.syntax().text().to_string().trim())
                        })
                        .unwrap_or_default(),
                    namespace: Self::attribute_namespace(&option),
                    value: Some(
                        option
                            .attribute_value()
                            .map(|value| {
                                value
                                    .literal()
                                    .and_then(|literal| Self::resolve_string_literal(&literal))
                                    .unwrap_or_else(|| {
                                        value.syntax().text().to_string().trim().to_string()
                                    })
                            })
                            .unwrap_or_else(|| "true".to_string()),
                    ),
                })
                .collect()
        })
        .unwrap_or_default()
    }

    pub(super) fn extract_publication_object(
        object: ast::PublicationObject,
    ) -> Option<crate::_internal::analysis::facts::PublicationObjectFact> {
        match object {
            ast::PublicationObject::PublicationObjectTable(object) => {
                let path = object.table_name_ref()?.path_ref()?;
                Some(
                    crate::_internal::analysis::facts::PublicationObjectFact::Table {
                        name: Self::path_ref_to_qualified_name(&path)?,
                        // PostgreSQL always records published tables as ONLY rows
                        // in pg_publication_rel; the `*` (include partitions)
                        // form is only a difference in the number of rows, so
                        // normalization treats every published table as ONLY.
                        only: true,
                        include_partitions: object.star_token().is_some(),
                        columns: object.column_ref_list().map(|columns| {
                            columns
                                .column_name_refs()
                                .map(|name| Self::resolve_ast_identifier(&name))
                                .collect()
                        }),
                        row_filter: object.where_condition_clause().and_then(|where_clause| {
                            where_clause
                                .expr()
                                .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
                                .map(
                                    crate::_internal::analysis::facts::PublicationRowFilter::Parsed,
                                )
                        }),
                    },
                )
            }
            ast::PublicationObject::PublicationObjectTablesInSchema(object) => {
                object.schema_ref().map(|schema_ref| {
                    crate::_internal::analysis::facts::PublicationObjectFact::SchemaTables {
                        schema: Self::resolve_ast_identifier(&schema_ref),
                        row_filter: object.where_condition_clause().and_then(|where_clause| {
                            where_clause
                                .expr()
                                .map(crate::_internal::analysis::expr_visitor::ExprVisitor::convert)
                                .map(
                                    crate::_internal::analysis::facts::PublicationRowFilter::Parsed,
                                )
                        }),
                    }
                })
            }
            ast::PublicationObject::PublicationObjectCurrentSchema(_) => Some(
                crate::_internal::analysis::facts::PublicationObjectFact::CurrentSchemaShorthand,
            ),
        }
    }

    pub(super) fn extract_create_publication(
        node: &squawk_syntax::ast::CreatePublication,
    ) -> Option<StatementFact> {
        let name = node
            .publication()
            .map(|publication| Self::resolve_ast_identifier(&publication))
            .unwrap_or_default();
        let scope = match node.publication_for_clause() {
            Some(ast::PublicationForClause::ForAllPublicationObjects(all_objects)) => {
                crate::_internal::analysis::facts::PublicationScope::AllTables {
                    except: all_objects
                        .except_table_clause()
                        .map(|clause| {
                            clause
                                .except_table_names()
                                .filter_map(|name| name.table_relation_name())
                                .filter_map(|name| name.table_name_ref())
                                .filter_map(|name| name.path_ref())
                                .filter_map(|path| Self::path_ref_to_qualified_name(&path))
                                .map(|name| name.name.resolve())
                                .collect()
                        })
                        .unwrap_or_default(),
                }
            }
            Some(ast::PublicationForClause::ForPublicationObjects(objects)) => {
                crate::_internal::analysis::facts::PublicationScope::Explicit(
                    objects
                        .publication_objects()
                        .filter_map(Self::extract_publication_object)
                        .collect(),
                )
            }
            None => crate::_internal::analysis::facts::PublicationScope::Explicit(Vec::new()),
        };
        let params =
            Self::extract_attribute_list(node.with_params().and_then(|with| with.attribute_list()));

        Some(StatementFact::CreatePublication(
            crate::_internal::analysis::facts::CreatePublicationFact {
                name,
                scope,
                params,
            },
        ))
    }

    pub(super) fn extract_alter_publication(
        node: &squawk_syntax::ast::AlterPublication,
    ) -> Option<StatementFact> {
        let name = Self::resolve_ast_identifier(&node.publication_ref()?);
        let action = match node.action()? {
            ast::AlterPublicationAction::AddPublicationObjects(action) => {
                crate::_internal::analysis::facts::AlterPublicationActionFact::AddObjects(
                    action
                        .publication_objects()
                        .filter_map(Self::extract_publication_object)
                        .collect(),
                )
            }
            ast::AlterPublicationAction::DropPublicationObjects(action) => {
                crate::_internal::analysis::facts::AlterPublicationActionFact::DropObjects(
                    action
                        .publication_objects()
                        .filter_map(Self::extract_publication_object)
                        .collect(),
                )
            }
            ast::AlterPublicationAction::SetPublicationObjects(action) => {
                crate::_internal::analysis::facts::AlterPublicationActionFact::SetObjects(
                    crate::_internal::analysis::facts::PublicationScope::Explicit(
                        action
                            .publication_objects()
                            .filter_map(Self::extract_publication_object)
                            .collect(),
                    ),
                )
            }
            ast::AlterPublicationAction::SetAllPublicationObjectList(action) => {
                let except = action
                    .except_table_clause()
                    .map(|clause| {
                        clause
                            .except_table_names()
                            .filter_map(|name| name.table_relation_name())
                            .filter_map(|name| name.table_name_ref())
                            .filter_map(|name| name.path_ref())
                            .filter_map(|path| Self::path_ref_to_qualified_name(&path))
                            .map(|name| name.name.resolve())
                            .collect()
                    })
                    .unwrap_or_default();
                crate::_internal::analysis::facts::AlterPublicationActionFact::SetObjects(
                    crate::_internal::analysis::facts::PublicationScope::AllTables { except },
                )
            }
            ast::AlterPublicationAction::SetOptions(action) => {
                crate::_internal::analysis::facts::AlterPublicationActionFact::SetOptions(
                    Self::extract_attribute_list(action.attribute_list()),
                )
            }
            ast::AlterPublicationAction::OwnerTo(action) => {
                crate::_internal::analysis::facts::AlterPublicationActionFact::OwnerChange(
                    Self::extract_role(&action.role_ref()?),
                )
            }
            ast::AlterPublicationAction::PublicationRenameTo(action) => {
                crate::_internal::analysis::facts::AlterPublicationActionFact::Rename {
                    to: Self::resolve_ast_identifier(&action.publication()?),
                }
            }
        };
        Some(StatementFact::AlterPublication(
            crate::_internal::analysis::facts::AlterPublicationFact { name, action },
        ))
    }

    pub(super) fn extract_drop_publication(
        node: &squawk_syntax::ast::DropPublication,
    ) -> Option<StatementFact> {
        let names = node
            .publication_refs()
            .map(|publication| Self::resolve_ast_identifier(&publication))
            .collect();
        Some(StatementFact::DropPublication(
            crate::_internal::analysis::facts::DropPublicationFact {
                names,
                if_exists: node.if_exists().is_some(),
                cascade: Self::is_cascade(node.drop_behavior()),
            },
        ))
    }

    pub(super) fn extract_create_subscription(
        node: &squawk_syntax::ast::CreateSubscription,
    ) -> Option<StatementFact> {
        let name = node
            .subscription()
            .map(|subscription| Self::resolve_ast_identifier(&subscription));
        let connection = match node.source() {
            Some(ast::SubscriptionSource::ServerClause(server)) => {
                crate::_internal::analysis::facts::ConnectionTarget::Server(
                    server
                        .server_ref()
                        .map(|server| Self::resolve_ast_identifier(&server)),
                )
            }
            Some(ast::SubscriptionSource::ConnectionClause(connection)) => {
                crate::_internal::analysis::facts::ConnectionTarget::Literal(
                    connection
                        .literal()
                        .and_then(|literal| Self::resolve_string_literal(&literal)),
                )
            }
            None => crate::_internal::analysis::facts::ConnectionTarget::Literal(None),
        };
        let publications = node
            .publication_refs()
            .map(|publication| Self::resolve_ast_identifier(&publication))
            .collect();
        let params = node
            .with_params()
            .map(|with| Self::extract_attribute_list(with.attribute_list()));

        Some(StatementFact::CreateSubscription(
            crate::_internal::analysis::facts::CreateSubscriptionFact {
                name,
                connection,
                publications,
                params,
            },
        ))
    }

    pub(super) fn extract_alter_subscription(
        node: &squawk_syntax::ast::AlterSubscription,
    ) -> Option<StatementFact> {
        let name = Self::resolve_ast_identifier(&node.subscription_ref()?);
        let action = match node.action()? {
            ast::AlterSubscriptionAction::ConnectionClause(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::SetConnection(
                    crate::_internal::analysis::facts::ConnectionTarget::Literal(
                        action
                            .literal()
                            .and_then(|literal| Self::resolve_string_literal(&literal)),
                    ),
                )
            }
            ast::AlterSubscriptionAction::ServerClause(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::SetServer(
                    action
                        .server_ref()
                        .map(|server| Self::resolve_ast_identifier(&server)),
                )
            }
            ast::AlterSubscriptionAction::SetPublication(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::Publications {
                    mode: crate::_internal::analysis::facts::SubscriptionPublicationMode::Set,
                    publications: action
                        .publication_refs()
                        .map(|publication| Self::resolve_ast_identifier(&publication))
                        .collect(),
                    params: Self::extract_attribute_list(
                        action
                            .with_params()
                            .and_then(|params| params.attribute_list()),
                    ),
                }
            }
            ast::AlterSubscriptionAction::AddPublication(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::Publications {
                    mode: crate::_internal::analysis::facts::SubscriptionPublicationMode::Add,
                    publications: action
                        .publication_refs()
                        .map(|publication| Self::resolve_ast_identifier(&publication))
                        .collect(),
                    params: Self::extract_attribute_list(
                        action
                            .with_params()
                            .and_then(|params| params.attribute_list()),
                    ),
                }
            }
            ast::AlterSubscriptionAction::DropSubscriptionPublication(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::Publications {
                    mode: crate::_internal::analysis::facts::SubscriptionPublicationMode::Drop,
                    publications: action
                        .publication_refs()
                        .map(|publication| Self::resolve_ast_identifier(&publication))
                        .collect(),
                    params: Self::extract_attribute_list(
                        action
                            .with_params()
                            .and_then(|params| params.attribute_list()),
                    ),
                }
            }
            ast::AlterSubscriptionAction::RefreshPublication(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::RefreshPublication(
                    Self::extract_attribute_list(
                        action
                            .with_params()
                            .and_then(|params| params.attribute_list()),
                    ),
                )
            }
            ast::AlterSubscriptionAction::EnableSubscription(_) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::SetEnabled(true)
            }
            ast::AlterSubscriptionAction::DisableSubscription(_) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::SetEnabled(false)
            }
            ast::AlterSubscriptionAction::SetOptions(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::SetOptions(
                    Self::extract_attribute_list(action.attribute_list()),
                )
            }
            ast::AlterSubscriptionAction::SkipSubscription(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::Skip(
                    Self::extract_attribute_list(action.attribute_list()),
                )
            }
            ast::AlterSubscriptionAction::OwnerTo(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::OwnerChange(
                    Self::extract_role(&action.role_ref()?),
                )
            }
            ast::AlterSubscriptionAction::SubscriptionRenameTo(action) => {
                crate::_internal::analysis::facts::AlterSubscriptionActionFact::Rename {
                    to: Self::resolve_ast_identifier(&action.subscription()?),
                }
            }
        };
        Some(StatementFact::AlterSubscription(
            crate::_internal::analysis::facts::AlterSubscriptionFact { name, action },
        ))
    }

    pub(super) fn extract_drop_subscription(
        node: &squawk_syntax::ast::DropSubscription,
    ) -> Option<StatementFact> {
        let name = Self::resolve_ast_identifier(&node.subscription_ref()?);
        Some(StatementFact::DropSubscription(
            crate::_internal::analysis::facts::DropSubscriptionFact {
                name,
                if_exists: node.if_exists().is_some(),
            },
        ))
    }
}
