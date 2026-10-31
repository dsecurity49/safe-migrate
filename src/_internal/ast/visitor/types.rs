use super::*;

impl AstVisitor {
    pub(super) fn extract_create_domain(node: &CreateDomain) -> Option<StatementFact> {
        let path = node.domain()?.path()?;
        let base_type = node
            .ty()
            .map(|t| t.syntax().text().to_string())
            .unwrap_or_else(|| "<domain>".to_string());
        let mut collation = None;
        let mut default = None;
        let mut constraints = Vec::new();
        for qualifier in node.domain_qualifiers() {
            match qualifier {
                ast::DomainQualifier::Collate(collate) => {
                    if collation.is_some() {
                        return None;
                    }
                    collation = Some(Self::index_item_written_name(Some(collate), |collate| {
                        collate.collation_ref()?.path_ref()
                    })?);
                }
                ast::DomainQualifier::Constraint(constraint) => match constraint {
                    ast::Constraint::CheckConstraint(check) => {
                        constraints.push(
                            crate::_internal::analysis::facts::DomainConstraintFact::Check(
                                Self::domain_check_fact(&check)?,
                            ),
                        );
                    }
                    ast::Constraint::DefaultConstraint(default_constraint) => {
                        if default.is_some() {
                            return None;
                        }
                        default = Some(Self::domain_default_fact(default_constraint.expr()?));
                    }
                    ast::Constraint::NotNullConstraint(not_null_constraint) => {
                        constraints.push(
                            crate::_internal::analysis::facts::DomainConstraintFact::NotNull {
                                name: Self::domain_constraint_name(
                                    not_null_constraint.constraint_name_clause(),
                                ),
                            },
                        );
                    }
                    ast::Constraint::NullConstraint(_) => {
                        constraints
                            .push(crate::_internal::analysis::facts::DomainConstraintFact::Null);
                    }
                    _ => return None,
                },
            }
        }
        Some(StatementFact::CreateDomain(
            crate::_internal::analysis::facts::CreateDomainFact {
                name: Self::path_to_qualified_name(&path)?,
                base_type,
                collation,
                default,
                constraints,
            },
        ))
    }

    fn domain_constraint_name(clause: Option<ast::ConstraintNameClause>) -> Option<String> {
        clause
            .and_then(|clause| clause.constraint_name())
            .and_then(|name| Self::constraint_name_text(&name))
    }

    fn constraint_name_text(name: &ast::ConstraintName) -> Option<String> {
        name.ident_token()
            .or_else(|| {
                name.syntax()
                    .descendants_with_tokens()
                    .filter_map(|element| element.into_token())
                    .find(|token| token.kind() != squawk_syntax::SyntaxKind::WHITESPACE)
            })
            .map(|token| Self::resolve_identifier_token(token.text()))
    }

    fn constraint_name_ref_text(name: &ast::ConstraintNameRef) -> Option<String> {
        name.path_ref()?
            .syntax()
            .descendants_with_tokens()
            .filter_map(|element| element.into_token())
            .find(|token| token.kind() != squawk_syntax::SyntaxKind::WHITESPACE)
            .map(|token| Self::resolve_identifier_token(token.text()))
    }

    fn domain_check_fact(
        check: &ast::CheckConstraint,
    ) -> Option<crate::_internal::analysis::facts::DomainCheckFact> {
        let expr = check.expr()?;
        let expression_text = expr.syntax().text().to_string();
        let not_valid = check
            .constraint_options()
            .any(|option| matches!(option, ast::ConstraintOption::NotValid(_)));
        Some(crate::_internal::analysis::facts::DomainCheckFact {
            name: Self::domain_constraint_name(check.constraint_name_clause()),
            expression: crate::_internal::analysis::expr_visitor::ExprVisitor::convert(expr),
            definition: expression_text.clone(),
            expression_text,
            not_valid,
        })
    }

    fn domain_default_fact(
        expr: ast::Expr,
    ) -> crate::_internal::analysis::facts::DomainDefaultFact {
        let text = expr.syntax().text().to_string();
        let expression = crate::_internal::analysis::expr_visitor::ExprVisitor::convert(expr);
        let is_null = Self::domain_expression_is_null(&expression);
        crate::_internal::analysis::facts::DomainDefaultFact {
            expression,
            text,
            is_null,
        }
    }

    fn domain_expression_is_null(expression: &ExprIr) -> bool {
        match expression {
            ExprIr::Literal(value) => value.trim().eq_ignore_ascii_case("null"),
            ExprIr::Cast { expr, .. } | ExprIr::UnaryOp { expr, .. } => {
                Self::domain_expression_is_null(expr)
            }
            _ => false,
        }
    }

    pub(super) fn extract_alter_domain(node: &AlterDomain) -> Option<StatementFact> {
        let path = node.domain_ref()?.path_ref()?;
        let action = match node.action()? {
            squawk_syntax::ast::AlterDomainAction::AddConstraint(add) => {
                let constraint = match add.constraint()? {
                    ast::Constraint::CheckConstraint(check) => {
                        crate::_internal::analysis::facts::DomainConstraintFact::Check(
                            Self::domain_check_fact(&check)?,
                        )
                    }
                    ast::Constraint::NotNullConstraint(not_null) => {
                        crate::_internal::analysis::facts::DomainConstraintFact::NotNull {
                            name: Self::domain_constraint_name(not_null.constraint_name_clause()),
                        }
                    }
                    _ => return None,
                };
                crate::_internal::analysis::facts::AlterDomainActionFact::AddConstraint(constraint)
            }
            squawk_syntax::ast::AlterDomainAction::DomainRenameTo(rename) => {
                let path = rename.domain()?.path()?;
                let name = Self::path_to_qualified_name(&path)?;
                crate::_internal::analysis::facts::AlterDomainActionFact::RenameTo {
                    new_name: name.name,
                }
            }
            squawk_syntax::ast::AlterDomainAction::DropConstraint(drop) => {
                let name = Self::constraint_name_ref_text(&drop.constraint_name_ref()?)?;
                crate::_internal::analysis::facts::AlterDomainActionFact::DropConstraint {
                    name,
                    if_exists: drop.if_exists().is_some(),
                    cascade: Self::is_cascade(drop.drop_behavior()),
                }
            }
            squawk_syntax::ast::AlterDomainAction::DropDefault(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::DropDefault
            }
            squawk_syntax::ast::AlterDomainAction::DropNotNull(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::DropNotNull
            }
            squawk_syntax::ast::AlterDomainAction::OwnerTo(owner) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::OwnerChange(
                    Self::extract_role(&owner.role_ref()?),
                )
            }
            squawk_syntax::ast::AlterDomainAction::RenameConstraint(rename) => {
                let old = Self::constraint_name_ref_text(&rename.constraint_name_ref()?)?;
                let new = Self::constraint_name_text(&rename.constraint_name()?)?;
                crate::_internal::analysis::facts::AlterDomainActionFact::RenameConstraint {
                    old_name: old,
                    new_name: new,
                }
            }
            squawk_syntax::ast::AlterDomainAction::SetDefault(set) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::SetDefault(
                    Self::domain_default_fact(set.expr()?),
                )
            }
            squawk_syntax::ast::AlterDomainAction::SetNotNull(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::SetNotNull
            }
            squawk_syntax::ast::AlterDomainAction::SetSchema(set) => {
                let schema = set.schema_ref()?.ident_token()?;
                crate::_internal::analysis::facts::AlterDomainActionFact::SetSchema {
                    new_schema: Self::resolve_identifier_token(schema.text()),
                }
            }
            squawk_syntax::ast::AlterDomainAction::ValidateConstraint(validate) => {
                let name = Self::constraint_name_ref_text(&validate.constraint_name_ref()?)?;
                crate::_internal::analysis::facts::AlterDomainActionFact::ValidateConstraint {
                    name,
                }
            }
        };
        Some(StatementFact::AlterDomain {
            name: Self::path_ref_to_qualified_name(&path)?,
            action: Some(action),
        })
    }

    pub(super) fn extract_drop_type(node: &DropType) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node
            .type_name_refs()
            .filter_map(|p| p.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .collect();

        Some(StatementFact::DropType {
            names,
            if_exists: node.if_exists().is_some(),
            cascade: Self::is_cascade(node.drop_behavior()),
        })
    }

    pub(super) fn extract_drop_domain(node: &DropDomain) -> Option<StatementFact> {
        let names: Vec<QualifiedName> = node
            .domain_refs()
            .filter_map(|p| p.path_ref())
            .filter_map(|p| Self::path_ref_to_qualified_name(&p))
            .collect();

        Some(StatementFact::DropDomain {
            names,
            if_exists: node.if_exists().is_some(),
            cascade: Self::is_cascade(node.drop_behavior()),
        })
    }

    pub(super) fn extract_create_type(node: &CreateType) -> Option<StatementFact> {
        let path = node.type_name()?.path()?;
        let name = Self::path_to_qualified_name(&path)?;

        let kind = match node.kind() {
            None => TypeCreationKind::Base {
                options: crate::_internal::model::types::BaseTypeOptions::default(),
            },
            Some(ast::CreateTypeKind::EnumType(enum_type)) => TypeCreationKind::Enum {
                variants: enum_type
                    .variant_list()?
                    .variants()
                    .map(|variant| {
                        variant
                            .literal()
                            .and_then(|literal| Self::resolve_string_literal(&literal))
                    })
                    .collect::<Option<Vec<_>>>()?,
            },
            Some(ast::CreateTypeKind::CompositeType(composite)) => TypeCreationKind::Composite {
                fields: composite
                    .composite_field_list()?
                    .composite_field_defs()
                    .map(|field| {
                        let collation = Self::index_item_written_name(field.collate(), |collate| {
                            collate.collation_ref()?.path_ref()
                        })
                        .map(|written| match written.schema {
                            Some(schema) => format!("{schema}.{}", written.name),
                            None => written.name,
                        });
                        let name = field
                            .name()
                            .map(|n| {
                                Self::resolve_identifier_token(n.syntax().text().to_string().trim())
                            })
                            .unwrap_or_default();
                        Some(crate::_internal::analysis::facts::CompositeFieldFact {
                            name,
                            data_type: field.ty()?.syntax().text().to_string(),
                            collation,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?,
            },
            // A range type is defined by its subtype, optional multirange name,
            // collation, opclass, canonical, and subtype_diff.
            Some(ast::CreateTypeKind::RangeType(range)) => {
                let attrs = Self::extract_attribute_list(range.attribute_list());
                let multirange_type_name = attrs
                    .iter()
                    .find(|attribute| attribute.name.eq_ignore_ascii_case("multirange_type_name"))
                    .and_then(|attribute| attribute.value.as_deref())
                    .map(|val| {
                        if let Some((schema, name)) = val.split_once('.') {
                            QualifiedName::new(
                                Some(Self::identifier_from_name(schema.trim(), false)),
                                Self::identifier_from_name(name.trim(), false),
                            )
                        } else {
                            QualifiedName::new(None, Self::identifier_from_name(val.trim(), false))
                        }
                    });
                TypeCreationKind::Range {
                    subtype: Self::type_attribute(attrs.clone(), "subtype"),
                    multirange_type_name,
                    collation: Self::type_attribute(attrs.clone(), "collation"),
                    opclass: Self::type_attribute(attrs.clone(), "subtype_opclass"),
                    canonical: Self::type_attribute(attrs.clone(), "canonical"),
                    subtype_diff: Self::type_attribute(attrs, "subtype_diff"),
                }
            }
            Some(ast::CreateTypeKind::BaseType(base)) => {
                let attrs = Self::extract_attribute_list(base.attribute_list());
                TypeCreationKind::Base {
                    options: Self::extract_base_type_options(&attrs),
                }
            }
        };

        Some(StatementFact::CreateType(CreateTypeFact { name, kind }))
    }

    pub(super) fn extract_base_type_options(
        attributes: &[crate::_internal::analysis::facts::AttributeFact],
    ) -> crate::_internal::model::types::BaseTypeOptions {
        let attr = |name: &str| {
            attributes
                .iter()
                .find(|a| a.name.eq_ignore_ascii_case(name))
                .and_then(|a| a.value.clone())
        };
        let attr_bool = |name: &str| {
            attributes
                .iter()
                .find(|a| a.name.eq_ignore_ascii_case(name))
                .map(|a| {
                    a.value
                        .as_deref()
                        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
                        .unwrap_or(true)
                })
        };
        let internallength = attr("internallength").map(|len_str| {
            if len_str.eq_ignore_ascii_case("variable") {
                crate::_internal::model::types::BaseTypeLength::Variable
            } else if let Ok(fixed) = len_str.parse::<i16>() {
                crate::_internal::model::types::BaseTypeLength::Fixed(fixed)
            } else {
                crate::_internal::model::types::BaseTypeLength::Variable
            }
        });
        crate::_internal::model::types::BaseTypeOptions {
            input: attr("input"),
            output: attr("output"),
            receive: attr("receive"),
            send: attr("send"),
            typmod_in: attr("typmod_in"),
            typmod_out: attr("typmod_out"),
            analyze: attr("analyze"),
            subscript: attr("subscript"),
            internallength,
            passed_by_value: attr_bool("passedbyvalue"),
            alignment: attr("alignment"),
            storage: attr("storage"),
            like: attr("like"),
            category: attr("category"),
            preferred: attr_bool("preferred"),
            default: attr("default"),
            element: attr("element"),
            delimiter: attr("delimiter"),
            collatable: attr_bool("collatable"),
        }
    }

    /// The named type an attribute list declares, if it names one.
    pub(super) fn type_attribute(
        attributes: Vec<crate::_internal::analysis::facts::AttributeFact>,
        name: &str,
    ) -> Option<String> {
        attributes
            .into_iter()
            .find(|attribute| attribute.name.eq_ignore_ascii_case(name))
            .and_then(|attribute| attribute.value)
    }

    pub(super) fn extract_alter_type(node: &AlterType) -> Option<StatementFact> {
        let path = node.type_name_ref()?.path_ref()?;
        let name = Self::path_ref_to_qualified_name(&path)?;
        let mut actions = Vec::new();

        match node.action()? {
            ast::AlterTypeAction::TypeRenameTo(rename_type) => {
                let new_name = rename_type.type_name()?.path()?.segment()?;
                actions.push(AlterTypeActionFact::RenameTo {
                    new_name: Self::identifier_from_name(new_name.text(), new_name.is_quoted()),
                });
            }
            ast::AlterTypeAction::SetSchema(set_schema) => {
                let new_schema = set_schema.schema_ref()?.ident_token()?;
                actions.push(AlterTypeActionFact::SetSchema {
                    new_schema: Self::resolve_identifier_token(new_schema.text()),
                });
            }
            ast::AlterTypeAction::AddValue(add_value) => {
                let new_value = add_value
                    .literal()
                    .as_ref()
                    .and_then(Self::resolve_string_literal)?;
                let neighbor = add_value.value_position().and_then(|position| {
                    match position {
                        ast::ValuePosition::BeforeValue(before) => before.literal(),
                        ast::ValuePosition::AfterValue(after) => after.literal(),
                    }
                    .as_ref()
                    .and_then(Self::resolve_string_literal)
                });
                let before = matches!(
                    add_value.value_position(),
                    Some(ast::ValuePosition::BeforeValue(_))
                );
                actions.push(AlterTypeActionFact::AddValue {
                    new_value,
                    neighbor,
                    before,
                });
            }
            ast::AlterTypeAction::RenameValue(rename_value) => {
                let literals = rename_value
                    .syntax()
                    .descendants()
                    .filter_map(ast::Literal::cast)
                    .map(|literal| Self::resolve_string_literal(&literal))
                    .collect::<Option<Vec<_>>>()?;
                actions.push(AlterTypeActionFact::RenameValue {
                    old_value: literals.first()?.clone(),
                    new_value: literals.get(1)?.clone(),
                });
            }
            ast::AlterTypeAction::OwnerTo(owner_to) => {
                let role = owner_to.role_ref()?;
                actions.push(AlterTypeActionFact::OwnerTo {
                    new_owner: Self::extract_role(&role),
                });
            }
            ast::AlterTypeAction::RenameAttribute(rename_attr) => {
                let old_field = rename_attr
                    .composite_field_ref()?
                    .syntax()
                    .text()
                    .to_string();
                let new_field = rename_attr.composite_field()?.syntax().text().to_string();
                actions.push(AlterTypeActionFact::RenameAttribute {
                    old_name: Self::identifier_from_name(old_field.trim(), false),
                    new_name: Self::identifier_from_name(new_field.trim(), false),
                });
            }
            ast::AlterTypeAction::SetOptions(set_options) => {
                let attrs = Self::extract_attribute_list(set_options.attribute_list());
                actions.push(AlterTypeActionFact::SetOptions {
                    options: Self::extract_base_type_options(&attrs),
                });
            }
            ast::AlterTypeAction::AlterTypeAttributeActionList(list) => {
                for action in list.actions() {
                    match action {
                        ast::AlterTypeAttributeAction::AddAttribute(add) => {
                            let field_syntax = add.composite_field()?.syntax().text().to_string();
                            let name = Self::identifier_from_name(field_syntax.trim(), false);
                            let data_type = add.ty()?.syntax().text().to_string();
                            let collation =
                                Self::index_item_written_name(add.collate(), |collate| {
                                    collate.collation_ref()?.path_ref()
                                })
                                .map(|written| {
                                    match written.schema {
                                        Some(schema) => format!("{schema}.{}", written.name),
                                        None => written.name,
                                    }
                                });
                            actions.push(AlterTypeActionFact::AddAttribute {
                                name,
                                data_type,
                                collation,
                            });
                        }
                        ast::AlterTypeAttributeAction::DropAttribute(drop) => {
                            let field_syntax =
                                drop.composite_field_ref()?.syntax().text().to_string();
                            let name = Self::identifier_from_name(field_syntax.trim(), false);
                            let if_exists = drop.if_exists().is_some();
                            let cascade = Self::is_cascade(drop.drop_behavior());
                            actions.push(AlterTypeActionFact::DropAttribute {
                                name,
                                if_exists,
                                cascade,
                            });
                        }
                        ast::AlterTypeAttributeAction::AlterAttribute(alter) => {
                            let field_syntax =
                                alter.composite_field_ref()?.syntax().text().to_string();
                            let name = Self::identifier_from_name(field_syntax.trim(), false);
                            let data_type = alter.ty()?.syntax().text().to_string();
                            let collation =
                                Self::index_item_written_name(alter.collate(), |collate| {
                                    collate.collation_ref()?.path_ref()
                                })
                                .map(|written| {
                                    match written.schema {
                                        Some(schema) => format!("{schema}.{}", written.name),
                                        None => written.name,
                                    }
                                });
                            let cascade = Self::is_cascade(alter.drop_behavior());
                            actions.push(AlterTypeActionFact::AlterAttributeType {
                                name,
                                data_type,
                                collation,
                                cascade,
                            });
                        }
                    }
                }
            }
        }

        Some(StatementFact::AlterType(AlterTypeFact { name, actions }))
    }
}
