use super::*;

impl AstVisitor {
    pub(super) fn extract_create_domain(node: &CreateDomain) -> Option<StatementFact> {
        // Domain constraints and collations affect every column using the
        // domain, but are not represented in TypeState.  Do not claim an
        // exact domain when either catalog-visible property is present.
        if node.domain_qualifiers().next().is_some() {
            return None;
        }
        let path = node.domain()?.path()?;
        let base_type = node
            .ty()
            .map(|t| t.syntax().text().to_string())
            .unwrap_or_else(|| "<domain>".to_string());
        Some(StatementFact::CreateDomain {
            name: Self::path_to_qualified_name(&path)?,
            base_type,
        })
    }

    pub(super) fn extract_alter_domain(node: &AlterDomain) -> Option<StatementFact> {
        let path = node.domain_ref()?.path_ref()?;
        let action = node.action().map(|a| match a {
            squawk_syntax::ast::AlterDomainAction::AddConstraint(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::AddConstraint
            }
            squawk_syntax::ast::AlterDomainAction::DropConstraint(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::DropConstraint
            }
            squawk_syntax::ast::AlterDomainAction::DropDefault(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::DropDefault
            }
            squawk_syntax::ast::AlterDomainAction::DropNotNull(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::DropNotNull
            }
            squawk_syntax::ast::AlterDomainAction::OwnerTo(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::OwnerChange
            }
            squawk_syntax::ast::AlterDomainAction::RenameConstraint(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::RenameConstraint
            }
            squawk_syntax::ast::AlterDomainAction::DomainRenameTo(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::RenameTo
            }
            squawk_syntax::ast::AlterDomainAction::SetDefault(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::SetDefault
            }
            squawk_syntax::ast::AlterDomainAction::SetNotNull(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::SetNotNull
            }
            squawk_syntax::ast::AlterDomainAction::SetSchema(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::SetSchema
            }
            squawk_syntax::ast::AlterDomainAction::ValidateConstraint(_) => {
                crate::_internal::analysis::facts::AlterDomainActionFact::ValidateConstraint
            }
        });
        Some(StatementFact::AlterDomain {
            name: Self::path_ref_to_qualified_name(&path)?,
            action,
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

        let kind = match node.kind()? {
            ast::CreateTypeKind::EnumType(enum_type) => TypeCreationKind::Enum {
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
            ast::CreateTypeKind::CompositeType(composite) => TypeCreationKind::Composite {
                fields: composite
                    .composite_field_list()?
                    .composite_field_defs()
                    .map(|field| {
                        Some(crate::_internal::analysis::facts::CompositeFieldFact {
                            name: Self::resolve_identifier_token(
                                field.name()?.ident_token()?.text(),
                            ),
                            data_type: field.ty()?.syntax().text().to_string(),
                        })
                    })
                    .collect::<Option<Vec<_>>>()?,
            },
            // A range type is defined by its subtype and a base type by its
            // element; both arrive as attributes on the same list.
            ast::CreateTypeKind::RangeType(range) => TypeCreationKind::Range {
                subtype: Self::type_attribute(
                    Self::extract_attribute_list(range.attribute_list()),
                    "subtype",
                ),
            },
            ast::CreateTypeKind::BaseType(base) => TypeCreationKind::Base {
                element: Self::type_attribute(
                    Self::extract_attribute_list(base.attribute_list()),
                    "element",
                ),
            },
        };

        Some(StatementFact::CreateType(CreateTypeFact { name, kind }))
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
            // PostgreSQL also accepts attribute changes, OWNER changes, and
            // type options.  Those facts are not represented in the state
            // model; returning an empty action list would turn them into a
            // silent no-op, so route them through UnsupportedStatement.
            _ => return None,
        }

        Some(StatementFact::AlterType(AlterTypeFact { name, actions }))
    }
}
