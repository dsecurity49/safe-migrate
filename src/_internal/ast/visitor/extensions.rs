use super::*;

impl AstVisitor {
    pub(super) fn extract_create_extension(node: &ast::CreateExtension) -> Option<StatementFact> {
        let name = Self::extension_name(node.extension()?.ident_token()?)?;
        let schema = node
            .extension_schema()
            .and_then(|schema| schema.schema_ref())
            .map(|schema| Self::resolve_schema_ref(&schema));
        let version = Self::extension_version(node.extension_version_clause());
        Some(StatementFact::CreateExtension(
            crate::_internal::analysis::facts::CreateExtensionFact {
                name,
                if_not_exists: node.if_not_exists().is_some(),
                schema,
                version,
                cascade: node.cascade_token().is_some(),
            },
        ))
    }

    pub(super) fn extract_alter_extension(node: &ast::AlterExtension) -> Option<StatementFact> {
        let name = Self::extension_name(node.extension_ref()?.ident_token()?)?;
        let action = match node.action()? {
            ast::AlterExtensionAction::AlterExtensionAdd(add) => {
                crate::_internal::analysis::facts::AlterExtensionActionFact::Add(
                    Self::extension_member_fact(add.extension_member_object()?)?,
                )
            }
            ast::AlterExtensionAction::AlterExtensionDrop(drop) => {
                crate::_internal::analysis::facts::AlterExtensionActionFact::Drop(
                    Self::extension_member_fact(drop.extension_member_object()?)?,
                )
            }
            ast::AlterExtensionAction::AlterExtensionUpdate(update) => {
                crate::_internal::analysis::facts::AlterExtensionActionFact::Update {
                    version: Self::update_to_version(update.update_to()),
                }
            }
            ast::AlterExtensionAction::SetSchema(set_schema) => {
                crate::_internal::analysis::facts::AlterExtensionActionFact::SetSchema {
                    new_schema: Self::resolve_schema_ref(&set_schema.schema_ref()?),
                }
            }
        };
        Some(StatementFact::AlterExtension(
            crate::_internal::analysis::facts::AlterExtensionFact { name, action },
        ))
    }

    pub(super) fn extract_drop_extension(node: &ast::DropExtension) -> Option<StatementFact> {
        let names = node
            .extension_refs()
            .filter_map(|extension| Self::extension_name(extension.ident_token()?))
            .collect::<Vec<_>>();
        if names.is_empty() {
            return None;
        }
        Some(StatementFact::DropExtension(
            crate::_internal::analysis::facts::DropExtensionFact {
                names,
                if_exists: node.if_exists().is_some(),
                cascade: Self::is_cascade(node.drop_behavior()),
            },
        ))
    }

    fn extension_name(token: squawk_syntax::SyntaxToken) -> Option<String> {
        let text = token.text();
        if text.is_empty() {
            return None;
        }
        Some(Self::identifier_from_token(text).resolve())
    }

    fn extension_version(clause: Option<ast::ExtensionVersionClause>) -> Option<String> {
        let clause = clause?;
        clause
            .literal()
            .and_then(|literal| Self::resolve_string_literal(&literal))
            .or_else(|| {
                clause
                    .extension_version()
                    .and_then(|version| version.ident_token())
                    .map(|token| Self::identifier_from_token(token.text()).resolve())
            })
    }

    fn update_to_version(clause: Option<ast::UpdateTo>) -> Option<String> {
        let clause = clause?;
        clause
            .literal()
            .and_then(|literal| Self::resolve_string_literal(&literal))
            .or_else(|| {
                clause
                    .extension_version()
                    .and_then(|version| version.ident_token())
                    .map(|token| Self::identifier_from_token(token.text()).resolve())
            })
    }

    fn extension_member_fact(
        object: ast::ExtensionMemberObject,
    ) -> Option<crate::_internal::analysis::facts::ExtensionMemberFact> {
        use crate::_internal::analysis::facts::ExtensionMemberFact;
        use crate::_internal::model::extension::ExtensionMemberKind;
        Some(match object {
            ast::ExtensionMemberObject::ObjectTable(table) => Self::named_extension_member(
                ExtensionMemberKind::Relation,
                table
                    .table_name_ref()
                    .and_then(|name| name.path_ref())
                    .and_then(|path| Self::path_ref_to_qualified_name(&path)),
            ),
            ast::ExtensionMemberObject::ObjectView(view) => Self::named_extension_member(
                ExtensionMemberKind::Relation,
                view.view_ref()
                    .and_then(|view| view.path_ref())
                    .and_then(|path| Self::path_ref_to_qualified_name(&path)),
            ),
            ast::ExtensionMemberObject::ObjectMaterializedView(view) => {
                Self::named_extension_member(
                    ExtensionMemberKind::Relation,
                    view.view_ref()
                        .and_then(|view| view.path_ref())
                        .and_then(|path| Self::path_ref_to_qualified_name(&path)),
                )
            }
            ast::ExtensionMemberObject::ObjectSequence(sequence) => Self::named_extension_member(
                ExtensionMemberKind::Sequence,
                sequence
                    .sequence_ref()
                    .and_then(|sequence| sequence.path_ref())
                    .and_then(|path| Self::path_ref_to_qualified_name(&path)),
            ),
            ast::ExtensionMemberObject::ObjectIndex(index) => Self::named_extension_member(
                ExtensionMemberKind::Index,
                index
                    .index_ref()
                    .and_then(|index| index.path_ref())
                    .and_then(|path| Self::path_ref_to_qualified_name(&path)),
            ),
            ast::ExtensionMemberObject::ObjectType(ty) => Self::named_extension_member(
                ExtensionMemberKind::Type,
                ty.type_name_ref()
                    .and_then(|name| name.path_ref())
                    .and_then(|path| Self::path_ref_to_qualified_name(&path)),
            ),
            ast::ExtensionMemberObject::ObjectDomain(domain) => Self::named_extension_member(
                ExtensionMemberKind::Type,
                domain
                    .domain_ref()
                    .and_then(|domain| domain.path_ref())
                    .and_then(|path| Self::path_ref_to_qualified_name(&path)),
            ),
            ast::ExtensionMemberObject::ObjectSchema(schema) => {
                ExtensionMemberFact::Schema(Self::resolve_schema_ref(&schema.schema_ref()?))
            }
            ast::ExtensionMemberObject::ObjectCollation(collation) => Self::named_extension_member(
                ExtensionMemberKind::Collation,
                collation
                    .collation_ref()
                    .and_then(|collation| collation.path_ref())
                    .and_then(|path| Self::path_ref_to_qualified_name(&path)),
            ),
            ast::ExtensionMemberObject::ObjectFunction(function) => {
                let signature = function.function_sig()?;
                ExtensionMemberFact::Routine {
                    name: Self::path_ref_to_qualified_name(
                        &signature.function_name_ref()?.path_ref()?,
                    )?,
                    params: Self::extract_signature_params(signature.param_list()),
                }
            }
            ast::ExtensionMemberObject::ObjectProcedure(procedure) => {
                let signature = procedure.procedure_sig()?;
                ExtensionMemberFact::Routine {
                    name: Self::path_ref_to_qualified_name(
                        &signature.procedure_name_ref()?.path_ref()?,
                    )?,
                    params: Self::extract_signature_params(signature.param_list()),
                }
            }
            ast::ExtensionMemberObject::ObjectRoutine(routine) => {
                let signature = routine.routine_sig()?;
                ExtensionMemberFact::Routine {
                    name: Self::path_ref_to_qualified_name(
                        &signature.routine_name_ref()?.path_ref()?,
                    )?,
                    params: Self::extract_signature_params(signature.param_list()),
                }
            }
            ast::ExtensionMemberObject::ObjectAggregate(aggregate) => {
                let aggregate = aggregate.aggregate()?;
                ExtensionMemberFact::Routine {
                    name: Self::path_ref_to_qualified_name(&aggregate.path_ref()?)?,
                    params: Self::extract_signature_params(aggregate.param_list()),
                }
            }
            ast::ExtensionMemberObject::ObjectCast(_) => {
                ExtensionMemberFact::Unmodeled("cast".to_string())
            }
            _ => ExtensionMemberFact::Unmodeled("extension_member".to_string()),
        })
    }

    fn named_extension_member(
        kind: crate::_internal::model::extension::ExtensionMemberKind,
        name: Option<QualifiedName>,
    ) -> crate::_internal::analysis::facts::ExtensionMemberFact {
        match name {
            Some(name) => {
                crate::_internal::analysis::facts::ExtensionMemberFact::Named { kind, name }
            }
            None => crate::_internal::analysis::facts::ExtensionMemberFact::Unmodeled(
                "extension_member".to_string(),
            ),
        }
    }
}
