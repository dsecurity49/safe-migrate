use super::*;

impl AstVisitor {
    pub(super) fn extract_create_schema(node: &ast::CreateSchema) -> Option<StatementFact> {
        let (name, authorization) = match node.create_schema_target()? {
            ast::CreateSchemaTarget::NamedSchema(ns) => (
                ns.schema()
                    .and_then(|schema| schema.ident_token())
                    .map(|token| Self::identifier_from_token(token.text()))?,
                ns.role_ref().map(|role| Self::extract_role(&role)),
            ),
            ast::CreateSchemaTarget::AuthorizationSchema(aus) => {
                let role = aus.role()?;
                let authorization = Self::extract_role_node(&role);
                let crate::_internal::analysis::facts::RoleFact::Named { name, .. } =
                    &authorization
                else {
                    return None;
                };
                (Ident::new(name.clone(), true), Some(authorization))
            }
        };

        Some(StatementFact::CreateSchema {
            name: QualifiedName::new(None, name),
            if_not_exists: node.if_not_exists().is_some(),
            authorization,
        })
    }

    pub(super) fn extract_alter_schema(node: &ast::AlterSchema) -> Option<StatementFact> {
        let nr = node.schema_ref()?.ident_token()?;
        let name = QualifiedName::new(None, Self::identifier_from_token(nr.text()));
        let action = node.action().and_then(|a| match a {
            ast::AlterSchemaAction::SchemaRenameTo(rt) => {
                rt.schema().and_then(|s| s.ident_token()).map(|n| {
                    crate::_internal::analysis::facts::AlterSchemaActionFact::RenameTo {
                        new_name: Self::identifier_from_token(n.text()),
                    }
                })
            }
            ast::AlterSchemaAction::OwnerTo(owner) => owner.role_ref().map(|role| {
                crate::_internal::analysis::facts::AlterSchemaActionFact::OwnerTo {
                    new_owner: Self::extract_role(&role),
                }
            }),
        })?;
        Some(StatementFact::AlterSchema { name, action })
    }

    pub(super) fn extract_drop_schema(node: &ast::DropSchema) -> Option<StatementFact> {
        // DROP SCHEMA uses NameRef nodes (bare identifiers), NOT Path nodes.
        // Squawk's DropSchema accessor exposes name_refs() for exactly this reason.
        let names: Vec<QualifiedName> = node
            .schema_refs()
            .filter_map(|r| r.ident_token())
            .map(|nr| QualifiedName::new(None, Self::identifier_from_token(nr.text())))
            .collect();

        if names.is_empty() {
            return None;
        }

        Some(StatementFact::DropSchema {
            names,
            if_exists: node.if_exists().is_some(),
            cascade: Self::is_cascade(node.drop_behavior()),
        })
    }
}
