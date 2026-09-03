use super::Resolver;
use crate::_internal::analysis::facts::{AlterSchemaActionFact, RoleFact};
use crate::_internal::analysis::mutations::{
    AlterSchemaMutation, CreateSchemaMutation, DropSchemaMutation, Mutation,
};
use crate::_internal::ast::identifiers::QualifiedName;

impl Resolver {
    pub(super) fn resolve_create_schema(
        name: &QualifiedName,
        if_not_exists: bool,
        authorization: &Option<RoleFact>,
    ) -> Mutation {
        Mutation::CreateSchema(CreateSchemaMutation {
            name: name.name.resolve(),
            if_not_exists,
            authorization: authorization.clone(),
        })
    }

    pub(super) fn resolve_alter_schema(
        name: &QualifiedName,
        action: &AlterSchemaActionFact,
    ) -> Mutation {
        let name = name.name.resolve();
        let action = match action {
            AlterSchemaActionFact::RenameTo { new_name } => AlterSchemaMutation::Rename {
                old_name: name,
                new_name: new_name.resolve(),
            },
            AlterSchemaActionFact::OwnerTo { new_owner } => AlterSchemaMutation::OwnerTo {
                name,
                new_owner: new_owner.clone(),
            },
        };
        Mutation::AlterSchema(action)
    }

    pub(super) fn resolve_drop_schema(
        names: &[QualifiedName],
        if_exists: bool,
        cascade: bool,
    ) -> Mutation {
        Mutation::DropSchema(DropSchemaMutation {
            names: names.iter().map(|name| name.name.resolve()).collect(),
            if_exists,
            cascade,
        })
    }
}
