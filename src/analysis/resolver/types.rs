use super::Resolver;
use crate::analysis::facts::{
    AlterDomainActionFact, AlterTypeActionFact, AlterTypeFact, CreateTypeFact, TypeCreationKind,
};
use crate::analysis::mutations::{
    AlterDomainMutation, AlterTypeActionMutation, AlterTypeMutation, CreateDomainMutation,
    CreateTypeMutation, DropDomainMutation, DropTypeMutation, Mutation, Rename,
};
use crate::analysis::state::AnalysisState;
use crate::ast::identifiers::{ObjectId, QualifiedName};
use crate::model::types::TypeKind;

impl Resolver {
    pub(super) fn resolve_create_type(fact: &CreateTypeFact, state: &AnalysisState) -> Mutation {
        let kind = match &fact.kind {
            TypeCreationKind::Enum { variants } => TypeKind::Enum {
                variants: variants.clone(),
            },
            TypeCreationKind::Range => TypeKind::Range,
            TypeCreationKind::Composite => TypeKind::Composite,
            TypeCreationKind::Base => TypeKind::Base,
        };
        Mutation::CreateType(CreateTypeMutation {
            id: Self::resolve_creation_name(&fact.name, state),
            kind,
        })
    }

    pub(super) fn resolve_alter_type(fact: &AlterTypeFact, state: &AnalysisState) -> Vec<Mutation> {
        let id = Self::resolve_type_lookup_name(&fact.name, state);
        fact.actions
            .iter()
            .map(|action| match action {
                AlterTypeActionFact::RenameTo { new_name } => {
                    let mut new_id = ObjectId::new(id.schema.clone(), new_name.resolve());
                    new_id.inferred_schema = id.inferred_schema;
                    Mutation::RenameType(Rename {
                        old_id: id.clone(),
                        new_id,
                    })
                }
                AlterTypeActionFact::SetSchema { new_schema } => Mutation::RenameType(Rename {
                    old_id: id.clone(),
                    new_id: ObjectId::new(new_schema, &id.name),
                }),
                AlterTypeActionFact::AddValue {
                    new_value,
                    neighbor,
                    before,
                } => Mutation::AlterType(AlterTypeMutation {
                    id: id.clone(),
                    action: AlterTypeActionMutation::AddValue {
                        new_value: new_value.clone(),
                        neighbor: neighbor.clone(),
                        before: *before,
                    },
                }),
                AlterTypeActionFact::RenameValue {
                    old_value,
                    new_value,
                } => Mutation::AlterType(AlterTypeMutation {
                    id: id.clone(),
                    action: AlterTypeActionMutation::RenameValue {
                        old_value: old_value.clone(),
                        new_value: new_value.clone(),
                    },
                }),
            })
            .collect()
    }

    pub(super) fn resolve_create_domain(
        name: &QualifiedName,
        base_type: &str,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::CreateDomain(CreateDomainMutation {
            id: Self::resolve_creation_name(name, state),
            base_type: base_type.to_string(),
        })
    }

    pub(super) fn resolve_alter_domain(
        name: &QualifiedName,
        action: &Option<AlterDomainActionFact>,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::AlterDomain(AlterDomainMutation {
            id: Self::resolve_type_lookup_name(name, state),
            action: action.clone(),
        })
    }

    pub(super) fn resolve_drop_domain(
        names: &[QualifiedName],
        if_exists: bool,
        cascade: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropDomain(DropDomainMutation {
            ids: names
                .iter()
                .map(|name| Self::resolve_type_lookup_name(name, state))
                .collect(),
            if_exists,
            cascade,
        })
    }

    pub(super) fn resolve_drop_type(
        names: &[QualifiedName],
        if_exists: bool,
        cascade: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropType(DropTypeMutation {
            ids: names
                .iter()
                .map(|name| Self::resolve_type_lookup_name(name, state))
                .collect(),
            if_exists,
            cascade,
        })
    }
}
