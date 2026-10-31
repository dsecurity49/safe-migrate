use super::Resolver;
use crate::_internal::analysis::facts::{
    AlterDomainActionFact, AlterTypeActionFact, AlterTypeFact, CreateTypeFact, TypeCreationKind,
};
use crate::_internal::analysis::mutations::{
    AlterDomainMutation, AlterTypeActionMutation, AlterTypeMutation, CreateDomainMutation,
    CreateTypeMutation, DropDomainMutation, DropTypeMutation, Mutation, Rename,
};
use crate::_internal::analysis::state::AnalysisState;
use crate::_internal::ast::identifiers::{ObjectId, QualifiedName};
use crate::_internal::model::types::TypeKind;

impl Resolver {
    pub(super) fn resolve_create_type(fact: &CreateTypeFact, state: &AnalysisState) -> Mutation {
        let mut multirange_name = None;
        let kind = match &fact.kind {
            TypeCreationKind::Enum { variants } => TypeKind::Enum {
                variants: variants.clone(),
            },
            TypeCreationKind::Range {
                subtype,
                multirange_type_name,
                collation,
                opclass,
                canonical,
                subtype_diff,
            } => {
                if let Some(mr_name) = multirange_type_name {
                    multirange_name = Some(Self::resolve_creation_name(mr_name, state));
                }
                let collation_id = collation.as_deref().and_then(|written| {
                    let w = if let Some((s, n)) = written.split_once('.') {
                        crate::_internal::model::index::WrittenName {
                            schema: Some(s.to_string()),
                            name: n.to_string(),
                        }
                    } else {
                        crate::_internal::model::index::WrittenName {
                            schema: None,
                            name: written.to_string(),
                        }
                    };
                    state
                        .local
                        .collations
                        .resolve(&w, &state.local.search_path)
                        .map(|c| ObjectId::new(c.schema, c.name))
                });
                let opclass_id = opclass.as_deref().and_then(|written| {
                    let w = if let Some((s, n)) = written.split_once('.') {
                        crate::_internal::model::index::WrittenName {
                            schema: Some(s.to_string()),
                            name: n.to_string(),
                        }
                    } else {
                        crate::_internal::model::index::WrittenName {
                            schema: None,
                            name: written.to_string(),
                        }
                    };
                    state
                        .local
                        .opclasses
                        .resolve(&w, "btree", &state.local.search_path)
                        .map(|o| ObjectId::new(o.family.schema.clone(), o.name.clone()))
                });
                let canonical_id = None;
                let subtype_diff_id = None;
                TypeKind::Range {
                    subtype: subtype.clone(),
                    subtype_id: subtype
                        .as_deref()
                        .and_then(|subtype| state.resolve_type_reference(subtype)),
                    multirange: None,
                    collation: collation.clone(),
                    collation_id,
                    opclass: opclass.clone(),
                    opclass_id,
                    canonical: canonical.clone(),
                    canonical_id,
                    subtype_diff: subtype_diff.clone(),
                    subtype_diff_id,
                }
            }
            TypeCreationKind::Composite { fields } => TypeKind::Composite {
                fields: fields
                    .iter()
                    .map(|field| {
                        let collation_id = field.collation.as_deref().and_then(|written| {
                            let w = if let Some((s, n)) = written.split_once('.') {
                                crate::_internal::model::index::WrittenName {
                                    schema: Some(s.to_string()),
                                    name: n.to_string(),
                                }
                            } else {
                                crate::_internal::model::index::WrittenName {
                                    schema: None,
                                    name: written.to_string(),
                                }
                            };
                            state
                                .local
                                .collations
                                .resolve(&w, &state.local.search_path)
                                .map(|c| ObjectId::new(c.schema, c.name))
                        });
                        crate::_internal::model::types::CompositeFieldState {
                            name: field.name.clone(),
                            data_type: field.data_type.clone(),
                            data_type_id: state.resolve_type_reference(&field.data_type),
                            collation: field.collation.clone(),
                            collation_id,
                        }
                    })
                    .collect(),
            },
            TypeCreationKind::Base { options } => {
                let is_shell =
                    options == &crate::_internal::model::types::BaseTypeOptions::default();
                TypeKind::Base {
                    shell: is_shell,
                    options: options.clone(),
                }
            }
        };
        Mutation::CreateType(CreateTypeMutation {
            id: Self::resolve_creation_name(&fact.name, state),
            kind,
            multirange_name,
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
                AlterTypeActionFact::OwnerTo { new_owner } => {
                    Mutation::AlterType(AlterTypeMutation {
                        id: id.clone(),
                        action: AlterTypeActionMutation::OwnerTo {
                            new_owner: new_owner.clone(),
                        },
                    })
                }
                AlterTypeActionFact::AddAttribute {
                    name,
                    data_type,
                    collation,
                } => Mutation::AlterType(AlterTypeMutation {
                    id: id.clone(),
                    action: AlterTypeActionMutation::AddAttribute {
                        name: name.resolve(),
                        data_type: data_type.clone(),
                        collation: collation.clone(),
                    },
                }),
                AlterTypeActionFact::DropAttribute {
                    name,
                    if_exists,
                    cascade,
                } => Mutation::AlterType(AlterTypeMutation {
                    id: id.clone(),
                    action: AlterTypeActionMutation::DropAttribute {
                        name: name.resolve(),
                        if_exists: *if_exists,
                        cascade: *cascade,
                    },
                }),
                AlterTypeActionFact::AlterAttributeType {
                    name,
                    data_type,
                    collation,
                    cascade,
                } => Mutation::AlterType(AlterTypeMutation {
                    id: id.clone(),
                    action: AlterTypeActionMutation::AlterAttributeType {
                        name: name.resolve(),
                        data_type: data_type.clone(),
                        collation: collation.clone(),
                        cascade: *cascade,
                    },
                }),
                AlterTypeActionFact::RenameAttribute { old_name, new_name } => {
                    Mutation::AlterType(AlterTypeMutation {
                        id: id.clone(),
                        action: AlterTypeActionMutation::RenameAttribute {
                            old_name: old_name.resolve(),
                            new_name: new_name.resolve(),
                        },
                    })
                }
                AlterTypeActionFact::SetOptions { options } => {
                    Mutation::AlterType(AlterTypeMutation {
                        id: id.clone(),
                        action: AlterTypeActionMutation::SetOptions {
                            options: options.clone(),
                        },
                    })
                }
            })
            .collect()
    }

    pub(super) fn resolve_create_domain(
        create: &crate::_internal::analysis::facts::CreateDomainFact,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::CreateDomain(CreateDomainMutation {
            id: Self::resolve_creation_name(&create.name, state),
            base_type: create.base_type.clone(),
            collation: create.collation.clone(),
            default: create.default.clone(),
            constraints: create.constraints.clone(),
        })
    }

    pub(super) fn resolve_alter_domain(
        name: &QualifiedName,
        action: &Option<AlterDomainActionFact>,
        state: &AnalysisState,
    ) -> Mutation {
        let id = Self::resolve_type_lookup_name(name, state);
        let Some(action) = action else {
            return Mutation::AlterDomain(AlterDomainMutation { id, action: None });
        };
        match action {
            AlterDomainActionFact::RenameTo { new_name } => {
                let mut new_id = ObjectId::new(id.schema.clone(), new_name.resolve());
                new_id.inferred_schema = id.inferred_schema;
                Mutation::RenameDomain(Rename { old_id: id, new_id })
            }
            AlterDomainActionFact::SetSchema { new_schema } => Mutation::RenameDomain(Rename {
                old_id: id.clone(),
                new_id: ObjectId::new(new_schema, &id.name),
            }),
            action => Mutation::AlterDomain(AlterDomainMutation {
                id,
                action: Some(action.clone()),
            }),
        }
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
