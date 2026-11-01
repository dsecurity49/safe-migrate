use super::Resolver;
use crate::_internal::analysis::facts::{
    AlterExtensionActionFact, AlterExtensionFact, CreateExtensionFact, ExtensionMemberFact,
};
use crate::_internal::analysis::mutations::{
    AlterExtensionActionMutation, AlterExtensionMutation, CreateExtensionMutation,
    DropExtensionMutation, Mutation,
};
use crate::_internal::analysis::state::AnalysisState;
use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::model::extension::{ExtensionMember, ExtensionMemberKind};

impl Resolver {
    pub(super) fn resolve_create_extension(fact: &CreateExtensionFact) -> Mutation {
        Mutation::CreateExtension(CreateExtensionMutation {
            name: fact.name.clone(),
            if_not_exists: fact.if_not_exists,
            schema: fact.schema.clone(),
            version: fact.version.clone(),
            cascade: fact.cascade,
        })
    }

    pub(super) fn resolve_alter_extension(
        fact: &AlterExtensionFact,
        state: &AnalysisState,
    ) -> Mutation {
        let action = match &fact.action {
            AlterExtensionActionFact::Add(member) => {
                AlterExtensionActionMutation::Add(Self::resolve_extension_member(member, state))
            }
            AlterExtensionActionFact::Drop(member) => {
                AlterExtensionActionMutation::Drop(Self::resolve_extension_member(member, state))
            }
            AlterExtensionActionFact::Update { version } => AlterExtensionActionMutation::Update {
                version: version.clone(),
            },
            AlterExtensionActionFact::SetSchema { new_schema } => {
                AlterExtensionActionMutation::SetSchema {
                    new_schema: new_schema.clone(),
                }
            }
        };
        Mutation::AlterExtension(AlterExtensionMutation {
            name: fact.name.clone(),
            action,
        })
    }

    pub(super) fn resolve_drop_extension(
        names: &[String],
        if_exists: bool,
        cascade: bool,
    ) -> Mutation {
        Mutation::DropExtension(DropExtensionMutation {
            names: names.to_vec(),
            if_exists,
            cascade,
        })
    }

    fn resolve_extension_member(
        member: &ExtensionMemberFact,
        state: &AnalysisState,
    ) -> ExtensionMember {
        match member {
            ExtensionMemberFact::Named { kind, name } => {
                let id = match kind {
                    ExtensionMemberKind::Relation
                    | ExtensionMemberKind::Sequence
                    | ExtensionMemberKind::Index => Self::resolve_relation_lookup_name(name, state),
                    ExtensionMemberKind::Type => Self::resolve_type_lookup_name(name, state),
                    _ => Self::resolve_creation_name(name, state),
                };
                ExtensionMember {
                    kind: kind.clone(),
                    id,
                }
            }
            ExtensionMemberFact::Routine { name, params } => ExtensionMember {
                kind: ExtensionMemberKind::Routine,
                id: Self::resolve_routine_lookup_name(name, params, state),
            },
            ExtensionMemberFact::Schema(name) => ExtensionMember {
                kind: ExtensionMemberKind::Schema,
                id: ObjectId::new("", name),
            },
            ExtensionMemberFact::Unmodeled(class) => ExtensionMember {
                kind: ExtensionMemberKind::Unmodeled(class.clone()),
                id: ObjectId::new("", class),
            },
        }
    }
}
