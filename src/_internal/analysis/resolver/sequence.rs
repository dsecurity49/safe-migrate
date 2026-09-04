use super::Resolver;
use crate::_internal::analysis::facts::AlterSequenceActionFact;
use crate::_internal::analysis::mutations::{
    AlterSequenceActionMutation, AlterSequenceMutation, CreateSequenceMutation,
    DropSequenceMutation, Mutation,
};
use crate::_internal::analysis::state::AnalysisState;
use crate::_internal::ast::identifiers::{ObjectId, QualifiedName};

impl Resolver {
    fn resolve_owned_by(
        owned_by: &Option<(QualifiedName, String)>,
        state: &AnalysisState,
    ) -> Option<(ObjectId, String)> {
        owned_by.as_ref().map(|(table_name, column)| {
            (
                Self::resolve_relation_lookup_name(table_name, state),
                column.clone(),
            )
        })
    }

    pub(super) fn resolve_create_sequence(
        name: &QualifiedName,
        if_not_exists: bool,
        owned_by: &Option<(QualifiedName, String)>,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::CreateSequence(CreateSequenceMutation {
            id: Self::resolve_creation_name(name, state),
            if_not_exists,
            owned_by: Self::resolve_owned_by(owned_by, state),
        })
    }

    pub(super) fn resolve_alter_sequence(
        name: &QualifiedName,
        if_exists: bool,
        action: &AlterSequenceActionFact,
        state: &AnalysisState,
    ) -> Mutation {
        let id = Self::resolve_relation_lookup_name(name, state);
        let action = match action {
            AlterSequenceActionFact::OwnedBy(owned_by) => {
                AlterSequenceActionMutation::OwnedBy(Self::resolve_owned_by(owned_by, state))
            }
            AlterSequenceActionFact::OwnerTo(owner) => {
                AlterSequenceActionMutation::OwnerTo(owner.clone())
            }
            AlterSequenceActionFact::RenameTo(new_name) => {
                let mut new_id = ObjectId::new(&id.schema, new_name.resolve());
                new_id.inferred_schema = id.inferred_schema;
                AlterSequenceActionMutation::RenameTo(new_id)
            }
            AlterSequenceActionFact::SetSchema(schema) => {
                AlterSequenceActionMutation::SetSchema(ObjectId::new(schema, &id.name))
            }
            AlterSequenceActionFact::Other => AlterSequenceActionMutation::Other,
        };
        Mutation::AlterSequence(AlterSequenceMutation {
            id,
            if_exists,
            action,
        })
    }

    pub(super) fn resolve_drop_sequence(
        names: &[QualifiedName],
        if_exists: bool,
        cascade: bool,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::DropSequence(DropSequenceMutation {
            ids: names
                .iter()
                .map(|name| Self::resolve_relation_lookup_name(name, state))
                .collect(),
            if_exists,
            cascade,
        })
    }
}
