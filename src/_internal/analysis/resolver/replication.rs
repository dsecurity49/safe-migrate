use super::Resolver;
use crate::_internal::analysis::facts::{
    AlterPublicationActionFact, AlterPublicationFact, AlterSubscriptionFact, CreatePublicationFact,
    CreateSubscriptionFact, DropPublicationFact, DropSubscriptionFact, PublicationObjectFact,
    PublicationScope,
};
use crate::_internal::analysis::mutations::{
    AlterPublicationMutation, AlterSubscriptionMutation, CreatePublicationMutation,
    CreateSubscriptionMutation, DropPublicationMutation, DropSubscriptionMutation, Mutation,
};
use crate::_internal::analysis::state::AnalysisState;
use crate::_internal::ast::identifiers::{Ident, QualifiedName};

impl Resolver {
    fn resolve_publication_object(
        object: &PublicationObjectFact,
        state: &AnalysisState,
    ) -> PublicationObjectFact {
        match object {
            PublicationObjectFact::Table {
                name,
                only,
                include_partitions,
                columns,
                row_filter,
            } => {
                let id = Self::resolve_relation_lookup_name(name, state);
                PublicationObjectFact::Table {
                    name: QualifiedName::new(
                        Some(Ident::new(id.schema, true)),
                        Ident::new(id.name, true),
                    ),
                    only: *only,
                    include_partitions: *include_partitions,
                    columns: columns.clone(),
                    row_filter: row_filter.clone(),
                }
            }
            PublicationObjectFact::CurrentSchemaShorthand => PublicationObjectFact::SchemaTables {
                schema: state
                    .local
                    .search_path
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "public".to_string()),
                row_filter: None,
            },
            other => other.clone(),
        }
    }

    fn resolve_publication_scope(
        scope: &PublicationScope,
        state: &AnalysisState,
    ) -> PublicationScope {
        match scope {
            PublicationScope::AllTables { except } => PublicationScope::AllTables {
                except: except.clone(),
            },
            PublicationScope::Explicit(objects) => PublicationScope::Explicit(
                objects
                    .iter()
                    .map(|object| Self::resolve_publication_object(object, state))
                    .collect(),
            ),
        }
    }

    fn resolve_alter_publication_action(
        action: &AlterPublicationActionFact,
        state: &AnalysisState,
    ) -> AlterPublicationActionFact {
        match action {
            AlterPublicationActionFact::AddObjects(objects) => {
                AlterPublicationActionFact::AddObjects(
                    objects
                        .iter()
                        .map(|object| Self::resolve_publication_object(object, state))
                        .collect(),
                )
            }
            AlterPublicationActionFact::DropObjects(objects) => {
                AlterPublicationActionFact::DropObjects(
                    objects
                        .iter()
                        .map(|object| Self::resolve_publication_object(object, state))
                        .collect(),
                )
            }
            AlterPublicationActionFact::SetObjects(scope) => {
                AlterPublicationActionFact::SetObjects(Self::resolve_publication_scope(
                    scope, state,
                ))
            }
            other => other.clone(),
        }
    }

    pub(super) fn resolve_create_publication(
        fact: &CreatePublicationFact,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::CreatePublication(CreatePublicationMutation {
            name: fact.name.clone(),
            scope: Self::resolve_publication_scope(&fact.scope, state),
            params: fact.params.clone(),
        })
    }

    pub(super) fn resolve_alter_publication(
        fact: &AlterPublicationFact,
        state: &AnalysisState,
    ) -> Mutation {
        Mutation::AlterPublication(AlterPublicationMutation {
            name: fact.name.clone(),
            action: Self::resolve_alter_publication_action(&fact.action, state),
        })
    }

    pub(super) fn resolve_drop_publication(fact: &DropPublicationFact) -> Mutation {
        Mutation::DropPublication(DropPublicationMutation {
            names: fact.names.clone(),
            if_exists: fact.if_exists,
            cascade: fact.cascade,
        })
    }

    pub(super) fn resolve_create_subscription(fact: &CreateSubscriptionFact) -> Mutation {
        Mutation::CreateSubscription(CreateSubscriptionMutation {
            name: fact.name.clone(),
            connection: fact.connection.clone(),
            publications: fact.publications.clone(),
            params: fact.params.clone(),
        })
    }

    pub(super) fn resolve_alter_subscription(fact: &AlterSubscriptionFact) -> Mutation {
        Mutation::AlterSubscription(AlterSubscriptionMutation {
            name: fact.name.clone(),
            action: fact.action.clone(),
        })
    }

    pub(super) fn resolve_drop_subscription(fact: &DropSubscriptionFact) -> Mutation {
        Mutation::DropSubscription(DropSubscriptionMutation {
            name: fact.name.clone(),
            if_exists: fact.if_exists,
        })
    }
}
