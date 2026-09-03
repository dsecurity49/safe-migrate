use safe_migrate::_internal::analysis::graph::DependencyKind;
use safe_migrate::_internal::analysis::state::AnalysisState;
use safe_migrate::_internal::analysis::transaction::TransactionFrameKind;
use safe_migrate::_internal::db::cache::DbCache;
use safe_migrate::_internal::model::function::FunctionOverlay;
use safe_migrate::_internal::model::relation::RelationOverlay;
use safe_migrate::_internal::model::replication::{PublicationOverlay, SubscriptionOverlay};
use safe_migrate::_internal::model::role::RoleOverlay;
use safe_migrate::_internal::model::schema::SchemaOverlay;
use safe_migrate::_internal::model::sequence::SequenceOverlay;
use safe_migrate::_internal::model::trigger::TriggerOverlay;
use safe_migrate::_internal::model::types::TypeOverlay;
use std::collections::HashSet;

pub fn assert_cache_invariants(cache: &DbCache) {
    for (id, relation) in &cache.relations {
        assert_eq!(
            id, &relation.id,
            "cached relation map key disagrees with state"
        );
    }
    for (id, ty) in &cache.types {
        assert_eq!(id, &ty.id, "cached type map key disagrees with state");
    }
    for (id, function) in &cache.functions {
        assert_eq!(
            id, &function.id,
            "cached function map key disagrees with state"
        );
    }
    for (id, sequence) in &cache.sequences {
        assert_eq!(
            id, &sequence.id,
            "cached sequence map key disagrees with state"
        );
        if let Some((table_id, _)) = &sequence.owned_by {
            assert!(
                cache.relations.contains_key(table_id),
                "cached owned sequence must reference a cached relation"
            );
        }
    }
    for (id, role) in &cache.roles {
        assert_eq!(id, &role.id, "cached role map key disagrees with state");
    }
    for (name, schema) in &cache.schemas {
        assert_eq!(
            name, &schema.name,
            "cached schema map key disagrees with state"
        );
    }
    for (name, publication) in &cache.publications {
        assert_eq!(
            name, &publication.name,
            "cached publication map key disagrees with state"
        );
    }
    for (name, subscription) in &cache.subscriptions {
        assert_eq!(
            name, &subscription.name,
            "cached subscription map key disagrees with state"
        );
    }

    let mut constraint_keys = HashSet::new();
    for constraint in &cache.constraints {
        assert!(
            cache.relations.contains_key(&constraint.table_id),
            "cached constraint must reference a cached relation"
        );
        assert!(
            constraint_keys.insert((constraint.table_id.clone(), constraint.name.clone())),
            "cached constraints must have unique table/name identities"
        );
    }
    for index in &cache.indexes {
        assert!(
            cache.relations.contains_key(&index.table_id),
            "cached index must reference a cached relation"
        );
    }
    for trigger in &cache.triggers {
        assert!(
            cache.relations.contains_key(&trigger.table_id),
            "cached trigger must reference a cached relation"
        );
    }
    for foreign_key in &cache.foreign_keys {
        assert!(
            cache.relations.contains_key(&foreign_key.from_table)
                && cache.relations.contains_key(&foreign_key.to_table),
            "cached foreign key must reference cached relations"
        );
    }
}

pub fn assert_state_invariants(state: &AnalysisState) {
    let local = &state.local;
    assert!(
        local.graph.indexes_are_valid(),
        "dependency-graph indexes disagree with canonical edges"
    );

    for (name, schema) in &local.schemas {
        if let SchemaOverlay::Present(schema) = schema {
            assert_eq!(name, &schema.name, "schema map key disagrees with state");
        }
    }
    for (id, relation) in &local.relations {
        if let RelationOverlay::Present(relation) = relation {
            assert_eq!(id, &relation.id, "relation map key disagrees with state");
        }
    }
    for (id, ty) in &local.types {
        if let TypeOverlay::Present(ty) = ty {
            assert_eq!(id, &ty.id, "type map key disagrees with state");
        }
    }
    for (id, function) in &local.functions {
        if let FunctionOverlay::Present(function) = function {
            assert_eq!(id, &function.id, "function map key disagrees with state");
        }
    }
    for (id, sequence) in &local.sequences {
        if let SequenceOverlay::Present(sequence) = sequence {
            assert_eq!(id, &sequence.id, "sequence map key disagrees with state");
        }
    }
    for (id, role) in &local.roles {
        if let RoleOverlay::Present(role) = role {
            assert_eq!(id, &role.id, "role map key disagrees with state");
        }
    }
    for (name, publication) in &local.publications {
        if let PublicationOverlay::Present(publication) = publication {
            assert_eq!(
                name, &publication.name,
                "publication map key disagrees with state"
            );
        }
    }
    for (name, subscription) in &local.subscriptions {
        if let SubscriptionOverlay::Present(subscription) = subscription {
            assert_eq!(
                name, &subscription.name,
                "subscription map key disagrees with state"
            );
        }
    }
    for (id, trigger) in &local.triggers {
        if let TriggerOverlay::Present(trigger) = trigger {
            assert_eq!(id, &trigger.id, "trigger map key disagrees with state");
            assert!(
                !matches!(
                    local.relations.get(&trigger.table_id),
                    Some(RelationOverlay::Dropped)
                ),
                "present trigger belongs to a dropped relation"
            );
        }
    }
    for ((table_id, name), constraint) in &local.constraints {
        assert_eq!(
            table_id, &constraint.table_id,
            "constraint table key disagrees with state"
        );
        assert_eq!(
            name, &constraint.name,
            "constraint name key disagrees with state"
        );
        assert!(
            !matches!(
                local.relations.get(table_id),
                Some(RelationOverlay::Dropped)
            ),
            "constraint belongs to a dropped relation"
        );
    }
    for key in &local.pending_validation {
        let constraint = local
            .constraints
            .get(key)
            .expect("pending validation must reference a known constraint");
        assert!(
            !constraint.validated,
            "validated constraint cannot be pending"
        );
    }

    for edge in local.graph.edges() {
        match &edge.kind {
            DependencyKind::ForeignKey {
                constraint_name: Some(name),
                ..
            } => assert!(
                local
                    .constraints
                    .contains_key(&(edge.dependent.clone(), name.clone())),
                "foreign-key edge must have a matching constraint"
            ),
            DependencyKind::ViewDependency { .. } => {
                let dependent_is_modeled_view = matches!(
                    local.relations.get(&edge.dependent),
                    Some(RelationOverlay::Present(relation))
                        if matches!(relation.kind, safe_migrate::_internal::model::relation::RelationKind::View | safe_migrate::_internal::model::relation::RelationKind::MaterializedView)
                );
                let dependent_schema_is_omitted = state
                    .baseline_schemas
                    .as_ref()
                    .is_some_and(|schemas| !schemas.contains(&edge.dependent.schema));
                assert!(
                    dependent_is_modeled_view || dependent_schema_is_omitted,
                    "view dependency must have a modeled view or an explicitly omitted dependent schema"
                );
                assert!(!matches!(
                    local.relations.get(&edge.referenced),
                    Some(RelationOverlay::Dropped)
                ));
            }
            DependencyKind::SequenceOwnedBy { column } => assert!(matches!(
                local.sequences.get(&edge.dependent),
                Some(SequenceOverlay::Present(sequence))
                    if sequence.owned_by == Some((edge.referenced.clone(), column.clone()))
            )),
            DependencyKind::TriggerOnTable { trigger_id, .. } => assert!(matches!(
                local.triggers.get(trigger_id),
                Some(TriggerOverlay::Present(trigger)) if trigger.table_id == edge.referenced
            )),
            DependencyKind::PublicationIncludes { publication_name } => assert!(matches!(
                local.publications.get(publication_name),
                Some(PublicationOverlay::Present(publication)) if publication.name == *publication_name
            )),
            DependencyKind::ConstraintOnRelation {
                constraint_name, ..
            } => assert!(
                local
                    .constraints
                    .contains_key(&(edge.dependent.clone(), constraint_name.clone())),
                "constraint key edge must have a matching constraint"
            ),
            DependencyKind::IndexOnRelation { .. }
            | DependencyKind::RenameTo
            | DependencyKind::InheritanceOf
            | DependencyKind::PartitionOf
            | DependencyKind::ConstraintDependency { .. }
            | DependencyKind::ColumnGeneratedFrom { .. }
            | DependencyKind::ColumnDefaultOnSequence { .. }
            | DependencyKind::ForeignKey {
                constraint_name: None,
                ..
            } => {}
        }
    }

    if local.transactions.is_empty() {
        assert!(
            !local.transaction_aborted,
            "an aborted transaction must retain its root frame"
        );
    } else {
        assert!(matches!(
            local.transactions.first().map(|frame| &frame.kind),
            Some(TransactionFrameKind::Root)
        ));
        assert!(
            local
                .transactions
                .iter()
                .skip(1)
                .all(|frame| matches!(frame.kind, TransactionFrameKind::Savepoint { .. })),
            "only the first transaction frame may be the root"
        );
    }
}
