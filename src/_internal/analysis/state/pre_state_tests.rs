use super::*;
use crate::_internal::model::column::Column;
use crate::_internal::model::index::{IndexDefinition, IndexPredicate, index_keys};
use crate::_internal::model::types::CompositeFieldState;

#[test]
fn incremental_capture_matches_a_fresh_public_pre_state() {
    let mut state = AnalysisState::new(DbCache::new());
    let table_id = ObjectId::new("public", "capture_table");
    state.local.relations.insert(
        table_id.clone(),
        RelationOverlay::Present(crate::_internal::model::relation::RelationState::new(
            table_id.clone(),
            ObjectId::new("", "postgres"),
            1,
            Some(1),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        )),
    );

    let mut reused = PreState::default();
    state.capture_pre_state_into(&mut reused);
    assert_eq!(reused, state.capture_pre_state());

    let Some(RelationOverlay::Present(relation)) = state.local.relations.get_mut(&table_id) else {
        panic!("test relation must remain present");
    };
    relation.estimated_rows = Some(2);
    let index_id = ObjectId::new("public", "capture_table_idx");
    state.local.graph.add_edge(DependencyEdge::new(
        index_id,
        table_id.clone(),
        DependencyKind::IndexOnRelation {
            definition: IndexDefinition {
                method: Some("btree".into()),
                keys: index_keys(vec!["id".into()]),
                included: index_keys(Vec::new()),
                expression_keys: 0,
                unique: false,
                nulls_not_distinct: Some(false),
                predicate: IndexPredicate::None,
                unestablished: false,
                valid: true,
                ready: true,
                live: true,
            },
            dependency_columns: vec!["id".into()],
            dependency_columns_known: true,
            is_concurrent: false,
            is_immediate: true,
            eligibility_known: true,
        },
    ));
    state.capture_pre_state_into(&mut reused);
    assert_eq!(reused, state.capture_pre_state());
    assert_eq!(reused.relations[&table_id].estimated_rows, Some(2));
    assert_eq!(reused.indexes.len(), 1);

    state
        .local
        .relations
        .insert(table_id.clone(), RelationOverlay::Dropped);
    state.local.graph.replace_edges(Vec::new());
    state.capture_pre_state_into(&mut reused);
    assert_eq!(reused, state.capture_pre_state());
    assert!(!reused.relations.contains_key(&table_id));
    assert!(reused.indexes.is_empty());
}

#[test]
fn shared_composite_container_is_reported_for_every_relation() {
    let address = ObjectId::new("public", "address");
    let wrapper = ObjectId::new("public", "address_wrapper");
    let owner = ObjectId::new("", "postgres");

    let mut pre_state = PreState::default();
    pre_state.types.insert(
        address.clone(),
        TypeState {
            id: address.clone(),
            generation: 0,
            owner: owner.clone(),
            kind: TypeKind::Composite {
                fields: vec![CompositeFieldState {
                    name: "city".into(),
                    data_type: "text".into(),
                    data_type_id: None,
                    collation: None,
                    collation_id: None,
                }],
            },
        },
    );
    pre_state.types.insert(
        wrapper.clone(),
        TypeState {
            id: wrapper.clone(),
            generation: 0,
            owner: owner.clone(),
            kind: TypeKind::Composite {
                fields: vec![CompositeFieldState {
                    name: "location".into(),
                    data_type: "address".into(),
                    data_type_id: Some(address.clone()),
                    collation: None,
                    collation_id: None,
                }],
            },
        },
    );

    for (name, estimated_rows) in [("customers", 0), ("suppliers", 100_000)] {
        let table = ObjectId::new("public", name);
        let mut relation = crate::_internal::model::relation::RelationState::new(
            table.clone(),
            owner.clone(),
            0,
            Some(estimated_rows),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        let mut column = Column::migration_created(
            "address_info".into(),
            Some("address_wrapper".into()),
            true,
            None,
        );
        column.type_id = Some(wrapper.clone());
        relation.columns.push(column);
        pre_state.relations.insert(table, relation);
    }

    let dependent = pre_state.relations_using_composite(&address);
    assert_eq!(dependent.len(), 2);
    assert_eq!(
        dependent
            .iter()
            .filter_map(|relation| relation.estimated_rows)
            .max(),
        Some(100_000)
    );
}

#[test]
fn composite_containers_are_found_through_domains_and_arrays_for_every_relation() {
    let address = ObjectId::new("public", "address");
    let wrapper = ObjectId::new("public", "address_wrapper");
    let domain = ObjectId::new("public", "address_domain");
    let array = ObjectId::new("public", "address_wrapper[]");
    let owner = ObjectId::new("", "postgres");

    let mut pre_state = PreState::default();
    for (id, kind) in [
        (
            address.clone(),
            TypeKind::Composite {
                fields: vec![CompositeFieldState {
                    name: "city".into(),
                    data_type: "text".into(),
                    data_type_id: None,
                    collation: None,
                    collation_id: None,
                }],
            },
        ),
        (
            wrapper.clone(),
            TypeKind::Composite {
                fields: vec![CompositeFieldState {
                    name: "location".into(),
                    data_type: "address".into(),
                    data_type_id: Some(address.clone()),
                    collation: None,
                    collation_id: None,
                }],
            },
        ),
        (
            domain.clone(),
            TypeKind::Domain {
                base_type: "address_wrapper".into(),
                base_type_id: Some(wrapper.clone()),
                collation: None,
                collation_id: None,
                default: None,
                default_text: None,
                not_null: false,
                not_null_constraint: None,
                constraints: Default::default(),
            },
        ),
    ] {
        pre_state.types.insert(
            id.clone(),
            TypeState {
                id,
                generation: 0,
                owner: owner.clone(),
                kind,
            },
        );
    }

    for (name, column_type) in [
        ("customers", domain.clone()),
        ("suppliers", array),
        ("orders", wrapper),
    ] {
        let table = ObjectId::new("public", name);
        let mut relation = crate::_internal::model::relation::RelationState::new(
            table.clone(),
            owner.clone(),
            0,
            Some(10),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        let mut column = Column::migration_created("address_info".into(), None, true, None);
        column.type_id = Some(column_type);
        relation.columns.push(column);
        pre_state.relations.insert(table, relation);
    }

    assert_eq!(pre_state.relations_using_composite(&address).len(), 3);
}
