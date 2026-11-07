use super::*;
use crate::_internal::model::column::Column;
use crate::_internal::model::index::{IndexDefinition, IndexPredicate, index_keys};
use crate::_internal::model::relation::RelationState;
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
    state.capture_pre_state_into(&mut reused, &PreStateReadSet::full());
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
    state.capture_pre_state_into(&mut reused, &PreStateReadSet::full());
    assert_eq!(reused, state.capture_pre_state());
    assert_eq!(reused.relations[&table_id].estimated_rows, Some(2));
    assert_eq!(reused.indexes.len(), 1);

    state
        .local
        .relations
        .insert(table_id.clone(), RelationOverlay::Dropped);
    state.local.graph.replace_edges(Vec::new());
    state.capture_pre_state_into(&mut reused, &PreStateReadSet::full());
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

#[test]
fn selective_capture_keeps_only_the_requested_relations() {
    let mut state = AnalysisState::new(DbCache::new());
    let owner = ObjectId::new("public", "postgres");
    for name in ["alpha", "beta", "gamma"] {
        let id = ObjectId::new("public", name);
        state.local.relations.insert(
            id.clone(),
            RelationOverlay::Present(RelationState::new(
                id,
                owner.clone(),
                0,
                Some(10),
                RelationKind::Table,
                Persistence::Permanent,
                0,
            )),
        );
    }
    let alpha = ObjectId::new("public", "alpha");
    let beta = ObjectId::new("public", "beta");
    let gamma = ObjectId::new("public", "gamma");
    let mut reads = PreStateReadSet::none();
    reads.relations = ReadScope::selected([alpha.clone(), beta.clone()]);

    let mut pre_state = PreState::default();
    state.capture_pre_state_into(&mut pre_state, &reads);
    assert_eq!(
        pre_state.relations.keys().cloned().collect::<HashSet<_>>(),
        HashSet::from([alpha.clone(), beta.clone()])
    );

    reads.relations = ReadScope::selected([alpha.clone()]);
    state.capture_pre_state_into(&mut pre_state, &reads);
    assert_eq!(
        pre_state.relations.keys().cloned().collect::<HashSet<_>>(),
        HashSet::from([alpha.clone()])
    );

    reads.relations = ReadScope::None;
    state.capture_pre_state_into(&mut pre_state, &reads);
    assert!(pre_state.relations.is_empty());

    reads.relations = ReadScope::All;
    state.capture_pre_state_into(&mut pre_state, &reads);
    assert_eq!(pre_state.relations.len(), 3);
    assert!(pre_state.relations.contains_key(&gamma));
}

#[test]
fn selective_capture_filters_index_edges_and_baseline_constraints() {
    let mut state = AnalysisState::new(DbCache::new());
    let first_table = ObjectId::new("public", "first_table");
    let second_table = ObjectId::new("public", "second_table");
    let first_index = ObjectId::new("public", "first_idx");
    let second_index = ObjectId::new("public", "second_idx");
    for (table, index) in [(&first_table, &first_index), (&second_table, &second_index)] {
        state.local.graph.add_edge(DependencyEdge::new(
            index.clone(),
            table.clone(),
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
    }
    let keep_constraint = (first_table.clone(), "first_fk".to_string());
    let drop_constraint = (second_table, "second_fk".to_string());
    state.baseline_foreign_keys.insert(keep_constraint.clone());
    state.baseline_foreign_keys.insert(drop_constraint);

    let mut reads = PreStateReadSet::none();
    reads.indexes = ReadScope::selected([first_index.clone()]);
    reads.baseline_foreign_keys = ReadScope::selected([keep_constraint.clone()]);

    let mut pre_state = PreState::default();
    state.capture_pre_state_into(&mut pre_state, &reads);
    assert_eq!(pre_state.indexes.len(), 1);
    assert_eq!(pre_state.indexes[0].dependent, first_index);
    assert_eq!(
        pre_state.baseline_foreign_keys,
        HashSet::from([keep_constraint])
    );

    reads.indexes = ReadScope::None;
    reads.baseline_foreign_keys = ReadScope::None;
    state.capture_pre_state_into(&mut pre_state, &reads);
    assert!(pre_state.indexes.is_empty());
    assert!(pre_state.baseline_foreign_keys.is_empty());
}
