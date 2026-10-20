use super::*;
use crate::_internal::model::index::{IndexDefinition, IndexPredicate, index_keys};

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
