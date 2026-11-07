use super::*;

fn domain_state(id: &ObjectId, base: &ObjectId) -> TypeState {
    TypeState {
        id: id.clone(),
        generation: 0,
        owner: ObjectId::new("", "postgres"),
        kind: TypeKind::Domain {
            base_type: base.to_string(),
            base_type_id: Some(base.clone()),
            collation: None,
            collation_id: None,
            default: None,
            default_text: None,
            not_null: false,
            not_null_constraint: None,
            constraints: Default::default(),
        },
    }
}

#[test]
fn domain_closure_follows_chains_and_branches_exactly_once() {
    let int_type = ObjectId::new("pg_catalog", "int4");
    let first = ObjectId::new("public", "first");
    let second = ObjectId::new("public", "second");
    let third = ObjectId::new("public", "third");
    let branch = ObjectId::new("public", "branch");
    let dropped = ObjectId::new("public", "dropped");
    let unrelated = ObjectId::new("public", "unrelated");

    let mut state = AnalysisState::new(DbCache::new());
    state.local.types.insert(
        first.clone(),
        TypeOverlay::Present(domain_state(&first, &int_type)),
    );
    state.local.types.insert(
        second.clone(),
        TypeOverlay::Present(domain_state(&second, &first)),
    );
    state.local.types.insert(
        third.clone(),
        TypeOverlay::Present(domain_state(&third, &second)),
    );
    state.local.types.insert(
        branch.clone(),
        TypeOverlay::Present(domain_state(&branch, &first)),
    );
    state
        .local
        .types
        .insert(dropped.clone(), TypeOverlay::Dropped);
    state.local.types.insert(
        unrelated.clone(),
        TypeOverlay::Present(domain_state(&unrelated, &int_type)),
    );

    assert_eq!(
        state.domain_closure(&first),
        HashSet::from([first.clone(), second.clone(), third.clone(), branch])
    );
    assert_eq!(state.domain_closure(&third), HashSet::from([third]));
}

#[test]
fn domain_closure_survives_a_cyclic_domain_chain() {
    let first = ObjectId::new("public", "first");
    let second = ObjectId::new("public", "second");

    let mut state = AnalysisState::new(DbCache::new());
    state.local.types.insert(
        first.clone(),
        TypeOverlay::Present(domain_state(&first, &second)),
    );
    state.local.types.insert(
        second.clone(),
        TypeOverlay::Present(domain_state(&second, &first)),
    );

    assert_eq!(state.domain_closure(&first), HashSet::from([first, second]));
}
