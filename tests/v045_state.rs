mod common;

use common::{object_id, setup_engine};
use safe_migrate::_internal::analysis::facts::{PublicationObjectFact, PublicationScope};
use safe_migrate::_internal::analysis::graph::DependencyKind;
use safe_migrate::_internal::db::cache::{DbCache, IndexCache};
use safe_migrate::_internal::model::relation::{Persistence, RelationKind, RelationState};
use safe_migrate::_internal::model::role::RoleState;
use safe_migrate::_internal::model::schema::{SchemaOverlay, SchemaState};
use safe_migrate::_internal::model::sequence::{SequenceKind, SequenceOverlay, SequenceState};
use safe_migrate::_internal::model::types::{TypeKind, TypeState};
use safe_migrate::api::AnalysisState;

fn cache_with_public_schema() -> DbCache {
    let mut cache = DbCache::new();
    cache.metadata.source_role = Some("owner".into());
    cache.metadata.source_session_role = Some("owner".into());
    let owner = object_id("", "owner");
    cache.roles.insert(
        owner.clone(),
        RoleState {
            id: owner.clone(),
            can_login: true,
            is_superuser: true,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );
    cache.schemas.insert(
        "public".into(),
        SchemaState {
            name: "public".into(),
            owner,
            generation: 0,
        },
    );
    cache
}

#[test]
fn cache_v5_hydrates_schema_sequence_and_ownership_edge() {
    let mut cache = cache_with_public_schema();
    let sequence_id = object_id("public", "t_id_seq");
    let table_id = object_id("public", "t");
    cache.insert_baseline(
        table_id.clone(),
        RelationState::new(
            table_id.clone(),
            object_id("", "owner"),
            0,
            Some(0),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );
    cache.sequences.insert(
        sequence_id.clone(),
        SequenceState {
            id: sequence_id.clone(),
            owner: object_id("", "owner"),
            owned_by: Some((table_id.clone(), "id".into())),
            kind: SequenceKind::SerialLike,
            generation: 0,
        },
    );

    let state = AnalysisState::new(cache);
    assert!(matches!(
        state.local.schemas.get("public"),
        Some(SchemaOverlay::Present(_))
    ));
    assert!(matches!(
        state.local.sequences.get(&sequence_id),
        Some(SequenceOverlay::Present(sequence)) if sequence.kind == SequenceKind::SerialLike
    ));
    assert!(state.local.graph.edges().iter().any(|edge| {
        edge.dependent == sequence_id
            && edge.referenced == table_id
            && matches!(
                &edge.kind,
                DependencyKind::SequenceOwnedBy { column } if column == "id"
            )
    }));
}

#[test]
fn schema_authorization_checks_authoritative_role_catalog() {
    let engine = setup_engine();
    let mut state = AnalysisState::new(cache_with_public_schema());
    let findings = engine
        .analyze("CREATE SCHEMA app AUTHORIZATION missing_role;", &mut state)
        .unwrap();

    assert!(findings.iter().any(|finding| {
        finding.rule_id == "chain-conflict" && finding.reason.contains("does not exist")
    }));
    assert!(!state.schema_is_present_for_test("app"));
}

#[test]
fn schema_rename_remaps_namespace_and_rolls_back_atomically() {
    let engine = setup_engine();
    let mut cache = cache_with_public_schema();
    let owner = object_id("", "owner");
    cache.schemas.insert(
        "schema_old".into(),
        SchemaState {
            name: "schema_old".into(),
            owner: owner.clone(),
            generation: 0,
        },
    );
    cache.schemas.insert(
        "schema_new".into(),
        SchemaState {
            name: "schema_new".into(),
            owner: owner.clone(),
            generation: 0,
        },
    );
    cache.metadata.schemas = Some(vec![
        "public".into(),
        "schema_old".into(),
        "schema_new".into(),
    ]);
    let table = object_id("schema_old", "t");
    cache.insert_baseline(
        table.clone(),
        RelationState::new(
            table.clone(),
            owner.clone(),
            0,
            Some(0),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );
    let ty = object_id("schema_old", "mood");
    cache.types.insert(
        ty.clone(),
        TypeState {
            id: ty,
            generation: 0,
            kind: TypeKind::Enum {
                variants: vec!["ok".into()],
            },
        },
    );
    let sequence = object_id("schema_old", "t_id_seq");
    cache.sequences.insert(
        sequence.clone(),
        SequenceState {
            id: sequence,
            owner,
            owned_by: Some((table.clone(), "id".into())),
            kind: SequenceKind::Owned,
            generation: 0,
        },
    );
    cache.search_path = vec!["schema_old".into(), "public".into()];
    cache.metadata.source_search_path = Some(vec!["schema_old".into(), "public".into()]);
    let mut state = AnalysisState::new(cache);

    engine
        .analyze(
            "CREATE PUBLICATION app_publication FOR TABLE schema_old.t;",
            &mut state,
        )
        .unwrap();
    // Make the target a locally authoritative tombstone. A scoped baseline
    // cannot prove that an entirely unseen schema name is absent.
    engine
        .analyze("DROP SCHEMA schema_new CASCADE;", &mut state)
        .unwrap();

    let rename_findings = engine
        .analyze(
            "BEGIN; ALTER SCHEMA schema_old RENAME TO schema_new;",
            &mut state,
        )
        .unwrap();
    assert!(
        state.relation_is_present(&object_id("schema_new", "t")),
        "relations after rename: {:?}; findings: {:?}",
        state.local.relations.keys().collect::<Vec<_>>(),
        rename_findings
    );
    assert!(
        state
            .local
            .types
            .contains_key(&object_id("schema_new", "mood"))
    );
    assert!(
        state
            .local
            .sequences
            .contains_key(&object_id("schema_new", "t_id_seq"))
    );
    assert!(
        state
            .baseline_relations
            .contains(&object_id("schema_new", "t"))
    );
    assert_eq!(state.local.search_path_template, ["schema_old", "public"]);
    assert_eq!(state.local.search_path, ["public"]);
    assert!(matches!(
        state.local.publications.get("app_publication"),
        Some(safe_migrate::_internal::model::replication::PublicationOverlay::Present(publication))
            if matches!(
                &publication.scope,
                PublicationScope::Explicit(objects)
                    if matches!(
                        objects.first(),
                        Some(PublicationObjectFact::Table { name, .. })
                            if name.schema.as_ref().is_some_and(|schema| schema.resolve() == "schema_new")
                    )
            )
    ));

    engine.analyze("ROLLBACK;", &mut state).unwrap();
    assert!(state.relation_is_present(&object_id("schema_old", "t")));
    assert!(
        !state
            .local
            .relations
            .contains_key(&object_id("schema_new", "t"))
    );
    assert!(
        state
            .local
            .sequences
            .contains_key(&object_id("schema_old", "t_id_seq"))
    );
    assert_eq!(state.local.search_path, ["schema_old", "public"]);
    assert_eq!(
        state.baseline_schemas.as_ref(),
        Some(&std::collections::HashSet::from([
            "public".to_string(),
            "schema_old".to_string(),
            "schema_new".to_string(),
        ])),
        "rollback must restore authoritative schema scope as well as local objects"
    );
    assert!(matches!(
        state.local.publications.get("app_publication"),
        Some(safe_migrate::_internal::model::replication::PublicationOverlay::Present(publication))
            if matches!(
                &publication.scope,
                PublicationScope::Explicit(objects)
                    if matches!(
                        objects.first(),
                        Some(PublicationObjectFact::Table { name, .. })
                            if name.schema.as_ref().is_some_and(|schema| schema.resolve() == "schema_old")
                    )
            )
    ));

    engine
        .analyze("DROP SCHEMA schema_old CASCADE;", &mut state)
        .unwrap();
    assert!(matches!(
        state.local.publications.get("app_publication"),
        Some(safe_migrate::_internal::model::replication::PublicationOverlay::Present(publication))
            if matches!(
                &publication.scope,
                PublicationScope::Explicit(objects) if objects.is_empty()
            )
    ));
}

#[test]
fn table_set_schema_moves_the_relation_and_preserves_baseline_origin() {
    let engine = setup_engine();
    let mut cache = cache_with_public_schema();
    let owner = object_id("", "owner");
    cache.schemas.insert(
        "app".into(),
        SchemaState {
            name: "app".into(),
            owner: owner.clone(),
            generation: 0,
        },
    );
    let old_id = object_id("public", "accounts");
    cache.insert_baseline(
        old_id.clone(),
        RelationState::new(
            old_id.clone(),
            owner,
            0,
            Some(0),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        ),
    );
    let sequence_id = object_id("public", "accounts_id_seq");
    cache.sequences.insert(
        sequence_id.clone(),
        SequenceState {
            id: sequence_id.clone(),
            owner: object_id("", "owner"),
            owned_by: Some((old_id.clone(), "id".into())),
            kind: SequenceKind::SerialLike,
            generation: 0,
        },
    );
    let index_id = object_id("public", "accounts_id_idx");
    cache.indexes.push(IndexCache {
        index_id: index_id.clone(),
        table_id: old_id.clone(),
        using_method: "btree".into(),
        key_columns: vec!["id".into()],
        included_columns: Vec::new(),
        dependency_columns: vec!["id".into()],
        dependency_columns_known: true,
        has_expression_keys: false,
        has_predicate: false,
        is_unique: false,
        is_valid: true,
        is_ready: true,
        is_live: true,
        has_default_sort_order: true,
        has_default_opclasses: true,
        has_default_collations: true,
    });
    let mut state = AnalysisState::new(cache);

    engine
        .analyze("ALTER TABLE public.accounts SET SCHEMA app;", &mut state)
        .unwrap();

    let new_id = object_id("app", "accounts");
    assert!(state.relation_is_present(&new_id));
    assert!(!state.relation_is_present(&old_id));
    assert!(state.baseline_relations.contains(&new_id));
    assert!(!state.baseline_relations.contains(&old_id));

    let new_sequence_id = object_id("app", "accounts_id_seq");
    assert!(matches!(
        state.local.sequences.get(&new_sequence_id),
        Some(SequenceOverlay::Present(sequence))
            if sequence.id == new_sequence_id
                && sequence.owned_by == Some((new_id.clone(), "id".into()))
    ));
    assert!(!state.local.sequences.contains_key(&sequence_id));
    assert!(state.baseline_sequences.contains(&new_sequence_id));
    assert!(!state.baseline_sequences.contains(&sequence_id));

    let new_index_id = object_id("app", "accounts_id_idx");
    assert!(!state.local.graph.edges().iter().any(|edge| {
        edge.dependent == index_id && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
    }));
    assert!(state.local.graph.edges().iter().any(|edge| {
        edge.dependent == new_index_id
            && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
    }));
    assert!(state.baseline_indexes.contains(&new_index_id));
    assert!(!state.baseline_indexes.contains(&index_id));
    assert!(state.local.graph.edges().iter().any(|edge| {
        edge.dependent == new_index_id
            && edge.referenced == new_id
            && matches!(edge.kind, DependencyKind::IndexOnRelation { .. })
    }));
}

#[test]
fn serial_and_identity_columns_create_distinct_owned_sequences() {
    let engine = setup_engine();
    let mut state = AnalysisState::new(cache_with_public_schema());
    engine
        .analyze(
            "CREATE TABLE accounts (
                id serial,
                external_id bigint GENERATED ALWAYS AS IDENTITY
             );",
            &mut state,
        )
        .unwrap();

    let serial_id = object_id("public", "accounts_id_seq");
    let identity_id = object_id("public", "accounts_external_id_seq");
    assert!(matches!(
        state.local.sequences.get(&serial_id),
        Some(SequenceOverlay::Present(sequence))
            if sequence.kind == SequenceKind::SerialLike
                && sequence.owned_by == Some((object_id("public", "accounts"), "id".into()))
    ));
    assert!(matches!(
        state.local.sequences.get(&identity_id),
        Some(SequenceOverlay::Present(sequence)) if sequence.kind == SequenceKind::Identity
    ));

    engine
        .analyze(
            "ALTER TABLE accounts RENAME COLUMN id TO account_id;",
            &mut state,
        )
        .unwrap();
    assert!(state.local.sequences.contains_key(&serial_id));
    assert!(matches!(
        state.local.sequences.get(&serial_id),
        Some(SequenceOverlay::Present(sequence))
            if sequence.owned_by == Some((object_id("public", "accounts"), "account_id".into()))
    ));

    engine
        .analyze("ALTER TABLE accounts DROP COLUMN external_id;", &mut state)
        .unwrap();
    assert!(matches!(
        state.local.sequences.get(&identity_id),
        Some(SequenceOverlay::Dropped)
    ));
}

#[test]
fn implicit_sequence_collision_uses_postgres_suffix() {
    let engine = setup_engine();
    let mut state = AnalysisState::new(cache_with_public_schema());
    engine
        .analyze(
            "CREATE SEQUENCE accounts_id_seq;
             CREATE TABLE accounts (id serial);",
            &mut state,
        )
        .unwrap();
    assert!(
        state
            .local
            .sequences
            .contains_key(&object_id("public", "accounts_id_seq1"))
    );
}

#[test]
fn sequence_ownership_move_drop_and_rollback_follow_dependency_rules() {
    let engine = setup_engine();
    let mut cache = cache_with_public_schema();
    cache.schemas.insert(
        "archive".into(),
        SchemaState {
            name: "archive".into(),
            owner: object_id("", "owner"),
            generation: 0,
        },
    );
    let mut state = AnalysisState::new(cache);
    engine
        .analyze(
            "CREATE TABLE events (id integer, serial_id serial,
                identity_id bigint GENERATED ALWAYS AS IDENTITY);
             CREATE SEQUENCE event_cursor;
             ALTER SEQUENCE event_cursor OWNED BY events.id;",
            &mut state,
        )
        .unwrap();

    let cursor = object_id("public", "event_cursor");
    assert!(matches!(
        state.local.sequences.get(&cursor),
        Some(SequenceOverlay::Present(sequence))
            if sequence.kind == SequenceKind::Owned
                && sequence.owned_by == Some((object_id("public", "events"), "id".into()))
    ));

    engine
        .analyze(
            "BEGIN; ALTER SEQUENCE event_cursor RENAME TO renamed_cursor; ROLLBACK;",
            &mut state,
        )
        .unwrap();
    assert!(matches!(
        state.local.sequences.get(&cursor),
        Some(SequenceOverlay::Present(_))
    ));
    assert!(
        !state
            .local
            .sequences
            .contains_key(&object_id("public", "renamed_cursor"))
    );

    let move_findings = engine
        .analyze(
            "ALTER SEQUENCE event_cursor SET SCHEMA archive;",
            &mut state,
        )
        .unwrap();
    assert!(move_findings.iter().any(|finding| {
        finding.rule_id == "chain-conflict" && finding.reason.contains("same schema")
    }));
    engine
        .analyze(
            "ALTER SEQUENCE event_cursor OWNED BY NONE;
             ALTER SEQUENCE event_cursor SET SCHEMA archive;",
            &mut state,
        )
        .unwrap();
    assert!(matches!(
        state
            .local
            .sequences
            .get(&object_id("archive", "event_cursor")),
        Some(SequenceOverlay::Present(sequence)) if sequence.kind == SequenceKind::Standalone
    ));

    let serial_id = object_id("public", "events_serial_id_seq");
    let restrict_findings = engine
        .analyze("DROP SEQUENCE events_serial_id_seq;", &mut state)
        .unwrap();
    assert!(restrict_findings.iter().any(|finding| {
        finding.rule_id == "chain-conflict" && finding.reason.contains("dependent defaults")
    }));
    assert!(matches!(
        state.local.sequences.get(&serial_id),
        Some(SequenceOverlay::Present(_))
    ));
    engine
        .analyze("DROP SEQUENCE events_serial_id_seq CASCADE;", &mut state)
        .unwrap();
    assert!(matches!(
        state.local.sequences.get(&serial_id),
        Some(SequenceOverlay::Dropped)
    ));

    let identity_id = object_id("public", "events_identity_id_seq");
    let identity_findings = engine
        .analyze("DROP SEQUENCE events_identity_id_seq CASCADE;", &mut state)
        .unwrap();
    assert!(identity_findings.iter().any(|finding| {
        finding.rule_id == "chain-conflict" && finding.reason.contains("identity sequence")
    }));
    assert!(matches!(
        state.local.sequences.get(&identity_id),
        Some(SequenceOverlay::Present(_))
    ));
}

// Keep test-only schema inspection out of the public production API surface.
trait SchemaTestExt {
    fn schema_is_present_for_test(&self, name: &str) -> bool;
}

impl SchemaTestExt for AnalysisState {
    fn schema_is_present_for_test(&self, name: &str) -> bool {
        matches!(
            self.local.schemas.get(name),
            Some(SchemaOverlay::Present(_))
        )
    }
}
