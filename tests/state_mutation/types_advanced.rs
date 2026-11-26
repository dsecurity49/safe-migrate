use super::*;

#[test]
fn rename_type_remaps_only_the_resolved_schema_and_preserves_quoted_identity() {
    let engine = setup_engine();
    let mut state = setup_state();
    let violations = engine
            .analyze(
                "CREATE SCHEMA other;
                 CREATE TYPE public.mood AS ENUM ('sad');
                 CREATE TYPE other.mood AS ENUM ('happy');
                 SET search_path TO other, public;
                 CREATE TABLE other_entries (status mood);
                 CREATE TYPE public.\"Mood\" AS ENUM ('calm');
                 CREATE TABLE public.quoted_entries (status public.\"Mood\");
                 CREATE FUNCTION quoted_mood(value public.\"Mood\") RETURNS public.\"Mood\" LANGUAGE sql AS $$ SELECT value $$;
                 ALTER TYPE public.mood RENAME TO emotion;
                 ALTER TYPE public.\"Mood\" RENAME TO \"Emotion\";",
                &mut state,
            )
            .unwrap();

    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict")
    );
    let RelationOverlay::Present(other_entries) = state
        .get_relation(&object_id("other", "other_entries"))
        .unwrap()
    else {
        panic!("other_entries table missing");
    };
    assert_eq!(
        other_entries
            .get_column("status")
            .unwrap()
            .data_type
            .as_deref(),
        Some("mood")
    );
    assert_eq!(
        other_entries.get_column("status").unwrap().type_id,
        Some(object_id("other", "mood"))
    );
    let RelationOverlay::Present(quoted_entries) = state
        .get_relation(&object_id("public", "quoted_entries"))
        .unwrap()
    else {
        panic!("quoted_entries table missing");
    };
    assert_eq!(
        quoted_entries
            .get_column("status")
            .unwrap()
            .data_type
            .as_deref(),
        Some("public.\"Emotion\"")
    );
    assert_eq!(
        quoted_entries.get_column("status").unwrap().type_id,
        Some(object_id("public", "Emotion"))
    );
    assert!(
        state
            .local
            .types
            .contains_key(&object_id("public", "emotion"))
    );
    assert!(state.local.types.contains_key(&object_id("other", "mood")));
    assert!(
        state
            .local
            .types
            .contains_key(&object_id("public", "Emotion"))
    );
    let Some(FunctionOverlay::Present(function)) = state
        .local
        .functions
        .get(&object_id("other", "quoted_mood(public.\"Emotion\")"))
    else {
        panic!("quoted remapped function missing");
    };
    assert_eq!(function.return_type, "public.\"Emotion\"");
}

#[test]
fn rename_type_updates_columns_added_or_retyped_later_in_the_chain() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TYPE mood AS ENUM ('sad');
                 CREATE TABLE entries (status text);
                 ALTER TABLE entries ALTER COLUMN status TYPE mood;
                 ALTER TABLE entries ADD COLUMN secondary mood[];
                 ALTER TYPE mood RENAME TO emotion;",
            &mut state,
        )
        .unwrap();

    let RelationOverlay::Present(relation) =
        state.get_relation(&object_id("public", "entries")).unwrap()
    else {
        panic!("entries table missing");
    };
    assert_eq!(
        relation.get_column("status").unwrap().data_type.as_deref(),
        Some("emotion")
    );
    assert_eq!(
        relation
            .get_column("secondary")
            .unwrap()
            .data_type
            .as_deref(),
        Some("emotion[]")
    );
}

#[test]
fn alter_type_set_schema_updates_identity_and_rolls_back() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "CREATE SCHEMA app;
                 CREATE TYPE mood AS ENUM ('sad');
                 BEGIN;
                 ALTER TYPE mood SET SCHEMA app;",
            &mut state,
        )
        .unwrap();

    assert!(!state.local.types.contains_key(&object_id("public", "mood")));
    assert!(matches!(
        state.local.types.get(&object_id("app", "mood")),
        Some(TypeOverlay::Present(_))
    ));

    engine.analyze("ROLLBACK;", &mut state).unwrap();
    assert!(matches!(
        state.local.types.get(&object_id("public", "mood")),
        Some(TypeOverlay::Present(_))
    ));
    assert!(!state.local.types.contains_key(&object_id("app", "mood")));
}

#[test]
fn alter_type_set_schema_rejects_missing_schema_and_existing_target() {
    let engine = setup_engine();
    let mut state = setup_state();

    let violations = engine
        .analyze(
            "CREATE TYPE missing_target AS ENUM ('value');
                 ALTER TYPE missing_target SET SCHEMA missing_schema;
                 CREATE SCHEMA app;
                 CREATE TYPE source AS ENUM ('value');
                 CREATE TYPE app.source AS ENUM ('value');
                 ALTER TYPE source SET SCHEMA app;",
            &mut state,
        )
        .unwrap();

    assert!(violations.iter().any(|violation| {
        violation.rule_id == "chain-conflict"
            && violation.reason.contains("schema 'missing_schema'")
    }));
    assert!(violations.iter().any(|violation| {
        violation.rule_id == "chain-conflict" && violation.reason.contains("app.source")
    }));
}

#[test]
fn alter_type_set_schema_remaps_modeled_dependent_references() {
    let engine = setup_engine();
    let mut state = setup_state();

    let violations = engine
            .analyze(
                "CREATE SCHEMA app;
                 CREATE TYPE mood AS ENUM ('sad');
                 CREATE TABLE entries (status mood);
                 CREATE DOMAIN mood_alias AS mood;
                 CREATE FUNCTION accepts_mood(value mood) RETURNS mood LANGUAGE sql AS $$ SELECT value $$;
                 ALTER TYPE mood SET SCHEMA app;",
                &mut state,
            )
            .unwrap();

    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict")
    );
    assert!(!state.local.types.contains_key(&object_id("public", "mood")));
    assert!(matches!(
        state.local.types.get(&object_id("app", "mood")),
        Some(TypeOverlay::Present(_))
    ));
    let RelationOverlay::Present(relation) =
        state.get_relation(&object_id("public", "entries")).unwrap()
    else {
        panic!("entries table missing");
    };
    assert_eq!(
        relation.get_column("status").unwrap().data_type.as_deref(),
        Some("app.mood")
    );
    let Some(TypeOverlay::Present(TypeState {
        kind: TypeKind::Domain { base_type, .. },
        ..
    })) = state.local.types.get(&object_id("public", "mood_alias"))
    else {
        panic!("domain missing");
    };
    assert_eq!(base_type, "app.mood");
    let Some(FunctionOverlay::Present(function)) = state
        .local
        .functions
        .get(&object_id("public", "accepts_mood(app.mood)"))
    else {
        panic!("remapped function missing");
    };
    assert_eq!(function.return_type, "app.mood");
}

#[test]
fn enum_value_rename_obeys_cached_explicit_and_default_search_path_order() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.search_path = vec!["sm_core".into(), "public".into()];
    for schema in ["sm_core", "public"] {
        let id = object_id(schema, "mood");
        cache.types.insert(
            id.clone(),
            TypeState {
                id,
                generation: 0,
                owner: object_id("", "postgres"),
                kind: TypeKind::Enum {
                    variants: vec!["old".into(), format!("{schema}_only")],
                },
            },
        );
    }
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    engine
        .analyze(
            "ALTER TYPE mood RENAME VALUE 'old' TO 'core_new';
                 SET search_path TO public, sm_core;
                 ALTER TYPE mood RENAME VALUE 'old' TO 'public_new';
                 SET search_path TO DEFAULT;
                 ALTER TYPE mood RENAME VALUE 'core_new' TO 'core_final';",
            &mut state,
        )
        .unwrap();

    let variants = |schema: &str| {
        let Some(TypeOverlay::Present(type_state)) =
            state.local.types.get(&object_id(schema, "mood"))
        else {
            panic!("{schema}.mood missing");
        };
        let TypeKind::Enum { variants } = &type_state.kind else {
            panic!("{schema}.mood is not an enum");
        };
        variants.clone()
    };
    assert_eq!(variants("sm_core"), ["core_final", "sm_core_only"]);
    assert_eq!(variants("public"), ["public_new", "public_only"]);
    assert_eq!(state.search_path_names(), ["sm_core", "public"]);
}

#[test]
fn enum_value_rename_expands_user_search_path_from_v4_role_provenance() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    cache.metadata.source_role = Some("app_user".into());
    for schema in ["app_user", "public"] {
        cache.schemas.insert(
            schema.to_string(),
            SchemaState {
                name: schema.to_string(),
                owner: object_id("", "postgres"),
                generation: 0,
            },
        );
        let id = object_id(schema, "mood");
        cache.types.insert(
            id.clone(),
            TypeState {
                id,
                generation: 0,
                owner: object_id("", "postgres"),
                kind: TypeKind::Enum {
                    variants: vec!["old".into()],
                },
            },
        );
    }
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    engine
        .analyze(
            "SET search_path TO \"$user\", public;
                 ALTER TYPE mood RENAME VALUE 'old' TO 'new';",
            &mut state,
        )
        .unwrap();

    assert_eq!(state.local.current_role, "app_user");
    assert!(state.local.current_role_known);
    assert_eq!(state.search_path_names(), ["app_user", "public"]);
    assert_eq!(state.local.confidence, Confidence::Exact);
    let Some(TypeOverlay::Present(type_state)) =
        state.local.types.get(&object_id("app_user", "mood"))
    else {
        panic!("app_user.mood missing");
    };
    assert_eq!(
        type_state.kind,
        TypeKind::Enum {
            variants: vec!["new".into()]
        }
    );
}

#[test]
fn enum_value_rename_skips_dropped_type_tombstones_in_the_search_path() {
    let engine = setup_engine();
    let mut cache = crate::common::synced_cache();
    cache.search_path = vec!["first".into(), "second".into()];
    for schema in ["first", "second"] {
        let id = object_id(schema, "mood");
        cache.types.insert(
            id.clone(),
            TypeState {
                id,
                generation: 0,
                owner: object_id("", "postgres"),
                kind: TypeKind::Enum {
                    variants: vec!["old".into(), format!("{schema}_only")],
                },
            },
        );
    }
    let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

    let violations = engine
        .analyze(
            "DROP TYPE first.mood;
                 ALTER TYPE mood RENAME VALUE 'old' TO 'second_new';",
            &mut state,
        )
        .unwrap();

    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict")
    );
    assert!(matches!(
        state.local.types.get(&object_id("first", "mood")),
        Some(TypeOverlay::Dropped)
    ));
    let Some(TypeOverlay::Present(type_state)) =
        state.local.types.get(&object_id("second", "mood"))
    else {
        panic!("second.mood missing");
    };
    assert_eq!(
        type_state.kind,
        TypeKind::Enum {
            variants: vec!["second_new".into(), "second_only".into()]
        }
    );
}

#[test]
fn enum_value_rename_reports_postgres_conflicts_without_mutating_state() {
    for (sql, expected_reason) in [
        (
            "ALTER TYPE mood RENAME VALUE 'missing' TO 'new';",
            "not an existing label",
        ),
        (
            "ALTER TYPE mood RENAME VALUE 'old' TO 'existing';",
            "already exists",
        ),
        (
            "ALTER TYPE mood RENAME VALUE 'old' TO 'old';",
            "already exists",
        ),
    ] {
        let engine = setup_engine();
        let mut cache = crate::common::synced_cache();
        let id = object_id("public", "mood");
        cache.types.insert(
            id.clone(),
            TypeState {
                id: id.clone(),
                generation: 0,
                owner: object_id("", "postgres"),
                kind: TypeKind::Enum {
                    variants: vec!["old".into(), "existing".into()],
                },
            },
        );
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);
        let violations = engine.analyze(sql, &mut state).unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict" && violation.reason.contains(expected_reason)
        }));
        assert_eq!(
            state.local.types.get(&id),
            Some(&TypeOverlay::Present(TypeState {
                id: id.clone(),
                generation: 0,
                owner: object_id("", "postgres"),
                kind: TypeKind::Enum {
                    variants: vec!["old".into(), "existing".into()]
                }
            }))
        );
    }
}

#[test]
fn enum_value_rename_rejects_missing_and_non_enum_types() {
    let engine = setup_engine();
    for (setup, rename, expected_reason) in [
        (
            "",
            "ALTER TYPE missing_type RENAME VALUE 'old' TO 'new';",
            "does not exist",
        ),
        (
            "CREATE DOMAIN not_enum AS text;",
            "ALTER TYPE not_enum RENAME VALUE 'old' TO 'new';",
            "is not an enum",
        ),
    ] {
        let mut state = setup_state();
        let sql = format!("{setup} {rename}");
        let violations = engine.analyze(&sql, &mut state).unwrap();
        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict" && violation.reason.contains(expected_reason)
        }));
    }
}

#[test]
fn enum_value_rename_rolls_back_with_the_transaction() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TYPE mood AS ENUM ('old', 'stable');
                 BEGIN;
                 ALTER TYPE mood RENAME VALUE 'old' TO 'temporary';
                 ROLLBACK;",
            &mut state,
        )
        .unwrap();

    let Some(TypeOverlay::Present(type_state)) =
        state.local.types.get(&object_id("public", "mood"))
    else {
        panic!("enum mood missing");
    };
    assert_eq!(
        type_state.kind,
        TypeKind::Enum {
            variants: vec!["old".into(), "stable".into()]
        }
    );
}

#[test]
fn test_state_alter_column_types() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
            .analyze(
                "CREATE TABLE t(id INT NOT NULL); ALTER TABLE t ALTER COLUMN id SET DATA TYPE text; ALTER TABLE t ALTER COLUMN id DROP NOT NULL; ALTER TABLE t ALTER COLUMN id SET DEFAULT 'x';",
                &mut state,
            )
            .unwrap();

    if let Some(RelationOverlay::Present(r)) = state.get_relation(&object_id("public", "t")) {
        let col = r.get_column("id").unwrap();
        assert_eq!(col.data_type.as_deref(), Some("text"));
        assert!(col.is_nullable);
        assert!(col.default.is_some());
    } else {
        panic!("relation should be present");
    }
}

#[test]
fn range_creation_produces_companion_constructors() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "CREATE TYPE score_span AS RANGE (subtype = integer);",
            &mut state,
        )
        .unwrap();

    let range_id = object_id("public", "score_span");
    let mr_id = object_id("public", "score_span_multirange");

    // Both range and multirange companion are present
    assert!(state.local.types.contains_key(&range_id));
    assert!(state.local.types.contains_key(&mr_id));

    if let Some(TypeOverlay::Present(r_state)) = state.local.types.get(&range_id) {
        if let TypeKind::Range { multirange, .. } = &r_state.kind {
            assert_eq!(multirange.as_ref(), Some(&mr_id));
        } else {
            panic!("expected Range type kind");
        }
    } else {
        panic!("score_span should be present");
    }

    if let Some(TypeOverlay::Present(mr_state)) = state.local.types.get(&mr_id) {
        if let TypeKind::Multirange { range } = &mr_state.kind {
            assert_eq!(range.as_ref(), Some(&range_id));
        } else {
            panic!("expected Multirange type kind");
        }
    } else {
        panic!("score_span_multirange should be present");
    }

    // Constructors are present in functions map with internal_type_owner
    let r_ctor2 = object_id("public", "score_span(integer,integer)");
    let r_ctor3 = object_id("public", "score_span(integer,integer,text)");
    let mr_ctor0 = object_id("public", "score_span_multirange()");
    let mr_ctor1 = object_id("public", "score_span_multirange(score_span)");
    let mr_ctor2 = object_id("public", "score_span_multirange(VARIADIC score_span[])");

    assert!(state.local.functions.contains_key(&r_ctor2));
    assert!(state.local.functions.contains_key(&r_ctor3));
    assert!(state.local.functions.contains_key(&mr_ctor0));
    assert!(state.local.functions.contains_key(&mr_ctor1));
    assert!(state.local.functions.contains_key(&mr_ctor2));

    // Direct drop of internal constructor is rejected
    let violations = engine
        .analyze(
            "DROP FUNCTION public.score_span(integer, integer);",
            &mut state,
        )
        .unwrap();
    assert!(violations.iter().any(|v| v.rule_id == "chain-conflict"));
}

#[test]
fn base_type_routine_options_are_dependencies_that_track_renames() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE FUNCTION public.base_in(cstring) RETURNS cstring
                 LANGUAGE sql IMMUTABLE AS 'SELECT $1';
             CREATE FUNCTION public.base_out(cstring) RETURNS cstring
                 LANGUAGE sql IMMUTABLE AS 'SELECT $1';
             CREATE TYPE public.base_type (
                 INPUT = public.base_in,
                 OUTPUT = public.base_out
             );",
            &mut state,
        )
        .unwrap();

    let base = object_id("public", "base_type");
    let input = object_id("public", "base_in(cstring)");
    let expected_input = input.to_string();
    match state.local.types.get(&base) {
        Some(TypeOverlay::Present(TypeState {
            kind: TypeKind::Base { options, .. },
            ..
        })) => {
            assert_eq!(options.input.as_deref(), Some(expected_input.as_str()));
        }
        other => panic!("expected base type, got {other:?}"),
    }

    let violations = engine
        .analyze("DROP FUNCTION public.base_in(cstring);", &mut state)
        .unwrap();
    assert!(
        violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"
                && violation.reason.contains("base type")),
        "{violations:#?}"
    );

    engine
        .analyze(
            "ALTER FUNCTION public.base_in(cstring) RENAME TO base_in_renamed;",
            &mut state,
        )
        .unwrap();
    let renamed = object_id("public", "base_in_renamed(cstring)");
    let expected_renamed = renamed.to_string();
    match state.local.types.get(&base) {
        Some(TypeOverlay::Present(TypeState {
            kind: TypeKind::Base { options, .. },
            ..
        })) => assert_eq!(options.input.as_deref(), Some(expected_renamed.as_str())),
        other => panic!("expected base type, got {other:?}"),
    }

    engine
        .analyze(
            "DROP FUNCTION public.base_in_renamed(cstring) CASCADE;",
            &mut state,
        )
        .unwrap();
    assert!(!matches!(
        state.local.types.get(&base),
        Some(TypeOverlay::Present(_))
    ));
}

#[test]
fn range_subtype_diff_is_a_routine_dependency_that_tracks_renames() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE FUNCTION public.diff(integer, integer) RETURNS double precision
                 LANGUAGE sql IMMUTABLE AS 'SELECT ($1 - $2)::double precision';
             CREATE TYPE public.r AS RANGE (subtype = integer, subtype_diff = public.diff);",
            &mut state,
        )
        .unwrap();

    let diff = object_id("public", "diff(integer,integer)");
    let range = object_id("public", "r");
    match state.local.types.get(&range) {
        Some(TypeOverlay::Present(TypeState {
            kind: TypeKind::Range {
                subtype_diff_id, ..
            },
            ..
        })) => assert_eq!(subtype_diff_id.as_ref(), Some(&diff)),
        other => panic!("expected range type, got {other:?}"),
    }

    let violations = engine
        .analyze("DROP FUNCTION public.diff(integer, integer);", &mut state)
        .unwrap();
    assert!(
        violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"
                && violation.reason.contains("range type")),
        "{violations:#?}"
    );
    assert!(matches!(
        state.local.types.get(&range),
        Some(TypeOverlay::Present(_))
    ));

    engine
        .analyze(
            "ALTER FUNCTION public.diff(integer, integer) RENAME TO diff2;",
            &mut state,
        )
        .unwrap();
    let renamed = object_id("public", "diff2(integer,integer)");
    match state.local.types.get(&range) {
        Some(TypeOverlay::Present(TypeState {
            kind: TypeKind::Range {
                subtype_diff_id, ..
            },
            ..
        })) => assert_eq!(subtype_diff_id.as_ref(), Some(&renamed)),
        other => panic!("expected range type, got {other:?}"),
    }

    let violations = engine
        .analyze("DROP FUNCTION public.diff2(integer, integer);", &mut state)
        .unwrap();
    assert!(
        violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "{violations:#?}"
    );

    engine
        .analyze(
            "CREATE TYPE public.my_int AS (val integer);
             CREATE FUNCTION public.diff_custom(public.my_int, public.my_int) RETURNS double precision
                 LANGUAGE sql IMMUTABLE AS 'SELECT 1.0';
             CREATE TYPE public.custom_range AS RANGE (subtype = public.my_int, subtype_diff = public.diff_custom);
             ALTER TYPE public.my_int RENAME TO my_int_renamed;",
            &mut state,
        )
        .unwrap();

    let renamed_func = object_id(
        "public",
        "diff_custom(public.my_int_renamed,public.my_int_renamed)",
    );
    let custom_range = object_id("public", "custom_range");
    match state.local.types.get(&custom_range) {
        Some(TypeOverlay::Present(TypeState {
            kind: TypeKind::Range {
                subtype_diff_id, ..
            },
            ..
        })) => assert_eq!(subtype_diff_id.as_ref(), Some(&renamed_func)),
        other => panic!("expected custom_range type, got {other:?}"),
    }

    let violations = engine
        .analyze(
            "DROP FUNCTION public.diff_custom(public.my_int_renamed, public.my_int_renamed);",
            &mut state,
        )
        .unwrap();
    assert!(
        violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "{violations:#?}"
    );
}

#[test]
fn explicit_multirange_name_is_respected_and_independent_rename_updates_links() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "CREATE TYPE custom_r AS RANGE (subtype = integer, multirange_type_name = custom_mr);",
            &mut state,
        )
        .unwrap();

    let range_id = object_id("public", "custom_r");
    let mr_id = object_id("public", "custom_mr");

    assert!(state.local.types.contains_key(&range_id));
    assert!(state.local.types.contains_key(&mr_id));

    // Rename the multirange independently
    engine
        .analyze(
            "ALTER TYPE custom_mr RENAME TO custom_mr_renamed;",
            &mut state,
        )
        .unwrap();

    let mr_renamed_id = object_id("public", "custom_mr_renamed");
    assert!(!state.local.types.contains_key(&mr_id));
    assert!(state.local.types.contains_key(&mr_renamed_id));

    // Check that range's multirange link was updated
    if let Some(TypeOverlay::Present(r_state)) = state.local.types.get(&range_id) {
        if let TypeKind::Range { multirange, .. } = &r_state.kind {
            assert_eq!(multirange.as_ref(), Some(&mr_renamed_id));
        } else {
            panic!("expected Range type kind");
        }
    }

    // Cascade drop of range drops the independently renamed multirange companion too!
    engine
        .analyze("DROP TYPE custom_r CASCADE;", &mut state)
        .unwrap();
    assert!(matches!(
        state.local.types.get(&range_id),
        Some(TypeOverlay::Dropped)
    ));
    assert!(matches!(
        state.local.types.get(&mr_renamed_id),
        Some(TypeOverlay::Dropped)
    ));
}

#[test]
fn range_drop_after_multirange_rename_does_not_require_cascade() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TYPE custom_r AS RANGE (subtype = integer, multirange_type_name = custom_mr);
             ALTER TYPE custom_mr RENAME TO custom_mr_renamed;",
            &mut state,
        )
        .unwrap();
    let violations = engine.analyze("DROP TYPE custom_r;", &mut state).unwrap();
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "{violations:#?}"
    );
    assert!(matches!(
        state.local.types.get(&object_id("public", "custom_r")),
        Some(TypeOverlay::Dropped)
    ));
    assert!(matches!(
        state
            .local
            .types
            .get(&object_id("public", "custom_mr_renamed")),
        Some(TypeOverlay::Dropped)
    ));
}

#[test]
fn dropping_a_multirange_without_cascade_is_blocked_by_its_range() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TYPE custom_r AS RANGE (subtype = integer, multirange_type_name = custom_mr);",
            &mut state,
        )
        .unwrap();
    let violations = engine.analyze("DROP TYPE custom_mr;", &mut state).unwrap();
    assert!(
        violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "{violations:#?}"
    );
    assert!(matches!(
        state.local.types.get(&object_id("public", "custom_mr")),
        Some(TypeOverlay::Present(_))
    ));
    assert!(matches!(
        state.local.types.get(&object_id("public", "custom_r")),
        Some(TypeOverlay::Present(_))
    ));
}

#[test]
fn composite_attribute_alterations_synchronize_typed_tables() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "CREATE TYPE item_t AS (a integer, b text);
             CREATE TABLE typed_items OF item_t;
             ALTER TYPE item_t RENAME TO item_t_renamed;
             ALTER TYPE item_t_renamed ADD ATTRIBUTE c boolean CASCADE;
             ALTER TYPE item_t_renamed RENAME ATTRIBUTE b TO b_renamed CASCADE;
             ALTER TYPE item_t_renamed DROP ATTRIBUTE a CASCADE;",
            &mut state,
        )
        .unwrap();

    let table_id = object_id("public", "typed_items");
    let RelationOverlay::Present(tbl) = state.local.relations.get(&table_id).unwrap() else {
        panic!("typed_items should be present");
    };

    assert_eq!(
        tbl.of_type.as_ref(),
        Some(&object_id("public", "item_t_renamed"))
    );
    assert!(!tbl.has_column("a"));
    assert!(tbl.has_column("b_renamed"));
    assert!(tbl.has_column("c"));

    let col_b = tbl.get_column("b_renamed").unwrap();
    assert_eq!(col_b.data_type.as_deref(), Some("text"));
    let col_c = tbl.get_column("c").unwrap();
    assert_eq!(col_c.data_type.as_deref(), Some("boolean"));
}

#[test]
fn base_type_option_changes_reject_immutable_and_invalid_physical_shape() {
    let engine = setup_engine();
    let mut state = setup_state();

    let violations = engine
        .analyze(
            "CREATE TYPE fixed_t (INTERNALLENGTH = 4, STORAGE = external);",
            &mut state,
        )
        .unwrap();
    assert!(
        violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"
                && violation
                    .reason
                    .contains("fixed-size types must have storage PLAIN")),
        "{violations:#?}"
    );
    assert!(
        !state
            .local
            .types
            .contains_key(&object_id("public", "fixed_t"))
    );

    let violations = engine
        .analyze(
            "CREATE TYPE invalid_storage_t (STORAGE = bogus);",
            &mut state,
        )
        .unwrap();
    assert!(
        violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"
                && violation
                    .reason
                    .contains("storage \"bogus\" not recognized")),
        "{violations:#?}"
    );
    assert!(
        !state
            .local
            .types
            .contains_key(&object_id("public", "invalid_storage_t"))
    );

    engine.analyze("CREATE TYPE shell_t;", &mut state).unwrap();
    let violations = engine
        .analyze("ALTER TYPE shell_t SET (STORAGE = external);", &mut state)
        .unwrap();
    assert!(
        violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"
                && violation.reason.contains("only a shell")),
        "{violations:#?}"
    );
    let shell = object_id("public", "shell_t");
    let Some(TypeOverlay::Present(TypeState {
        kind: TypeKind::Base { shell: true, .. },
        ..
    })) = state.local.types.get(&shell)
    else {
        panic!("shell_t should remain a shell");
    };

    let violations = engine
        .analyze(
            "CREATE TYPE shell_t (INTERNALLENGTH = 4, STORAGE = external);",
            &mut state,
        )
        .unwrap();
    assert!(
        violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"
                && violation
                    .reason
                    .contains("fixed-size types must have storage PLAIN")),
        "{violations:#?}"
    );
    let Some(TypeOverlay::Present(TypeState {
        kind: TypeKind::Base { shell: true, .. },
        ..
    })) = state.local.types.get(&shell)
    else {
        panic!("invalid completion must leave shell_t a shell");
    };

    engine
        .analyze(
            "CREATE TYPE shell_t (INPUT = shell_in, OUTPUT = shell_out, INTERNALLENGTH = VARIABLE);",
            &mut state,
        )
        .unwrap();
    let Some(TypeOverlay::Present(TypeState {
        kind: TypeKind::Base {
            shell: false,
            options,
        },
        ..
    })) = state.local.types.get(&shell)
    else {
        panic!("shell_t should be completed");
    };
    assert_eq!(options.input.as_deref(), Some("shell_in"));
    assert_eq!(options.output.as_deref(), Some("shell_out"));

    engine
        .analyze(
            "CREATE TYPE variable_t (INTERNALLENGTH = VARIABLE);",
            &mut state,
        )
        .unwrap();
    for statement in [
        "ALTER TYPE variable_t SET (INPUT = public.some_input);",
        "ALTER TYPE variable_t SET (INTERNALLENGTH = 8);",
        "ALTER TYPE variable_t SET (STORAGE = external);",
    ] {
        let violations = engine.analyze(statement, &mut state).unwrap();
        if statement.contains("STORAGE") {
            assert!(violations.is_empty(), "{violations:#?}");
        } else {
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.rule_id == "chain-conflict"
                        && violation.reason.contains("cannot be changed")),
                "{violations:#?}"
            );
        }
    }

    let variable = object_id("public", "variable_t");
    let Some(TypeOverlay::Present(TypeState {
        kind: TypeKind::Base { options, .. },
        ..
    })) = state.local.types.get(&variable)
    else {
        panic!("variable_t should be present");
    };
    assert_eq!(options.input, None);
    assert_eq!(
        options.internallength,
        Some(crate::_internal::model::types::BaseTypeLength::Variable)
    );
    assert_eq!(options.storage.as_deref(), Some("external"));
}

#[test]
fn base_type_shell_completion_and_options_work() {
    let engine = setup_engine();
    let mut state = setup_state();

    engine
        .analyze(
            "CREATE TYPE widget_t (INPUT = widget_in, OUTPUT = widget_out, INTERNALLENGTH = 16, PASSEDBYVALUE);",
            &mut state,
        )
        .unwrap();

    let widget_id = object_id("public", "widget_t");
    let Some(TypeOverlay::Present(type_state)) = state.local.types.get(&widget_id) else {
        panic!("widget_t should be present");
    };

    if let TypeKind::Base { options, shell } = &type_state.kind {
        assert!(!shell);
        assert_eq!(options.input.as_deref(), Some("widget_in"));
        assert_eq!(options.output.as_deref(), Some("widget_out"));
        assert_eq!(
            options.internallength,
            Some(crate::_internal::model::types::BaseTypeLength::Fixed(16))
        );
        assert_eq!(options.passed_by_value, Some(true));
    } else {
        panic!("expected Base type kind");
    }
}

#[test]
fn typed_table_attribute_add_and_rename_require_cascade() {
    let engine = setup_engine();
    for sql in [
        "ALTER TYPE item_t ADD ATTRIBUTE c boolean;",
        "ALTER TYPE item_t RENAME ATTRIBUTE b TO renamed_b;",
    ] {
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE TYPE item_t AS (a integer, b text);
                 CREATE TABLE typed_items OF item_t;",
                &mut state,
            )
            .unwrap();
        let findings = engine.analyze(sql, &mut state).unwrap();
        assert!(
            findings.iter().any(|finding| {
                finding.rule_id == "chain-conflict" && finding.reason.contains("typed table")
            }),
            "{sql} must require CASCADE: {findings:?}"
        );
        let TypeOverlay::Present(TypeState {
            kind: TypeKind::Composite { fields },
            ..
        }) = state
            .local
            .types
            .get(&object_id("public", "item_t"))
            .expect("item_t present")
        else {
            panic!("item_t should stay composite");
        };
        assert!(fields.iter().all(|field| field.name != "c"));
        assert!(fields.iter().any(|field| field.name == "b"));
    }
}

#[test]
fn schema_rename_remaps_type_and_routine_identity_links() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine.analyze("CREATE SCHEMA legacy;", &mut state).unwrap();

    let type_ids = [
        "domain_base",
        "domain_collation",
        "range_subtype",
        "range_multirange",
        "range_collation",
        "range_opclass",
        "range_canonical",
        "range_diff",
        "multirange_range",
        "composite_field",
        "composite_collation",
        "routine_arg",
        "routine_return",
        "routine_owner",
    ]
    .map(|name| object_id("legacy", name));

    state.local.types.insert(
        object_id("legacy", "d"),
        TypeOverlay::Present(TypeState {
            id: object_id("legacy", "d"),
            generation: 0,
            owner: object_id("", "postgres"),
            kind: TypeKind::Domain {
                base_type: "base".to_string(),
                base_type_id: Some(type_ids[0].clone()),
                collation: None,
                collation_id: Some(type_ids[1].clone()),
                default: None,
                default_text: None,
                not_null: false,
                not_null_constraint: None,
                constraints: Default::default(),
            },
        }),
    );
    state.local.types.insert(
        object_id("legacy", "r"),
        TypeOverlay::Present(TypeState {
            id: object_id("legacy", "r"),
            generation: 0,
            owner: object_id("", "postgres"),
            kind: TypeKind::Range {
                subtype: None,
                subtype_id: Some(type_ids[2].clone()),
                multirange: Some(type_ids[3].clone()),
                collation: None,
                collation_id: Some(type_ids[4].clone()),
                opclass: None,
                opclass_id: Some(type_ids[5].clone()),
                canonical: None,
                canonical_id: Some(type_ids[6].clone()),
                subtype_diff: None,
                subtype_diff_id: Some(type_ids[7].clone()),
            },
        }),
    );
    state.local.types.insert(
        object_id("legacy", "mr"),
        TypeOverlay::Present(TypeState {
            id: object_id("legacy", "mr"),
            generation: 0,
            owner: object_id("", "postgres"),
            kind: TypeKind::Multirange {
                range: Some(type_ids[8].clone()),
            },
        }),
    );
    state.local.types.insert(
        object_id("legacy", "c"),
        TypeOverlay::Present(TypeState {
            id: object_id("legacy", "c"),
            generation: 0,
            owner: object_id("", "postgres"),
            kind: TypeKind::Composite {
                fields: vec![safe_migrate::_internal::model::types::CompositeFieldState {
                    name: "f".to_string(),
                    data_type: "base".to_string(),
                    data_type_id: Some(type_ids[9].clone()),
                    collation: None,
                    collation_id: Some(type_ids[10].clone()),
                }],
            },
        }),
    );
    let routine_id = object_id("legacy", "f(integer)");
    let mut routine = FunctionState::with_inputs(
        routine_id.clone(),
        RoutineKind::Function,
        vec!["integer".to_string()],
    );
    routine.arg_type_ids = vec![Some(type_ids[11].clone())];
    routine.return_type_id = Some(type_ids[12].clone());
    routine.internal_type_owner = Some(type_ids[13].clone());
    state
        .local
        .functions
        .insert(routine_id, FunctionOverlay::Present(routine));

    let findings = engine
        .analyze("ALTER SCHEMA legacy RENAME TO modern;", &mut state)
        .unwrap();
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "{findings:?}"
    );

    let TypeOverlay::Present(TypeState {
        kind:
            TypeKind::Domain {
                base_type_id,
                collation_id,
                ..
            },
        ..
    }) = state
        .local
        .types
        .get(&object_id("modern", "d"))
        .expect("domain present")
    else {
        panic!("domain should be present");
    };
    assert_eq!(
        base_type_id.as_ref().map(|id| id.schema.as_str()),
        Some("modern")
    );
    assert_eq!(
        collation_id.as_ref().map(|id| id.schema.as_str()),
        Some("modern")
    );
    let TypeOverlay::Present(TypeState {
        kind:
            TypeKind::Range {
                subtype_id,
                multirange,
                collation_id,
                opclass_id,
                canonical_id,
                subtype_diff_id,
                ..
            },
        ..
    }) = state
        .local
        .types
        .get(&object_id("modern", "r"))
        .expect("range present")
    else {
        panic!("range should be present");
    };
    for id in [
        subtype_id,
        multirange,
        collation_id,
        opclass_id,
        canonical_id,
        subtype_diff_id,
    ]
    .into_iter()
    .flatten()
    {
        assert_eq!(id.schema, "modern", "{id} was not remapped");
    }
    let TypeOverlay::Present(TypeState {
        kind: TypeKind::Multirange { range },
        ..
    }) = state
        .local
        .types
        .get(&object_id("modern", "mr"))
        .expect("multirange present")
    else {
        panic!("multirange should be present");
    };
    assert_eq!(range.as_ref().map(|id| id.schema.as_str()), Some("modern"));
    let TypeOverlay::Present(TypeState {
        kind: TypeKind::Composite { fields },
        ..
    }) = state
        .local
        .types
        .get(&object_id("modern", "c"))
        .expect("composite present")
    else {
        panic!("composite should be present");
    };
    assert_eq!(
        fields[0].data_type_id.as_ref().map(|id| id.schema.as_str()),
        Some("modern")
    );
    assert_eq!(
        fields[0].collation_id.as_ref().map(|id| id.schema.as_str()),
        Some("modern")
    );
    let Some(FunctionOverlay::Present(routine)) = state
        .local
        .functions
        .get(&object_id("modern", "f(integer)"))
    else {
        panic!("routine should be present");
    };
    assert_eq!(
        routine.arg_type_ids[0]
            .as_ref()
            .map(|id| id.schema.as_str()),
        Some("modern")
    );
    assert_eq!(
        routine.return_type_id.as_ref().map(|id| id.schema.as_str()),
        Some("modern")
    );
    assert_eq!(
        routine
            .internal_type_owner
            .as_ref()
            .map(|id| id.schema.as_str()),
        Some("modern")
    );
}

#[test]
fn alter_type_owner_rejects_an_absent_role_with_a_complete_catalog() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    let owner = object_id("", "existing_owner");
    cache.roles.insert(
        owner.clone(),
        RoleState {
            id: owner.clone(),
            can_login: false,
            is_superuser: false,
            inherits: true,
            member_of: Vec::new(),
            can_administer_membership: Vec::new(),
            can_inherit_from: Vec::new(),
            can_set_role_to: Vec::new(),
        },
    );
    cache.metadata.source_role = Some("existing_owner".to_string());
    cache.metadata.source_session_role = Some("existing_owner".to_string());
    let mut state = AnalysisState::new(cache);

    engine
        .analyze("CREATE TYPE ownership_probe AS ENUM ('x');", &mut state)
        .unwrap();
    let findings = engine
        .analyze(
            "ALTER TYPE ownership_probe OWNER TO absent_owner;",
            &mut state,
        )
        .unwrap();

    assert!(
        findings.iter().any(|finding| {
            finding.rule_id == "chain-conflict"
                && finding
                    .reason
                    .contains("role 'absent_owner' does not exist")
        }),
        "{findings:?}"
    );
    let TypeOverlay::Present(probe) = state
        .local
        .types
        .get(&object_id("public", "ownership_probe"))
        .expect("ownership_probe present")
    else {
        panic!("ownership_probe should be present");
    };
    assert_eq!(probe.owner, owner);
}

#[test]
fn alter_type_owner_taints_when_the_role_catalog_is_incomplete() {
    let engine = setup_engine();
    let mut cache = synced_cache();
    cache.coverage = CatalogCoverage::for_families(
        SchemaCoverage::from_sync_scope(None),
        &CatalogFamily::ALL
            .iter()
            .copied()
            .filter(|family| *family != CatalogFamily::Roles)
            .collect::<Vec<_>>(),
    );
    let mut state = AnalysisState::new(cache);

    engine
        .analyze("CREATE TYPE ownership_probe AS ENUM ('x');", &mut state)
        .unwrap();
    let findings = engine
        .analyze(
            "ALTER TYPE ownership_probe OWNER TO unverified_owner;",
            &mut state,
        )
        .unwrap();

    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == "chain-conflict"),
        "{findings:?}"
    );
    assert_eq!(state.local.confidence, Confidence::Tainted);
    assert!(
        state
            .evidence()
            .iter()
            .any(|record| record.code == EvidenceCode::CatalogCoverageIncomplete)
    );
    let TypeOverlay::Present(probe) = state
        .local
        .types
        .get(&object_id("public", "ownership_probe"))
        .expect("ownership_probe present")
    else {
        panic!("ownership_probe should be present");
    };
    assert_eq!(probe.owner, object_id("", "unverified_owner"));
}

#[test]
fn dropping_composite_attribute_warns_of_data_loss_on_dependent_tables() {
    let engine = setup_engine();
    let mut state = setup_state();

    let violations = engine
        .analyze(
            "CREATE TYPE user_profile AS (username text, bio text);
             CREATE TABLE users (id int, profile user_profile);
             ALTER TYPE user_profile DROP ATTRIBUTE bio;",
            &mut state,
        )
        .unwrap();

    assert!(
        violations
            .iter()
            .any(|v| v.rule_id == "irreversible-migration"
                && v.object_name.starts_with("public.user_profile")
                && v.reason
                    .contains("Dropping attribute 'bio' from a composite type in use by tables")),
        "expected irreversible-migration rule on ALTER TYPE DROP ATTRIBUTE for table column: {violations:#?}"
    );
}

#[test]
fn range_type_routine_and_opclass_references_hydrate_from_baseline_cache() {
    let mut cache = crate::_internal::db::cache::DbCache::new();
    let diff_id = object_id("public", "my_diff(integer,integer)");
    cache.functions.insert(
        diff_id.clone(),
        crate::_internal::model::function::FunctionState {
            id: diff_id.clone(),
            arg_types: vec!["integer".into(), "integer".into()],
            arg_type_ids: vec![
                Some(object_id("pg_catalog", "int4")),
                Some(object_id("pg_catalog", "int4")),
            ],
            parameters: vec![],
            default_count: 0,
            return_type: "double precision".into(),
            return_type_id: Some(object_id("pg_catalog", "float8")),
            volatility: crate::_internal::model::function::Volatility::Immutable,
            language: "sql".into(),
            returns_set: false,
            routine_kind: crate::_internal::model::function::RoutineKind::Function,
            internal_type_owner: None,
            security: crate::_internal::model::function::SecurityMode::Invoker,
            aggregate: None,
        },
    );

    let range_id = object_id("public", "custom_range");
    let opclass_id = object_id("public", "custom_opclass");
    cache.opclasses = Some(
        crate::_internal::model::opclass::OpclassCatalogue::from_entries(vec![
            crate::_internal::model::opclass::OpclassEntry {
                name: "custom_opclass".into(),
                namespace: "public".into(),
                family: crate::_internal::model::index::ResolvedName {
                    schema: "public".into(),
                    name: "custom_family".into(),
                },
                intype: "int4".into(),
                aliases: vec!["integer".into()],
                method: "btree".into(),
                is_default: false,
            },
        ]),
    );
    cache.types.insert(
        range_id.clone(),
        TypeState {
            id: range_id.clone(),
            generation: 1,
            owner: object_id("", "postgres"),
            kind: TypeKind::Range {
                subtype: Some("integer".into()),
                subtype_id: None,
                multirange: None,
                collation: None,
                collation_id: None,
                opclass: Some("custom_opclass".into()),
                opclass_id: None,
                canonical: None,
                canonical_id: None,
                subtype_diff: Some("my_diff".into()),
                subtype_diff_id: None,
            },
        },
    );

    let state = AnalysisState::with_baseline(cache, true);
    let Some(TypeOverlay::Present(TypeState {
        kind:
            TypeKind::Range {
                opclass_id: hydrated_opclass_id,
                subtype_diff_id,
                ..
            },
        ..
    })) = state.local.types.get(&range_id)
    else {
        panic!("custom_range must be present");
    };

    assert_eq!(
        hydrated_opclass_id.as_ref(),
        Some(&opclass_id),
        "opclass_id must be hydrated from baseline cache"
    );
    assert_eq!(
        subtype_diff_id.as_ref(),
        Some(&diff_id),
        "subtype_diff_id must be hydrated from baseline cache"
    );
}

#[test]
fn alter_composite_attribute_type_rejects_direct_and_transitive_table_column_dependencies() {
    let engine = setup_engine();
    let mut state = setup_state();

    let direct = engine
        .analyze(
            "CREATE TYPE public.comp_in_use AS (x int, y text);
             CREATE TABLE public.holder (id int, payload public.comp_in_use);
             ALTER TYPE public.comp_in_use ALTER ATTRIBUTE x TYPE bigint;",
            &mut state,
        )
        .unwrap();
    assert!(
        direct.iter().any(|v| {
            v.rule_id == "chain-conflict"
                && v.reason.contains(
                    "cannot alter type \"comp_in_use\" because column \"holder.payload\" uses it",
                )
        }),
        "direct composite column dependency must reject ALTER ATTRIBUTE TYPE: {direct:?}"
    );

    let mut state2 = setup_state();
    let transitive = engine
        .analyze(
            "CREATE TYPE public.inner_c AS (x int);
             CREATE TYPE public.outer_c AS (inner_val public.inner_c);
             CREATE TABLE public.outer_holder (id int, payload public.outer_c[]);
             ALTER TYPE public.inner_c ALTER ATTRIBUTE x TYPE bigint CASCADE;",
            &mut state2,
        )
        .unwrap();
    assert!(
        transitive.iter().any(|v| {
            v.rule_id == "chain-conflict"
                && v.reason.contains(
                    "cannot alter type \"inner_c\" because column \"outer_holder.payload\" uses it",
                )
        }),
        "transitive composite/array column dependency must reject ALTER ATTRIBUTE TYPE even with CASCADE: {transitive:?}"
    );
}

#[test]
fn drop_attribute_if_exists_missing_is_a_noop_and_cascade_propagates_to_typed_table_dependents() {
    let engine = setup_engine();
    let mut state = setup_state();

    let noop_findings = engine
        .analyze(
            "CREATE TYPE public.comp_noop AS (x int, y text);
             CREATE TABLE public.comp_noop_holder (id int, payload public.comp_noop);
             ALTER TYPE public.comp_noop DROP ATTRIBUTE IF EXISTS missing_attr;",
            &mut state,
        )
        .unwrap();
    assert!(
        !noop_findings
            .iter()
            .any(|v| v.rule_id == "irreversible-migration"),
        "DROP ATTRIBUTE IF EXISTS on a missing attribute must be a NoOp and not fire irreversible-migration: {noop_findings:?}"
    );

    let mut state2 = setup_state();
    let cascade_findings = engine
        .analyze(
            "CREATE TYPE public.comp_casc AS (x int, y text);
             CREATE TABLE public.typed_casc OF public.comp_casc;
             CREATE INDEX typed_casc_x_idx ON public.typed_casc (x);
             ALTER TYPE public.comp_casc DROP ATTRIBUTE x CASCADE;
             DROP INDEX public.typed_casc_x_idx;",
            &mut state2,
        )
        .unwrap();
    assert!(
        cascade_findings
            .iter()
            .any(|v| { v.rule_id == "chain-conflict" && v.reason.contains("typed_casc_x_idx") }),
        "ALTER TYPE DROP ATTRIBUTE CASCADE must drop indexes depending on the typed-table column: {cascade_findings:?}"
    );
}

#[test]
fn schema_rename_remaps_typed_table_of_type_and_column_type_ids() {
    let engine = setup_engine();
    let mut state = setup_state();

    let findings = engine
        .analyze(
            "CREATE SCHEMA app;
             CREATE TYPE app.my_comp AS (x int, y text);
             CREATE TABLE app.typed_orders OF app.my_comp;
             CREATE TYPE app.status AS ENUM ('open', 'closed');
             CREATE TABLE app.orders (id int PRIMARY KEY, st app.status NOT NULL);
             ALTER SCHEMA app RENAME TO app_v2;
             ALTER TYPE app_v2.my_comp ADD ATTRIBUTE z int CASCADE;
             ALTER TABLE app_v2.typed_orders ALTER COLUMN z SET NOT NULL;
             DROP TYPE app_v2.status CASCADE;
             ALTER TABLE app_v2.orders DROP COLUMN st;",
            &mut state,
        )
        .unwrap();
    assert!(
        !findings.iter().any(|v| {
            v.rule_id == "chain-conflict" && v.reason.contains("column 'z' does not exist")
        }),
        "typed_orders.of_type must be remapped to app_v2.my_comp so ADD ATTRIBUTE z CASCADE reaches typed_orders: {findings:?}"
    );
    assert!(
        findings.iter().any(|v| {
            v.rule_id == "chain-conflict"
                && v.reason
                    .contains("column 'st' does not exist on relation 'app_v2.orders'")
        }),
        "orders.st.type_id must be remapped to app_v2.status so DROP TYPE CASCADE drops column st: {findings:?}"
    );
}

#[test]
fn create_and_drop_cast_update_implicit_coercion_catalogue_and_rollback() {
    let engine = setup_engine();
    let mut state = crate::_internal::analysis::state::AnalysisState::new(synced_cache());
    let findings = engine
        .analyze(
            "CREATE TYPE public.cast_src AS ENUM ('a');
             CREATE TYPE public.cast_dst AS ENUM ('a');
             CREATE FUNCTION public.cast_fn(public.cast_src) RETURNS public.cast_dst
                 LANGUAGE sql IMMUTABLE AS 'SELECT ''a''::public.cast_dst';
             CREATE CAST (public.cast_src AS public.cast_dst)
                 WITH FUNCTION public.cast_fn(public.cast_src) AS IMPLICIT;",
            &mut state,
        )
        .unwrap();
    assert!(
        !findings.iter().any(|v| v.rule_id == "chain-conflict"),
        "valid CREATE CAST AS IMPLICIT must not conflict: {findings:?}"
    );
    assert!(
        state
            .casts()
            .coerces_implicitly("public.cast_src", "public.cast_dst"),
        "CREATE CAST AS IMPLICIT must register implicit cast in CastCatalogue"
    );

    let mut dup_state = state.clone();
    let dup = engine
        .analyze(
            "CREATE CAST (public.cast_src AS public.cast_dst) WITH INOUT AS IMPLICIT;",
            &mut dup_state,
        )
        .unwrap();
    assert!(
        dup.iter().any(|v| {
            v.rule_id == "chain-conflict"
                && v.reason.contains(
                    "cast from type public.cast_src to type public.cast_dst already exists",
                )
        }),
        "duplicate implicit cast must conflict: {dup:?}"
    );

    let mut drop_state = state.clone();
    let drop_findings = engine
        .analyze(
            "DROP CAST (public.cast_src AS public.cast_dst);",
            &mut drop_state,
        )
        .unwrap();
    assert!(
        !drop_findings.iter().any(|v| v.rule_id == "chain-conflict"),
        "DROP CAST must succeed: {drop_findings:?}"
    );
    assert!(
        !drop_state
            .casts()
            .coerces_implicitly("public.cast_src", "public.cast_dst"),
        "DROP CAST must remove implicit cast from CastCatalogue"
    );
}
