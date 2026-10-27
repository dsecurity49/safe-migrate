use super::*;
use safe_migrate::_internal::model::collation::CollationCatalogue;
use safe_migrate::_internal::model::extension::{
    ExtensionMember, ExtensionMemberKind, ExtensionOverlay, ExtensionState,
};
use safe_migrate::_internal::model::index::ResolvedName;
use safe_migrate::_internal::model::types::TypeKind;

fn attach_extension(
    state: &mut AnalysisState,
    name: &str,
    schema: &str,
    relocatable: bool,
    members: impl IntoIterator<Item = ExtensionMember>,
) {
    state.local.extensions.insert(
        name.to_string(),
        ExtensionOverlay::Present(ExtensionState {
            name: name.to_string(),
            schema: Some(schema.to_string()),
            version: Some("1.0".to_string()),
            relocatable: Some(relocatable),
            owner: ObjectId::new("", state.local.current_role.clone()),
            members: members.into_iter().collect(),
            members_complete: true,
            config_tables: Vec::new(),
            generation: 0,
        }),
    );
}

fn member(kind: ExtensionMemberKind, schema: &str, name: &str) -> ExtensionMember {
    ExtensionMember {
        kind,
        id: object_id(schema, name),
    }
}

fn extension<'a>(state: &'a AnalysisState, name: &str) -> &'a ExtensionState {
    match state.local.extensions.get(name) {
        Some(ExtensionOverlay::Present(extension)) => extension,
        _ => panic!("extension {name} should be present"),
    }
}

#[test]
fn alter_extension_set_schema_moves_modeled_members_and_identities() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE SCHEMA relocated;
             CREATE TABLE public.items (id integer);
             CREATE VIEW public.items_view AS SELECT * FROM public.items;
             CREATE INDEX items_id_idx ON public.items (id);
             CREATE TYPE public.mood AS ENUM ('ok');
             CREATE SEQUENCE public.items_seq;
             CREATE FUNCTION public.f() RETURNS integer LANGUAGE sql AS 'SELECT 1';",
            &mut state,
        )
        .unwrap();
    attach_extension(
        &mut state,
        "ext",
        "public",
        true,
        [
            member(ExtensionMemberKind::Relation, "public", "items"),
            member(ExtensionMemberKind::Relation, "public", "items_view"),
            member(ExtensionMemberKind::Index, "public", "items_id_idx"),
            member(ExtensionMemberKind::Type, "public", "mood"),
            member(ExtensionMemberKind::Sequence, "public", "items_seq"),
            member(ExtensionMemberKind::Routine, "public", "f()"),
        ],
    );

    let violations = engine
        .analyze("ALTER EXTENSION ext SET SCHEMA relocated;", &mut state)
        .unwrap();

    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "set schema should be valid: {violations:?}"
    );
    assert_eq!(
        extension(&state, "ext").schema.as_deref(),
        Some("relocated")
    );
    assert!(state.relation_is_present(&object_id("relocated", "items")));
    assert!(state.relation_is_present(&object_id("relocated", "items_view")));
    assert!(state.index_is_present(&object_id("relocated", "items_id_idx")));
    assert!(state.type_is_present(&object_id("relocated", "mood")));
    assert!(state.sequence_is_present(&object_id("relocated", "items_seq")));
    assert!(matches!(
        state.local.functions.get(&object_id("relocated", "f()")),
        Some(FunctionOverlay::Present(_))
    ));
    let members = &extension(&state, "ext").members;
    assert!(members.contains(&member(ExtensionMemberKind::Relation, "relocated", "items")));
    assert!(members.contains(&member(
        ExtensionMemberKind::Relation,
        "relocated",
        "items_view"
    )));
    assert!(members.contains(&member(
        ExtensionMemberKind::Index,
        "relocated",
        "items_id_idx"
    )));
    assert!(members.contains(&member(ExtensionMemberKind::Type, "relocated", "mood")));
    assert!(members.contains(&member(
        ExtensionMemberKind::Sequence,
        "relocated",
        "items_seq"
    )));
    assert!(members.contains(&member(ExtensionMemberKind::Routine, "relocated", "f()")));
}

#[test]
fn alter_extension_set_schema_rejects_members_outside_the_extension_schema() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE SCHEMA relocated;
             CREATE SCHEMA elsewhere;
             CREATE TABLE elsewhere.items (id integer);",
            &mut state,
        )
        .unwrap();
    attach_extension(
        &mut state,
        "ext",
        "public",
        true,
        [member(ExtensionMemberKind::Relation, "elsewhere", "items")],
    );

    let violations = engine
        .analyze("ALTER EXTENSION ext SET SCHEMA relocated;", &mut state)
        .unwrap();

    assert!(violations.iter().any(|violation| {
        violation.rule_id == "chain-conflict"
            && violation.reason.contains("does not support SET SCHEMA")
    }));
    assert_eq!(extension(&state, "ext").schema.as_deref(), Some("public"));
    assert!(state.relation_is_present(&object_id("elsewhere", "items")));
}

#[test]
fn drop_extension_drops_modeled_members_without_cascade() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE public.items (id integer);
             CREATE VIEW public.items_view AS SELECT * FROM public.items;
             CREATE INDEX items_id_idx ON public.items (id);
             CREATE TYPE public.mood AS ENUM ('ok');
             CREATE SEQUENCE public.items_seq;
             CREATE FUNCTION public.f() RETURNS integer LANGUAGE sql AS 'SELECT 1';",
            &mut state,
        )
        .unwrap();
    attach_extension(
        &mut state,
        "ext",
        "public",
        true,
        [
            member(ExtensionMemberKind::Relation, "public", "items"),
            member(ExtensionMemberKind::Relation, "public", "items_view"),
            member(ExtensionMemberKind::Index, "public", "items_id_idx"),
            member(ExtensionMemberKind::Type, "public", "mood"),
            member(ExtensionMemberKind::Sequence, "public", "items_seq"),
            member(ExtensionMemberKind::Routine, "public", "f()"),
        ],
    );

    let violations = engine.analyze("DROP EXTENSION ext;", &mut state).unwrap();

    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "drop extension should be valid: {violations:?}"
    );
    assert!(!matches!(
        state.local.extensions.get("ext"),
        Some(ExtensionOverlay::Present(_))
    ));
    assert!(!state.relation_is_present(&object_id("public", "items")));
    assert!(!state.relation_is_present(&object_id("public", "items_view")));
    assert!(!state.index_is_present(&object_id("public", "items_id_idx")));
    assert!(!state.type_is_present(&object_id("public", "mood")));
    assert!(!state.sequence_is_present(&object_id("public", "items_seq")));
    assert!(!matches!(
        state.local.functions.get(&object_id("public", "f()")),
        Some(FunctionOverlay::Present(_))
    ));
}

#[test]
fn drop_extension_requires_cascade_for_external_dependents() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE public.items (id integer);
             CREATE VIEW public.external_view AS SELECT * FROM public.items;",
            &mut state,
        )
        .unwrap();
    attach_extension(
        &mut state,
        "ext",
        "public",
        true,
        [member(ExtensionMemberKind::Relation, "public", "items")],
    );

    let violations = engine.analyze("DROP EXTENSION ext;", &mut state).unwrap();

    assert!(violations.iter().any(|violation| {
        violation.rule_id == "chain-conflict"
            && violation
                .reason
                .contains("cannot drop extension ext because other objects depend on it")
    }));
    assert!(matches!(
        state.local.extensions.get("ext"),
        Some(ExtensionOverlay::Present(_))
    ));
    assert!(state.relation_is_present(&object_id("public", "items")));
    assert!(state.relation_is_present(&object_id("public", "external_view")));

    engine
        .analyze("DROP EXTENSION ext CASCADE;", &mut state)
        .unwrap();
    assert!(!state.relation_is_present(&object_id("public", "items")));
    assert!(!state.relation_is_present(&object_id("public", "external_view")));
}

#[test]
fn set_schema_rejects_a_target_schema_owned_by_the_extension() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze("CREATE SCHEMA relocated;", &mut state)
        .unwrap();
    attach_extension(
        &mut state,
        "ext",
        "public",
        true,
        [member(ExtensionMemberKind::Schema, "", "relocated")],
    );

    let violations = engine
        .analyze("ALTER EXTENSION ext SET SCHEMA relocated;", &mut state)
        .unwrap();

    assert!(violations.iter().any(|violation| {
        violation.rule_id == "chain-conflict"
            && violation.reason.contains("extension contains the schema")
    }));
    assert_eq!(extension(&state, "ext").schema.as_deref(), Some("public"));
}

#[test]
fn drop_extension_ignores_dependencies_between_its_members() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TYPE public.mood AS ENUM ('ok');
             CREATE FUNCTION public.f() RETURNS public.mood
                 LANGUAGE sql AS 'SELECT ''ok''::public.mood';",
            &mut state,
        )
        .unwrap();
    attach_extension(
        &mut state,
        "ext",
        "public",
        true,
        [
            member(ExtensionMemberKind::Type, "public", "mood"),
            member(ExtensionMemberKind::Routine, "public", "f()"),
        ],
    );

    let violations = engine.analyze("DROP EXTENSION ext;", &mut state).unwrap();

    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "member dependencies are internal: {violations:?}"
    );
    assert!(!state.type_is_present(&object_id("public", "mood")));
    assert!(!matches!(
        state.local.functions.get(&object_id("public", "f()")),
        Some(FunctionOverlay::Present(_))
    ));
}

#[test]
fn drop_extension_resolves_dependencies_across_the_dropped_set() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TYPE public.mood AS ENUM ('ok');
             CREATE FUNCTION public.f() RETURNS public.mood
                 LANGUAGE sql AS 'SELECT ''ok''::public.mood';",
            &mut state,
        )
        .unwrap();
    attach_extension(
        &mut state,
        "ext_a",
        "public",
        true,
        [member(ExtensionMemberKind::Type, "public", "mood")],
    );
    attach_extension(
        &mut state,
        "ext_b",
        "public",
        true,
        [member(ExtensionMemberKind::Routine, "public", "f()")],
    );

    let violations = engine
        .analyze("DROP EXTENSION ext_a, ext_b;", &mut state)
        .unwrap();

    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "both extensions are dropped together: {violations:?}"
    );
    assert!(!state.type_is_present(&object_id("public", "mood")));
    assert!(!matches!(
        state.local.functions.get(&object_id("public", "f()")),
        Some(FunctionOverlay::Present(_))
    ));
}

#[test]
fn drop_extension_reports_external_type_dependents_at_extension_level() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TYPE public.mood AS ENUM ('ok');
             CREATE TABLE public.external_table (m public.mood);",
            &mut state,
        )
        .unwrap();
    attach_extension(
        &mut state,
        "ext",
        "public",
        true,
        [member(ExtensionMemberKind::Type, "public", "mood")],
    );

    let violations = engine.analyze("DROP EXTENSION ext;", &mut state).unwrap();

    assert!(violations.iter().any(|violation| {
        violation.rule_id == "chain-conflict"
            && violation
                .reason
                .contains("cannot drop extension ext because other objects depend on it")
    }));
    assert!(state.type_is_present(&object_id("public", "mood")));
    assert!(state.relation_is_present(&object_id("public", "external_table")));

    engine
        .analyze("DROP EXTENSION ext CASCADE;", &mut state)
        .unwrap();
    assert!(!state.type_is_present(&object_id("public", "mood")));
    assert!(state.relation_is_present(&object_id("public", "external_table")));
    let Some(RelationOverlay::Present(table)) = state
        .local
        .relations
        .get(&object_id("public", "external_table"))
    else {
        panic!("external table should survive its dependent column drop");
    };
    assert!(table.columns.is_empty());
}

#[test]
fn drop_extension_reports_external_routine_dependents_at_extension_level() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE public.external_table (id integer);
             CREATE FUNCTION public.f() RETURNS trigger
                 LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
             CREATE TRIGGER trg BEFORE INSERT ON public.external_table
                 FOR EACH ROW EXECUTE FUNCTION public.f();",
            &mut state,
        )
        .unwrap();
    attach_extension(
        &mut state,
        "ext",
        "public",
        true,
        [member(ExtensionMemberKind::Routine, "public", "f()")],
    );

    let violations = engine.analyze("DROP EXTENSION ext;", &mut state).unwrap();

    assert!(violations.iter().any(|violation| {
        violation.rule_id == "chain-conflict"
            && violation
                .reason
                .contains("cannot drop extension ext because other objects depend on it")
    }));
    assert!(matches!(
        state.local.functions.get(&object_id("public", "f()")),
        Some(FunctionOverlay::Present(_))
    ));

    engine
        .analyze("DROP EXTENSION ext CASCADE;", &mut state)
        .unwrap();
    assert!(!matches!(
        state.local.functions.get(&object_id("public", "f()")),
        Some(FunctionOverlay::Present(_))
    ));
    assert!(state.relation_is_present(&object_id("public", "external_table")));
    assert!(state.local.triggers.values().all(|overlay| !matches!(
        overlay,
        safe_migrate::_internal::model::trigger::TriggerOverlay::Present(_)
    )));
}

#[test]
fn drop_extension_reports_external_sequence_dependents_at_extension_level() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE SEQUENCE public.items_seq;
             CREATE TABLE public.external_table (id integer);
             ALTER TABLE public.external_table
                 ALTER COLUMN id SET DEFAULT nextval('public.items_seq');",
            &mut state,
        )
        .unwrap();
    attach_extension(
        &mut state,
        "ext",
        "public",
        true,
        [member(ExtensionMemberKind::Sequence, "public", "items_seq")],
    );

    let violations = engine.analyze("DROP EXTENSION ext;", &mut state).unwrap();

    assert!(violations.iter().any(|violation| {
        violation.rule_id == "chain-conflict"
            && violation
                .reason
                .contains("cannot drop extension ext because other objects depend on it")
    }));
    assert!(state.sequence_is_present(&object_id("public", "items_seq")));

    engine
        .analyze("DROP EXTENSION ext CASCADE;", &mut state)
        .unwrap();
    assert!(!state.sequence_is_present(&object_id("public", "items_seq")));
    let Some(RelationOverlay::Present(table)) = state
        .local
        .relations
        .get(&object_id("public", "external_table"))
    else {
        panic!("external table should survive the sequence cascade");
    };
    assert!(table.columns.iter().all(|column| column.default.is_none()));
}

#[test]
fn drop_extension_ignores_trigger_dependencies_between_its_members() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE TABLE public.external_table (id integer);
             CREATE FUNCTION public.f() RETURNS trigger
                 LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
             CREATE TRIGGER trg BEFORE INSERT ON public.external_table
                 FOR EACH ROW EXECUTE FUNCTION public.f();",
            &mut state,
        )
        .unwrap();
    attach_extension(
        &mut state,
        "ext",
        "public",
        true,
        [
            member(ExtensionMemberKind::Relation, "public", "external_table"),
            member(ExtensionMemberKind::Routine, "public", "f()"),
            member(ExtensionMemberKind::Trigger, "public", "external_table.trg"),
        ],
    );

    let violations = engine.analyze("DROP EXTENSION ext;", &mut state).unwrap();

    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "trigger is an extension member: {violations:?}"
    );
    assert!(!state.relation_is_present(&object_id("public", "external_table")));
    assert!(!matches!(
        state.local.functions.get(&object_id("public", "f()")),
        Some(FunctionOverlay::Present(_))
    ));
    assert!(state.local.triggers.values().all(|overlay| !matches!(
        overlay,
        safe_migrate::_internal::model::trigger::TriggerOverlay::Present(_)
    )));
}

#[test]
fn set_schema_moves_collation_references() {
    let engine = setup_engine();
    let mut state = setup_state();
    state.local.collations = CollationCatalogue::from_entries(vec![
        ResolvedName {
            schema: "pg_catalog".to_string(),
            name: "default".to_string(),
        },
        ResolvedName {
            schema: "public".to_string(),
            name: "app_coll".to_string(),
        },
    ]);
    engine
        .analyze(
            "CREATE SCHEMA relocated;
             CREATE DOMAIN public.app_domain AS text COLLATE public.app_coll;",
            &mut state,
        )
        .unwrap();
    attach_extension(
        &mut state,
        "ext",
        "public",
        true,
        [
            member(ExtensionMemberKind::Collation, "public", "app_coll"),
            member(ExtensionMemberKind::Type, "public", "app_domain"),
        ],
    );

    let violations = engine
        .analyze("ALTER EXTENSION ext SET SCHEMA relocated;", &mut state)
        .unwrap();

    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "collation move should be valid: {violations:?}"
    );
    assert!(state.local.collations.has("relocated", "app_coll"));
    assert!(!state.local.collations.has("public", "app_coll"));
    let Some(TypeOverlay::Present(domain)) =
        state.local.types.get(&object_id("relocated", "app_domain"))
    else {
        panic!("domain should move with the extension");
    };
    let TypeKind::Domain { collation_id, .. } = &domain.kind else {
        panic!("expected a domain");
    };
    assert_eq!(
        collation_id.as_ref(),
        Some(&object_id("relocated", "app_coll"))
    );
}

#[test]
fn schema_rename_remaps_extension_members() {
    let engine = setup_engine();
    let mut state = setup_state();
    engine
        .analyze(
            "CREATE SCHEMA app;
             CREATE TABLE app.items (id integer);",
            &mut state,
        )
        .unwrap();
    attach_extension(
        &mut state,
        "ext",
        "app",
        true,
        [member(ExtensionMemberKind::Relation, "app", "items")],
    );

    engine
        .analyze("ALTER SCHEMA app RENAME TO renamed;", &mut state)
        .unwrap();

    assert_eq!(extension(&state, "ext").schema.as_deref(), Some("renamed"));
    assert!(extension(&state, "ext").members.contains(&member(
        ExtensionMemberKind::Relation,
        "renamed",
        "items"
    )));
    assert!(state.relation_is_present(&object_id("renamed", "items")));
}
