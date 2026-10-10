#[cfg(test)]
mod resolver_namespace_tests {
    use crate::common::{object_id, setup_engine, setup_state};
    use safe_migrate::_internal::model::function::FunctionOverlay;
    use safe_migrate::_internal::model::relation::RelationOverlay;
    use safe_migrate::_internal::model::schema::SchemaState;

    fn assert_no_conflict(findings: &[safe_migrate::_internal::report::violations::Violation]) {
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule_id != "chain-conflict"),
            "unexpected resolver conflict: {findings:?}"
        );
    }

    #[test]
    fn dropped_relation_tombstone_does_not_shadow_a_later_present_relation() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE SCHEMA lookup_a;
                 CREATE SCHEMA lookup_b;
                 CREATE TABLE lookup_a.shared_name (id integer);
                 CREATE TABLE lookup_b.shared_name (id integer);
                 DROP TABLE lookup_a.shared_name;
                 SET search_path TO lookup_a, lookup_b;",
                &mut state,
            )
            .unwrap();

        let findings = engine
            .analyze(
                "ALTER TABLE shared_name ADD COLUMN resolved integer;",
                &mut state,
            )
            .unwrap();

        assert_no_conflict(&findings);
        let Some(RelationOverlay::Present(relation)) =
            state.get_relation(&object_id("lookup_b", "shared_name"))
        else {
            panic!("lookup_b.shared_name should remain present");
        };
        assert!(relation.has_column("resolved"));
    }

    #[test]
    fn a_type_does_not_shadow_a_relation_in_a_later_schema() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE SCHEMA lookup_a;
                 CREATE SCHEMA lookup_b;
                 CREATE TYPE lookup_a.shared_name AS ENUM ('lookup_a');
                 CREATE TABLE lookup_b.shared_name (id integer);
                 SET search_path TO lookup_a, lookup_b;",
                &mut state,
            )
            .unwrap();

        let findings = engine
            .analyze(
                "ALTER TABLE shared_name ADD COLUMN resolved integer;",
                &mut state,
            )
            .unwrap();

        assert_no_conflict(&findings);
        let Some(RelationOverlay::Present(relation)) =
            state.get_relation(&object_id("lookup_b", "shared_name"))
        else {
            panic!("lookup_b.shared_name should remain present");
        };
        assert!(relation.has_column("resolved"));
    }

    #[test]
    fn a_relation_does_not_shadow_a_type_in_a_later_schema() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE SCHEMA lookup_a;
                 CREATE SCHEMA lookup_b;
                 CREATE TABLE lookup_a.shared_name (id integer);
                 CREATE TYPE lookup_b.shared_name AS ENUM ('old');
                 SET search_path TO lookup_a, lookup_b;",
                &mut state,
            )
            .unwrap();

        let findings = engine
            .analyze(
                "ALTER TYPE shared_name RENAME VALUE 'old' TO 'new';",
                &mut state,
            )
            .unwrap();

        assert_no_conflict(&findings);
    }

    #[test]
    fn an_unrelated_overload_does_not_shadow_an_exact_routine_signature() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE SCHEMA lookup_a;
                 CREATE SCHEMA lookup_b;
                 CREATE FUNCTION lookup_a.work(value text) RETURNS integer
                     LANGUAGE sql IMMUTABLE AS 'SELECT 1';
                 CREATE FUNCTION lookup_b.work(value integer) RETURNS integer
                     LANGUAGE sql VOLATILE AS 'SELECT value';
                 SET search_path TO lookup_a, lookup_b;",
                &mut state,
            )
            .unwrap();

        let findings = engine
            .analyze("ALTER FUNCTION work(integer) IMMUTABLE;", &mut state)
            .unwrap();

        assert_no_conflict(&findings);
        assert!(matches!(
            state
                .local
                .functions
                .get(&object_id("lookup_b", "work(integer)")),
            Some(FunctionOverlay::Present(_))
        ));
    }

    #[test]
    fn dropped_routine_tombstone_does_not_shadow_a_later_exact_signature() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE SCHEMA lookup_a;
                 CREATE SCHEMA lookup_b;
                 CREATE FUNCTION lookup_a.work(value integer) RETURNS integer
                     LANGUAGE sql VOLATILE AS 'SELECT value';
                 CREATE FUNCTION lookup_b.work(value integer) RETURNS integer
                     LANGUAGE sql VOLATILE AS 'SELECT value';
                 DROP FUNCTION lookup_a.work(integer);
                 SET search_path TO lookup_a, lookup_b;",
                &mut state,
            )
            .unwrap();

        let findings = engine
            .analyze("ALTER FUNCTION work(integer) IMMUTABLE;", &mut state)
            .unwrap();

        assert_no_conflict(&findings);
    }

    #[test]
    fn sequence_in_an_earlier_schema_shadows_a_later_table() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze(
                "CREATE SCHEMA lookup_a;
                 CREATE SCHEMA lookup_b;
                 CREATE SEQUENCE lookup_a.shared_name;
                 CREATE TABLE lookup_b.shared_name (id integer);
                 SET search_path TO lookup_a, lookup_b;",
                &mut state,
            )
            .unwrap();

        let findings = engine
            .analyze(
                "ALTER TABLE shared_name ADD COLUMN wrong integer;",
                &mut state,
            )
            .unwrap();

        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "the shared relation namespace must select lookup_a.shared_name: {findings:?}"
        );
    }

    #[test]
    fn quoted_relation_lookup_preserves_case_and_search_path_order() {
        let engine = setup_engine();
        let mut state = setup_state();
        let findings = engine
            .analyze(
                "CREATE SCHEMA lookup_a;
                 CREATE SCHEMA lookup_b;
                 CREATE TABLE lookup_a.\"SharedName\" (id integer);
                 CREATE TABLE lookup_b.sharedname (id integer);
                 SET search_path TO lookup_a, lookup_b;
                 ALTER TABLE \"SharedName\" ADD COLUMN resolved integer;",
                &mut state,
            )
            .unwrap();

        assert_no_conflict(&findings);
        let Some(RelationOverlay::Present(relation)) =
            state.get_relation(&object_id("lookup_a", "SharedName"))
        else {
            panic!("quoted lookup_a.SharedName should remain present");
        };
        assert!(relation.has_column("resolved"));
    }

    #[test]
    fn postgresql_identifier_truncation_creates_a_real_namespace_collision() {
        let engine = setup_engine();
        let mut state = setup_state();
        let findings = engine
            .analyze(
                "CREATE TABLE aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax (id integer);
                 CREATE TABLE aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay (id integer);",
                &mut state,
            )
            .unwrap();

        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "names equal after PostgreSQL's 63-byte truncation must conflict: {findings:?}"
        );
        assert!(state.relation_is_present(&object_id(
            "public",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )));
        assert!(
            !state
                .local
                .relations
                .keys()
                .any(|id| id.name.ends_with('x') || id.name.ends_with('y'))
        );
    }

    /// A scoped sync hides schemas outside `--schemas`, but `search_path` still
    /// names them, and an out-of-scope entry may *precede* an in-scope one.
    /// PostgreSQL would search `public` first; dropping it silently retargets
    /// the reference to `app` and reports drift on a table that may well live in
    /// `public`. The lookup must stay unknown instead.
    #[test]
    fn unqualified_reference_through_out_of_scope_search_path_entry_is_unknown() {
        let engine = setup_engine();
        let mut cache = crate::common::synced_cache();
        cache.metadata.schemas = Some(vec!["app".to_string()]);
        // What sync actually observed: `public` first, then the scoped `app`.
        cache.metadata.source_search_path = Some(vec!["public".to_string(), "app".to_string()]);
        cache.search_path = vec!["app".to_string()];
        cache.schemas.insert(
            "app".to_string(),
            SchemaState {
                name: "app".to_string(),
                owner: object_id("", "postgres"),
                generation: 0,
            },
        );
        let mut state = crate::_internal::analysis::state::AnalysisState::new(cache);

        let findings = engine
            .analyze(
                "ALTER TABLE external_table ADD COLUMN note text;",
                &mut state,
            )
            .unwrap();

        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == "chain-conflict"),
            "an unresolvable reference must not be reported as a chain conflict: \
             {findings:?}"
        );
        let coverage = findings
            .iter()
            .find(|finding| finding.rule_id == "schema-drift")
            .expect("an omitted schema must be reported as unknown coverage");
        assert_eq!(
            coverage.tier,
            safe_migrate::_internal::report::violations::ViolationTier::Tier2,
            "an unverifiable reference is a coverage gap, not a Tier1 drift claim"
        );
        assert!(coverage.reason.contains("does not cover schema \"public\""));
        assert!(
            !coverage.reason.contains("does not exist"),
            "coverage must never be reported as proven absence: {}",
            coverage.reason
        );
        assert!(
            !coverage.object_name.starts_with("app."),
            "the reference must keep the schema PostgreSQL searched first: {}",
            coverage.object_name
        );
        assert!(
            state.evidence().iter().any(|record| {
                record.code
                    == safe_migrate::_internal::analysis::evidence::EvidenceCode::UnknownObjectState
            }),
            "a search_path entry outside the synced scope must taint the lookup: {:?}",
            state.evidence()
        );
    }

    /// PostgreSQL searches the session temporary schema before every explicit
    /// path entry, for relations and types alike. A type reference must agree
    /// with the relation resolver, or `f(x tt)` and `f(x pg_temp.tt)` become two
    /// signatures for one type.
    #[test]
    fn unqualified_type_reference_searches_the_session_temporary_schema() {
        let engine = setup_engine();
        let mut state = setup_state();
        engine
            .analyze("CREATE TEMP TABLE tt(a integer);", &mut state)
            .unwrap();

        assert_eq!(
            state.resolve_type_reference("tt"),
            Some(object_id("pg_temp", "tt")),
            "an unqualified type must resolve through pg_temp"
        );
        assert_eq!(
            state.resolve_type_reference("pg_temp.tt"),
            Some(object_id("pg_temp", "tt")),
            "both spellings must name the same type"
        );
    }

    /// T10: seven overloads differing only by built-in type collapsed into one
    /// signature, because every unrecognised name rendered as nothing.
    #[test]
    fn built_in_overloads_keep_distinct_signatures() {
        let engine = setup_engine();
        let mut state = setup_state();

        for declaration in [
            "CREATE FUNCTION f(a bytea) RETURNS int LANGUAGE sql AS 'SELECT 1';",
            "CREATE FUNCTION f(a jsonb) RETURNS int LANGUAGE sql AS 'SELECT 1';",
            "CREATE FUNCTION f(a inet) RETURNS int LANGUAGE sql AS 'SELECT 1';",
            "CREATE FUNCTION f(a text) RETURNS int LANGUAGE sql AS 'SELECT 1';",
            "CREATE FUNCTION f(a varchar) RETURNS int LANGUAGE sql AS 'SELECT 1';",
            "CREATE FUNCTION f(a uuid) RETURNS int LANGUAGE sql AS 'SELECT 1';",
            "CREATE FUNCTION f(a xml) RETURNS int LANGUAGE sql AS 'SELECT 1';",
        ] {
            let findings = engine.analyze(declaration, &mut state).unwrap();
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.rule_id == "chain-conflict"),
                "declaring a built-in overload must not conflict: {declaration} -> {findings:?}"
            );
        }

        let mut identities = state
            .local
            .functions
            .keys()
            .map(|id| id.name.clone())
            .collect::<Vec<_>>();
        identities.sort();
        assert_eq!(
            identities,
            [
                "f(bytea)",
                "f(character varying)",
                "f(inet)",
                "f(jsonb)",
                "f(text)",
                "f(uuid)",
                "f(xml)",
            ],
            "each built-in argument type must give its own signature"
        );
    }

    /// T10: the two identity paths must agree, so a canonical spelling written in
    /// DDL and the same type read back from the catalog are one identity.
    #[test]
    fn written_and_catalog_spellings_share_one_identity() {
        use safe_migrate::_internal::model::data_type::{ParsedDataType, TypeIdentity};

        let state = setup_state();
        for (written, canonical) in [
            ("int", "integer"),
            ("int4", "integer"),
            ("integer", "integer"),
            ("timestamptz", "timestamp with time zone"),
            ("timestamp with time zone", "timestamp with time zone"),
            ("bool", "boolean"),
            ("boolean", "boolean"),
            ("float", "double precision"),
            ("float8", "double precision"),
            ("varbit", "bit varying"),
            ("varchar", "character varying"),
        ] {
            let identity =
                TypeIdentity::from_syntax(&ParsedDataType::parse(written, state.builtin_types()));
            assert_eq!(
                identity.render(),
                canonical,
                "{written} must render as {canonical}"
            );
            assert!(
                !identity.is_unknown(),
                "{written} is a built-in and must not read as unresolved"
            );
        }
    }

    /// T63: `citext` is an extension type, never a pg_catalog built-in. Treating
    /// it as native made a same-spelling user type unreachable.
    #[test]
    fn citext_is_not_a_builtin_family() {
        let state = setup_state();
        assert!(
            !state
                .builtin_types()
                .resolve("citext")
                .is_some_and(|entry| entry.typname == "citext"),
            "citext only exists in pg_catalog when its extension is installed"
        );
    }
}
