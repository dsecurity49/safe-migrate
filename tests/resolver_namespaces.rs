mod common;

#[cfg(test)]
mod resolver_namespace_tests {
    use super::common::{object_id, setup_engine, setup_state};
    use safe_migrate::model::function::FunctionOverlay;
    use safe_migrate::model::relation::RelationOverlay;

    fn assert_no_conflict(findings: &[safe_migrate::report::violations::Violation]) {
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
}
