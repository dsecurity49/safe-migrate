mod common;

mod identifier_casing_tests {
    use crate::common::*;
    use safe_migrate::_internal::model::relation::RelationOverlay;

    #[test]
    fn test_ident_unquoted_lowercase() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE TABLE Users (Id int);", &mut state)
            .unwrap();
        assert!(state.relation_is_present(&object_id("public", "users")));
    }

    #[test]
    fn test_ident_quoted_preserve() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze("CREATE TABLE \"MyTable\" (\"MyCol\" int);", &mut state)
            .unwrap();

        let mixed_id = object_id("public", "MyTable");
        assert!(state.relation_is_present(&mixed_id));

        engine
            .analyze(
                "ALTER TABLE \"MyTable\" RENAME TO \"NewTable\";",
                &mut state,
            )
            .unwrap();

        assert!(!state.relation_is_present(&mixed_id));
        assert!(state.relation_is_present(&object_id("public", "NewTable")));

        engine
            .analyze(
                "ALTER TABLE \"NewTable\" RENAME COLUMN \"MyCol\" TO \"NewCol\";",
                &mut state,
            )
            .unwrap();

        let rel = state
            .get_relation(&object_id("public", "NewTable"))
            .unwrap();
        if let RelationOverlay::Present(r) = rel {
            assert!(r.has_column("NewCol"));
            assert!(!r.has_column("MyCol"));
        } else {
            panic!("NewTable must be Present");
        }
    }

    #[test]
    fn test_ident_schema_resolution() {
        let engine = setup_engine();
        let mut state = setup_state();

        engine
            .analyze(
                "CREATE SCHEMA MySchema; CREATE TABLE MySchema.MyTable (id int);",
                &mut state,
            )
            .unwrap();

        assert!(state.relation_is_present(&object_id("myschema", "mytable")));
    }
}

// ─────────────────────────────────────────────
// 7. Destructive Rule Evaluation Tests
// ─────────────────────────────────────────────
