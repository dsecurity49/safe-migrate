mod common;

mod chain_execution_tests {
    use crate::common::*;
    use safe_migrate::_internal::model::relation::RelationOverlay;
    use safe_migrate::_internal::report::violations::ViolationTier;

    #[test]
    fn test_chain_state_persists_across_files() {
        let engine = setup_engine();
        let mut state = setup_state();

        let files = vec![
            (
                "V1__create.sql".to_string(),
                "CREATE TABLE IF NOT EXISTS users (id INT);".to_string(),
            ),
            (
                "V2__alter.sql".to_string(),
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;".to_string(),
            ),
        ];

        let violations = engine.analyze_chain(&files, &mut state).unwrap();
        assert!(
            violations.is_empty(),
            "Expected no violations, got: {:?}",
            violations
        );

        let rel = state.get_relation(&object_id("public", "users")).unwrap();
        if let RelationOverlay::Present(r) = rel {
            assert!(r.has_column("id"));
            assert!(r.has_column("email"));
        } else {
            panic!("users table should be present after chain");
        }
    }

    #[test]
    fn test_chain_rename_visible_across_files() {
        let engine = setup_engine();
        let mut state = setup_state();

        let files = vec![
            (
                "V1__base.sql".to_string(),
                "CREATE TABLE IF NOT EXISTS orders (id INT);".to_string(),
            ),
            (
                "V2__rename.sql".to_string(),
                "ALTER TABLE orders RENAME TO purchases;".to_string(),
            ),
            (
                "V3__post_rename.sql".to_string(),
                "ALTER TABLE purchases ADD COLUMN IF NOT EXISTS total NUMERIC;".to_string(),
            ),
        ];

        let violations = engine.analyze_chain(&files, &mut state).unwrap();
        assert!(
            violations.is_empty(),
            "Expected no violations, got: {:?}",
            violations
        );

        assert!(!state.relation_is_present(&object_id("public", "orders")));
        assert!(state.relation_is_present(&object_id("public", "purchases")));

        let rel = state
            .get_relation(&object_id("public", "purchases"))
            .unwrap();
        if let RelationOverlay::Present(r) = rel {
            assert!(r.has_column("total"));
        } else {
            panic!("purchases table should be present");
        }
    }

    #[test]
    fn test_chain_conflict_same_column_different_type() {
        let engine = setup_engine();
        let mut state = setup_state();

        let files = vec![
            (
                "V1__create.sql".to_string(),
                "CREATE TABLE products (id INT);".to_string(),
            ),
            (
                "V2__add_price.sql".to_string(),
                "ALTER TABLE products ADD COLUMN price INT;".to_string(),
            ),
            (
                "V3__change_price.sql".to_string(),
                "ALTER TABLE products ADD COLUMN price TEXT;".to_string(),
            ),
        ];

        let violations = engine.analyze_chain(&files, &mut state).unwrap();

        let conflict_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.rule_id == "chain-conflict")
            .collect();

        assert!(
            !conflict_violations.is_empty(),
            "Expected chain-conflict violation, got: {:?}",
            violations
        );

        let conflict = conflict_violations
            .iter()
            .find(|v| v.tier == ViolationTier::Tier1);
        assert!(conflict.is_some(), "Conflict should be Tier1");
        assert!(
            conflict.unwrap().reason.contains("price"),
            "Conflict message should mention column 'price'"
        );
        assert!(
            conflict.unwrap().reason.contains("INT"),
            "Conflict message should mention existing type INT"
        );
        assert!(
            conflict.unwrap().reason.contains("TEXT"),
            "Conflict message should mention conflicting type TEXT"
        );
    }

    #[test]
    fn test_chain_no_conflict_same_column_same_type() {
        let engine = setup_engine();
        let mut state = setup_state();

        let files = vec![
            (
                "V1__create.sql".to_string(),
                "CREATE TABLE IF NOT EXISTS items (id INT);".to_string(),
            ),
            (
                "V1__add.sql".to_string(),
                "ALTER TABLE items ADD COLUMN IF NOT EXISTS code TEXT;".to_string(),
            ),
            (
                "V2__idempotent.sql".to_string(),
                "ALTER TABLE items ADD COLUMN IF NOT EXISTS code TEXT;".to_string(),
            ),
        ];

        let violations = engine.analyze_chain(&files, &mut state).unwrap();

        let conflict_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.rule_id == "chain-conflict")
            .collect();

        assert!(
            conflict_violations.is_empty(),
            "Expected no chain-conflict violation for same-type re-add, got: {:?}",
            violations
        );

        let rel = state.get_relation(&object_id("public", "items")).unwrap();
        if let RelationOverlay::Present(r) = rel {
            assert!(r.has_column("code"));
            let col = r.get_column("code").unwrap();
            assert_eq!(col.data_type.as_deref(), Some("TEXT"));
        } else {
            panic!("items table should be present");
        }
    }

    #[test]
    fn test_chain_conflict_same_column_same_type_without_if_not_exists() {
        let engine = setup_engine();
        let mut state = setup_state();

        let violations = engine
            .analyze(
                "CREATE TABLE items (id INT);
                 ALTER TABLE items ADD COLUMN code TEXT;
                 ALTER TABLE items ADD COLUMN code TEXT;",
                &mut state,
            )
            .unwrap();

        assert!(violations.iter().any(|violation| {
            violation.rule_id == "chain-conflict"
                && violation.reason.contains("column 'code' already exists")
        }));
    }
}
