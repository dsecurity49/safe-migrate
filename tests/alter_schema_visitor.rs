mod common;

mod alter_schema_visitor_test {
    #[test]
    fn test_alter_schema_pipeline() {
        use safe_migrate::_internal::analysis::facts::{AlterSchemaActionFact, StatementFact};
        use safe_migrate::_internal::ast::visitor::AstVisitor;
        use squawk_syntax::ast::SourceFile;

        let sql = "ALTER SCHEMA old_name RENAME TO new_name";
        let parsed = SourceFile::parse(sql);
        let stmt = parsed.tree().stmts().next().expect("Failed to parse SQL");
        let fact = AstVisitor::extract(&stmt);

        match &fact {
            Some(StatementFact::AlterSchema { name, action }) => {
                assert_eq!(name.name.text, "old_name");
                assert!(
                    matches!(action, AlterSchemaActionFact::RenameTo { new_name } if new_name.text == "new_name")
                );
            }
            other => panic!("Expected AlterSchema, got {:?}", other),
        }
    }
}

// ─────────────────────────────────────────────
// 9. Architectural Gap Tests (Pre-existing)
// ─────────────────────────────────────────────
