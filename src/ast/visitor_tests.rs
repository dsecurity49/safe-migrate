// FILE: src/ast/visitor_tests.rs

#[cfg(test)]
mod tests {
    use crate::analysis::expr_ir::ExprIr;
    use crate::analysis::facts::StatementFact;
    use crate::ast::identifiers::{Ident, QualifiedName};
    use crate::ast::visitor::AstVisitor;
    use squawk_syntax::ast::SourceFile;

    // ========================================================================
    // Expression IR Tests (expr_visitor.rs coverage)
    // ========================================================================

    fn parse_and_extract(sql: &str) -> Vec<StatementFact> {
        let parsed = SourceFile::parse(sql);
        parsed
            .tree()
            .stmts()
            .filter_map(|stmt| AstVisitor::extract(&stmt))
            .collect()
    }

    fn parse_and_extract_statement(sql: &str) -> Option<StatementFact> {
        let parsed = SourceFile::parse(sql);
        parsed
            .tree()
            .stmts()
            .next()
            .and_then(|stmt| AstVisitor::extract(&stmt))
    }

    #[test]
    fn test_grant_extracts_individual_table_privileges() {
        let fact = parse_and_extract_statement(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON test_table TO app_user;",
        )
        .expect("grant fact");

        let StatementFact::Grant(grant) = fact else {
            panic!("expected grant fact");
        };
        assert_eq!(
            grant.privileges,
            crate::analysis::facts::PrivilegeSpec::List(vec![
                crate::analysis::facts::PrivilegeFact::Select,
                crate::analysis::facts::PrivilegeFact::Insert,
                crate::analysis::facts::PrivilegeFact::Update,
                crate::analysis::facts::PrivilegeFact::Delete,
            ])
        );
    }

    #[test]
    fn test_create_table_with_columns() {
        let sql = "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(255) NOT NULL);";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::CreateTable { name, columns, .. } => {
                assert_eq!(name.name.resolve(), "users");
                assert_eq!(columns.len(), 2);
            }
            _ => panic!("Expected CreateTable fact"),
        }
    }

    #[test]
    fn test_create_table_with_quoted_identifiers() {
        let sql = r#"CREATE TABLE "MyTable" ("MyColumn" INT);"#;
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::CreateTable { name, columns, .. } => {
                assert_eq!(name.name.resolve(), "MyTable");
                assert!(name.name.quoted);
                assert_eq!(columns[0].name, "MyColumn");
            }
            _ => panic!("Expected CreateTable fact"),
        }
    }

    #[test]
    fn test_create_table_with_default_expr() {
        let sql = "CREATE TABLE events (id INT, created_at TIMESTAMP DEFAULT NOW());";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::CreateTable { columns, .. } => {
                assert_eq!(columns.len(), 2);
                // Check default expression
                if let Some(default) = &columns[1].default {
                    assert!(!default.is_volatile()); // NOW() is STABLE
                }
            }
            _ => panic!("Expected CreateTable fact"),
        }
    }

    #[test]
    fn test_create_table_temporary() {
        let sql = "CREATE TEMP TABLE temp_table (id INT);";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::CreateTable {
                name, persistence, ..
            } => {
                assert_eq!(name.name.resolve(), "temp_table");
                assert!(matches!(
                    persistence,
                    crate::analysis::facts::PersistenceFact::Temporary
                ));
            }
            _ => panic!("Expected CreateTable fact"),
        }
    }

    #[test]
    fn test_create_table_unlogged() {
        let sql = "CREATE UNLOGGED TABLE unlogged_table (id INT);";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::CreateTable {
                name, persistence, ..
            } => {
                assert_eq!(name.name.resolve(), "unlogged_table");
                assert!(matches!(
                    persistence,
                    crate::analysis::facts::PersistenceFact::Unlogged
                ));
            }
            _ => panic!("Expected CreateTable fact"),
        }
    }

    #[test]
    fn test_create_table_if_not_exists() {
        let sql = "CREATE TABLE IF NOT EXISTS existing_table (id INT);";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::CreateTable {
                name,
                if_not_exists,
                ..
            } => {
                assert_eq!(name.name.resolve(), "existing_table");
                assert!(if_not_exists);
            }
            _ => panic!("Expected CreateTable fact"),
        }
    }

    #[test]
    fn test_alter_table_add_column() {
        let sql = "ALTER TABLE users ADD COLUMN email VARCHAR(255);";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::AlterTable { name, actions } => {
                assert_eq!(name.name.resolve(), "users");
                assert!(!actions.is_empty());
            }
            _ => panic!("Expected AlterTable fact"),
        }
    }

    #[test]
    fn test_alter_table_drop_column() {
        let sql = "ALTER TABLE users DROP COLUMN email;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::AlterTable { name, actions } => {
                assert_eq!(name.name.resolve(), "users");
                assert!(!actions.is_empty());
            }
            _ => panic!("Expected AlterTable fact"),
        }
    }

    #[test]
    fn test_alter_table_rename_column() {
        let sql = "ALTER TABLE users RENAME COLUMN email TO email_address;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::AlterTable { name, actions } => {
                assert_eq!(name.name.resolve(), "users");
                assert!(!actions.is_empty());
            }
            _ => panic!("Expected AlterTable fact"),
        }
    }

    #[test]
    fn test_alter_table_rename_table() {
        let sql = "ALTER TABLE users RENAME TO accounts;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::AlterTable { name, actions } => {
                assert_eq!(name.name.resolve(), "users");
                assert!(!actions.is_empty());
            }
            _ => panic!("Expected AlterTable fact"),
        }
    }

    #[test]
    fn test_alter_table_set_not_null() {
        let sql = "ALTER TABLE users ALTER COLUMN email SET NOT NULL;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::AlterTable { name, actions } => {
                assert_eq!(name.name.resolve(), "users");
                assert!(!actions.is_empty());
            }
            _ => panic!("Expected AlterTable fact"),
        }
    }

    #[test]
    fn test_alter_table_drop_not_null() {
        let sql = "ALTER TABLE users ALTER COLUMN email DROP NOT NULL;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::AlterTable { name, actions } => {
                assert_eq!(name.name.resolve(), "users");
                assert!(!actions.is_empty());
            }
            _ => panic!("Expected AlterTable fact"),
        }
    }

    #[test]
    fn test_drop_table() {
        let sql = "DROP TABLE users;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::DropTable { name, .. } => {
                assert_eq!(name.name.resolve(), "users");
            }
            _ => panic!("Expected DropTable fact"),
        }
    }

    #[test]
    fn test_drop_table_if_exists() {
        let sql = "DROP TABLE IF EXISTS users;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::DropTable {
                name, if_exists, ..
            } => {
                assert_eq!(name.name.resolve(), "users");
                assert!(if_exists);
            }
            _ => panic!("Expected DropTable fact"),
        }
    }

    #[test]
    fn test_drop_table_cascade() {
        let sql = "DROP TABLE users CASCADE;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::DropTable { name, cascade, .. } => {
                assert_eq!(name.name.resolve(), "users");
                assert!(cascade);
            }
            _ => panic!("Expected DropTable fact"),
        }
    }

    #[test]
    fn test_create_index() {
        let sql = "CREATE INDEX idx_users_email ON users(email);";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::CreateIndex {
                name: _, relation, ..
            } => {
                assert_eq!(relation.name.resolve(), "users");
            }
            _ => panic!("Expected CreateIndex fact"),
        }
    }

    #[test]
    fn test_create_index_unique() {
        let sql = "CREATE UNIQUE INDEX idx_users_email ON users(email);";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::CreateIndex { unique, .. } => {
                assert!(unique);
            }
            _ => panic!("Expected CreateIndex fact"),
        }
    }

    #[test]
    fn test_create_index_concurrently() {
        let sql = "CREATE INDEX CONCURRENTLY idx_users_email ON users(email);";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::CreateIndex { concurrently, .. } => {
                assert!(concurrently);
            }
            _ => panic!("Expected CreateIndex fact"),
        }
    }

    #[test]
    fn test_create_index_with_predicate() {
        let sql = "CREATE INDEX idx_users_active ON users(id) WHERE active = true;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::CreateIndex { has_predicate, .. } => {
                assert!(has_predicate);
            }
            _ => panic!("Expected CreateIndex fact"),
        }
    }

    #[test]
    fn test_create_index_using_method() {
        let sql = "CREATE INDEX idx_users_gin ON users USING GIN(data);";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::CreateIndex { using_method, .. } => {
                assert!(using_method.is_some());
                assert_eq!(using_method.unwrap(), "GIN");
            }
            _ => panic!("Expected CreateIndex fact"),
        }
    }

    #[test]
    fn test_drop_index() {
        let sql = "DROP INDEX idx_users_email;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::DropIndex { names, .. } => {
                assert_eq!(names.len(), 1);
            }
            _ => panic!("Expected DropIndex fact"),
        }
    }

    #[test]
    fn test_vacuum_full() {
        let sql = "VACUUM FULL;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::Vacuum { relation, is_full } => {
                assert!(is_full);
                assert!(relation.is_none());
            }
            _ => panic!("Expected Vacuum fact"),
        }
    }

    #[test]
    fn test_vacuum() {
        let sql = "VACUUM;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::Vacuum { relation, is_full } => {
                assert!(!is_full);
                assert!(relation.is_none());
            }
            _ => panic!("Expected Vacuum fact"),
        }
    }

    #[test]
    fn test_vacuum_with_table() {
        let sql = "VACUUM FULL accounts;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::Vacuum { relation, is_full } => {
                assert!(is_full);
                assert!(relation.is_some());
                let rel = relation.unwrap();
                assert_eq!(rel.name.resolve(), "accounts");
                assert!(rel.schema.is_none());
            }
            _ => panic!("Expected Vacuum fact"),
        }
    }

    #[test]
    fn test_begin_transaction() {
        let sql = "BEGIN;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::BeginTransaction => {}
            _ => panic!("Expected BeginTransaction fact"),
        }
    }

    #[test]
    fn test_commit_transaction() {
        let sql = "COMMIT;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::CommitTransaction => {}
            _ => panic!("Expected CommitTransaction fact"),
        }
    }

    #[test]
    fn test_rollback() {
        let sql = "ROLLBACK;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::RollbackTransaction => {}
            _ => panic!("Expected RollbackTransaction fact"),
        }
    }

    #[test]
    fn test_rollback_to_savepoint() {
        let sql = "ROLLBACK TO SAVEPOINT sp1;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::RollbackToSavepoint { name } => {
                assert_eq!(name, "sp1");
            }
            _ => panic!("Expected RollbackToSavepoint fact"),
        }
    }

    #[test]
    fn test_savepoint() {
        let sql = "SAVEPOINT sp1;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::Savepoint { name } => {
                assert_eq!(name, "sp1");
            }
            _ => panic!("Expected Savepoint fact"),
        }
    }

    #[test]
    fn test_release_savepoint() {
        let sql = "RELEASE SAVEPOINT sp1;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::ReleaseSavepoint { name } => {
                assert_eq!(name, "sp1");
            }
            _ => panic!("Expected ReleaseSavepoint fact"),
        }
    }

    #[test]
    fn test_set_search_path_default() {
        let sql = "SET search_path TO DEFAULT;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::SetSearchPath {
                target: crate::analysis::facts::SearchPathTarget::Default,
            } => {}
            _ => panic!("Expected SetSearchPath fact"),
        }
    }

    #[test]
    fn test_create_schema() {
        let sql = "CREATE SCHEMA my_schema;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::CreateSchema { name, .. } => {
                assert_eq!(name.name.resolve(), "my_schema");
            }
            _ => panic!("Expected CreateSchema fact"),
        }
    }

    #[test]
    fn test_drop_schema() {
        let sql = "DROP SCHEMA my_schema CASCADE;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::DropSchema { names, cascade, .. } => {
                assert!(!names.is_empty());
                assert!(cascade);
            }
            _ => panic!("Expected DropSchema fact"),
        }
    }

    #[test]
    fn test_alter_schema() {
        let sql = "ALTER SCHEMA my_schema RENAME TO new_schema;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::AlterSchema { name, new_name } => {
                assert_eq!(name.name.resolve(), "my_schema");
                assert!(new_name.is_some());
            }
            _ => panic!("Expected AlterSchema fact"),
        }
    }

    #[test]
    fn test_create_view() {
        let sql = "CREATE VIEW user_view AS SELECT id, name FROM users;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::CreateView { name, .. } => {
                assert_eq!(name.name.resolve(), "user_view");
            }
            _ => panic!("Expected CreateView fact"),
        }
    }

    #[test]
    fn test_drop_view() {
        let sql = "DROP VIEW user_view CASCADE;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::DropView { name, cascade, .. } => {
                assert_eq!(name.name.resolve(), "user_view");
                assert!(cascade);
            }
            _ => panic!("Expected DropView fact"),
        }
    }

    #[test]
    fn test_create_materialized_view() {
        let sql = "CREATE MATERIALIZED VIEW mv_users AS SELECT * FROM users;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::CreateMaterializedView { name, .. } => {
                assert_eq!(name.name.resolve(), "mv_users");
            }
            _ => panic!("Expected CreateMaterializedView fact"),
        }
    }

    #[test]
    fn test_drop_materialized_view() {
        let sql = "DROP MATERIALIZED VIEW mv_users;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::DropMaterializedView { names, .. } => {
                assert!(!names.is_empty());
            }
            _ => panic!("Expected DropMaterializedView fact"),
        }
    }

    #[test]
    fn test_refresh_materialized_view() {
        let sql = "REFRESH MATERIALIZED VIEW mv_users;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::RefreshMaterializedView { name, .. } => {
                assert_eq!(name.name.resolve(), "mv_users");
            }
            _ => panic!("Expected RefreshMaterializedView fact"),
        }
    }

    #[test]
    fn test_alter_table_attach_partition() {
        let sql = "ALTER TABLE parent ATTACH PARTITION child FOR VALUES FROM (1) TO (100);";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
    }

    #[test]
    fn test_alter_table_detach_partition() {
        let sql = "ALTER TABLE parent DETACH PARTITION child;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
    }

    #[test]
    fn test_ident_resolve_quoted() {
        let ident = Ident::new("MyIdent".to_string(), true);
        assert_eq!(ident.resolve(), "MyIdent");
    }

    #[test]
    fn test_ident_resolve_unquoted() {
        let ident = Ident::new("MyIdent".to_string(), false);
        assert_eq!(ident.resolve(), "myident");
    }

    #[test]
    fn test_qualified_name_new() {
        let schema = Some(Ident::new("my_schema".to_string(), false));
        let name = Ident::new("my_table".to_string(), false);
        let qname = QualifiedName::new(schema.clone(), name.clone());
        assert!(qname.schema.is_some());
        assert_eq!(qname.name.resolve(), "my_table");
    }

    // ========================================================================
    // Expression IR Tests - Direct ExprIr tests
    // ========================================================================

    #[test]
    fn test_expr_ir_is_volatile_literal() {
        let expr = ExprIr::Literal("static_value".into());
        assert!(!expr.is_volatile());
    }

    #[test]
    fn test_expr_ir_is_volatile_column_ref() {
        let expr = ExprIr::ColumnRef("column_name".into());
        assert!(!expr.is_volatile());
    }

    #[test]
    fn test_expr_ir_is_volatile_omitted() {
        let expr = ExprIr::Omitted;
        assert!(!expr.is_volatile());
    }

    #[test]
    fn test_expr_ir_is_volatile_now() {
        let expr = ExprIr::FunctionCall {
            name: "now".into(),
            args: vec![],
        };
        assert!(!expr.is_volatile());
    }

    #[test]
    fn test_expr_ir_is_volatile_random() {
        let expr = ExprIr::FunctionCall {
            name: "random".into(),
            args: vec![],
        };
        assert!(expr.is_volatile());
    }

    #[test]
    fn test_expr_ir_is_volatile_gen_random_uuid() {
        let expr = ExprIr::FunctionCall {
            name: "gen_random_uuid".into(),
            args: vec![],
        };
        assert!(expr.is_volatile());
    }

    #[test]
    fn test_expr_ir_is_volatile_case_expr() {
        let expr = ExprIr::FunctionCall {
            name: "<case>".into(),
            args: vec![ExprIr::FunctionCall {
                name: "random".into(),
                args: vec![],
            }],
        };
        assert!(expr.is_volatile());
    }

    #[test]
    fn test_expr_ir_is_volatile_binary_op() {
        let expr = ExprIr::BinaryOp {
            left: Box::new(ExprIr::FunctionCall {
                name: "random".into(),
                args: vec![],
            }),
            op: "||".into(),
            right: Box::new(ExprIr::Literal("test".into())),
        };
        assert!(expr.is_volatile());
    }

    #[test]
    fn test_expr_ir_is_volatile_cast() {
        let expr = ExprIr::Cast {
            expr: Box::new(ExprIr::FunctionCall {
                name: "random".into(),
                args: vec![],
            }),
            target_type: "text".into(),
        };
        assert!(expr.is_volatile());
    }

    #[test]
    fn test_now_is_stable_not_volatile() {
        let expr = ExprIr::FunctionCall {
            name: "now".to_string(),
            args: vec![],
        };
        assert!(!expr.is_volatile(), "now() should be STABLE, not VOLATILE");
    }

    #[test]
    fn test_current_timestamp_is_stable() {
        let expr = ExprIr::FunctionCall {
            name: "current_timestamp".to_string(),
            args: vec![],
        };
        assert!(!expr.is_volatile(), "current_timestamp should be STABLE");
    }

    #[test]
    fn test_clock_timestamp_is_volatile() {
        let expr = ExprIr::FunctionCall {
            name: "clock_timestamp".to_string(),
            args: vec![],
        };
        assert!(expr.is_volatile(), "clock_timestamp() should be VOLATILE");
    }

    // ========================================================================
    // Multiple statements tests
    // ========================================================================

    #[test]
    fn test_multiple_statements() {
        let sql = "
            CREATE TABLE users (id INT);
            CREATE TABLE orders (id INT);
            DROP TABLE users;
        ";
        let facts = parse_and_extract(sql);
        assert_eq!(facts.len(), 3);
    }

    #[test]
    fn test_do_block() {
        let sql = "DO $$ BEGIN RAISE NOTICE 'hello'; END $$;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::OpaqueBlock => {}
            _ => panic!("Expected OpaqueBlock fact"),
        }
    }

    #[test]
    fn test_execute_stmt() {
        let sql = "EXECUTE my_plan;";
        let facts = parse_and_extract_statement(sql);
        assert!(facts.is_some());
        match facts.unwrap() {
            StatementFact::Execute => {}
            _ => panic!("Expected Execute fact"),
        }
    }
}
