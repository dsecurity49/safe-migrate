// FILE: src/ast/visitor_tests.rs

#[cfg(test)]
mod tests {
    use crate::analysis::expr_ir::ExprIr;
    use crate::analysis::facts::{
        AlterTableActionFact, AlterTypeActionFact, StatementFact, TableConstraintFact,
        TypeCreationKind,
    };
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
    fn test_create_table_preserves_inline_constraint_names() {
        let fact = parse_and_extract_statement(
            "CREATE TABLE users (
                id integer CONSTRAINT users_pk PRIMARY KEY,
                email text CONSTRAINT users_email_unique UNIQUE,
                tenant_id integer,
                CONSTRAINT users_tenant_unique UNIQUE (tenant_id)
            );",
        )
        .expect("create table fact");

        let StatementFact::CreateTable {
            columns,
            table_constraints,
            ..
        } = fact
        else {
            panic!("expected create table fact");
        };
        assert_eq!(
            columns[0].primary_key_constraint_name.as_deref(),
            Some("users_pk")
        );
        assert_eq!(
            columns[1].unique_constraint_name.as_deref(),
            Some("users_email_unique")
        );
        assert!(matches!(
            &table_constraints[0],
            TableConstraintFact::Unique {
                constraint_name: Some(name),
                columns,
            } if name == "users_tenant_unique" && columns == &["tenant_id"]
        ));
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
    fn test_quoted_identifiers_unescape_doubled_quotes() {
        let facts = parse_and_extract(
            r#"
            CREATE SCHEMA "schema""name";
            CREATE TABLE "table""name" ("column""name" int);
            CREATE POLICY "policy""name" ON "table""name";
            CREATE TRIGGER "trigger""name" BEFORE INSERT ON "table""name"
                FOR EACH ROW EXECUTE FUNCTION "function""name"();
        "#,
        );

        match &facts[0] {
            StatementFact::CreateSchema { name, .. } => {
                assert_eq!(name.name.resolve(), "schema\"name");
            }
            _ => panic!("expected create schema fact"),
        }
        match &facts[1] {
            StatementFact::CreateTable { name, columns, .. } => {
                assert_eq!(name.name.resolve(), "table\"name");
                assert_eq!(columns[0].name, "column\"name");
            }
            _ => panic!("expected create table fact"),
        }
        match &facts[2] {
            StatementFact::CreatePolicy { name, .. } => assert_eq!(name, "policy\"name"),
            _ => panic!("expected create policy fact"),
        }
        match &facts[3] {
            StatementFact::CreateTrigger { name, function, .. } => {
                assert_eq!(name, "trigger\"name");
                assert_eq!(function.as_ref().unwrap().name.resolve(), "function\"name");
            }
            _ => panic!("expected create trigger fact"),
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
    fn create_enum_extracts_ordered_and_escaped_labels() {
        let fact = parse_and_extract_statement(
            r#"CREATE TYPE "Mood" AS ENUM ('sad', 'it''s fine', E'line\nbreak');"#,
        )
        .expect("create type fact");

        let StatementFact::CreateType(create_type) = fact else {
            panic!("expected create type fact");
        };
        assert_eq!(create_type.name.name.resolve(), "Mood");
        assert!(create_type.name.name.quoted);
        assert_eq!(
            create_type.kind,
            TypeCreationKind::Enum {
                variants: vec!["sad".into(), "it's fine".into(), "line\nbreak".into()]
            }
        );
    }

    #[test]
    fn alter_type_rename_value_extracts_qualified_identity_and_labels() {
        let fact = parse_and_extract_statement(
            r#"ALTER TYPE sm_core."Mood" RENAME VALUE 'it''s fine' TO 'it''s great';"#,
        )
        .expect("alter type fact");

        let StatementFact::AlterType(alter_type) = fact else {
            panic!("expected alter type fact");
        };
        assert_eq!(
            alter_type
                .name
                .schema
                .as_ref()
                .map(|schema| schema.resolve()),
            Some("sm_core".to_string())
        );
        assert_eq!(alter_type.name.name.resolve(), "Mood");
        assert!(alter_type.name.name.quoted);
        assert_eq!(
            alter_type.actions,
            vec![AlterTypeActionFact::RenameValue {
                old_value: "it's fine".into(),
                new_value: "it's great".into(),
            }]
        );
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
    fn test_alter_table_unique_using_index() {
        let fact = parse_and_extract_statement(
            "ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE USING INDEX users_email_key;",
        )
        .expect("alter table fact");

        let StatementFact::AlterTable { actions, .. } = fact else {
            panic!("expected alter table fact");
        };
        let AlterTableActionFact::AddUniqueConstraint {
            constraint_name,
            using_index,
        } = &actions[0]
        else {
            panic!("expected unique constraint fact");
        };
        assert_eq!(constraint_name.as_deref(), Some("users_email_key"));
        assert_eq!(
            using_index.as_ref().map(|name| name.name.resolve()),
            Some("users_email_key".to_string())
        );
    }

    #[test]
    fn test_alter_table_primary_key_using_index() {
        let fact = parse_and_extract_statement(
            "ALTER TABLE users ADD CONSTRAINT users_pkey PRIMARY KEY USING INDEX users_id_key;",
        )
        .expect("alter table fact");

        let StatementFact::AlterTable { actions, .. } = fact else {
            panic!("expected alter table fact");
        };
        let AlterTableActionFact::AddPrimaryKeyConstraint {
            constraint_name,
            using_index,
        } = &actions[0]
        else {
            panic!("expected primary-key constraint fact");
        };
        assert_eq!(constraint_name.as_deref(), Some("users_pkey"));
        assert_eq!(
            using_index.as_ref().map(|name| name.name.resolve()),
            Some("users_id_key".to_string())
        );
    }

    #[test]
    fn test_alter_table_exclusion_constraint() {
        let fact = parse_and_extract_statement(
            "ALTER TABLE reservations ADD CONSTRAINT no_overlap EXCLUDE USING gist (period WITH &&);",
        )
        .expect("alter table fact");

        let StatementFact::AlterTable { actions, .. } = fact else {
            panic!("expected alter table fact");
        };
        assert!(matches!(
            actions.as_slice(),
            [AlterTableActionFact::AddExcludeConstraint { constraint_name }]
                if constraint_name.as_deref() == Some("no_overlap")
        ));
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
    fn test_commit_and_chain() {
        let facts = parse_and_extract_statement("COMMIT AND CHAIN;");
        assert!(matches!(facts, Some(StatementFact::CommitAndChain)));

        let facts = parse_and_extract_statement("COMMIT AND NO CHAIN;");
        assert!(matches!(facts, Some(StatementFact::CommitTransaction)));
    }

    #[test]
    fn test_rollback_and_chain() {
        let facts = parse_and_extract_statement("ROLLBACK AND CHAIN;");
        assert!(matches!(facts, Some(StatementFact::RollbackAndChain)));

        let facts = parse_and_extract_statement("ROLLBACK AND NO CHAIN;");
        assert!(matches!(facts, Some(StatementFact::RollbackTransaction)));
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
    fn test_savepoint_identifier_casing_matches_postgres() {
        let unquoted = parse_and_extract_statement("SAVEPOINT MixedCase;").unwrap();
        assert!(matches!(
            unquoted,
            StatementFact::Savepoint { name } if name == "mixedcase"
        ));

        let quoted = parse_and_extract_statement("SAVEPOINT \"MixedCase\";").unwrap();
        assert!(matches!(
            quoted,
            StatementFact::Savepoint { name } if name == "MixedCase"
        ));

        let escaped = parse_and_extract_statement("SAVEPOINT \"a\"\"b\";").unwrap();
        assert!(matches!(
            escaped,
            StatementFact::Savepoint { name } if name == "a\"b"
        ));

        for (sql, expected) in [
            ("ROLLBACK TO MixedCase;", "mixedcase"),
            ("ROLLBACK TO \"MixedCase\";", "MixedCase"),
            ("RELEASE SAVEPOINT MixedCase;", "mixedcase"),
            ("RELEASE SAVEPOINT \"MixedCase\";", "MixedCase"),
        ] {
            let fact = parse_and_extract_statement(sql).unwrap();
            match fact {
                StatementFact::RollbackToSavepoint { name }
                | StatementFact::ReleaseSavepoint { name } => assert_eq!(name, expected),
                _ => panic!("expected savepoint reference"),
            }
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
    fn test_set_search_path_preserves_user_placeholder() {
        let facts = parse_and_extract_statement("SET search_path TO \"$user\", public;")
            .expect("search_path fact");
        assert_eq!(
            facts,
            StatementFact::SetSearchPath {
                target: crate::analysis::facts::SearchPathTarget::Schemas(vec![
                    "$user".into(),
                    "public".into(),
                ]),
            }
        );
    }

    #[test]
    fn test_set_time_zone_does_not_produce_a_search_path_fact() {
        assert!(parse_and_extract_statement("SET TIME ZONE DEFAULT;").is_none());
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
