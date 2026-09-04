use crate::_internal::ast::identifiers::ObjectId;
use crate::_internal::db::cache::DbCache;
use crate::_internal::model::relation::{Persistence, RelationKind, RelationState};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::_internal::sync::{
        cache_search_path, database_config_is_local, ensure_supported_postgres_version,
        is_local_host, is_system_schema, parse_search_path_setting, relation_owner_id, sync_cache,
    };
    use crate::_internal::test_support::EnvironmentValueGuard;
    use serde::Serialize;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_sync_cache_failure_no_db_url() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path();

        let _database_url = EnvironmentValueGuard::remove("DATABASE_URL");

        let result = sync_cache(path, None, false);
        let error = result.expect_err("sync without DATABASE_URL must fail");
        assert!(
            error
                .to_string()
                .contains("sync PostgreSQL schema metadata and statistics")
        );
    }

    #[test]
    fn test_sync_failure_preserves_existing_cache() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"known-good-cache").unwrap();
        tmp.flush().unwrap();

        let _database_url = EnvironmentValueGuard::remove("DATABASE_URL");

        assert!(sync_cache(tmp.path(), None, false).is_err());
        assert_eq!(std::fs::read(tmp.path()).unwrap(), b"known-good-cache");
    }

    fn assert_invalid_database_url_preserves_existing_cache(database_url: &str) {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"known-good-cache").unwrap();
        tmp.flush().unwrap();

        let _database_url = EnvironmentValueGuard::set("DATABASE_URL", database_url);
        let error = sync_cache(tmp.path(), None, false).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("DATABASE_URL must not be empty or whitespace")
        );
        assert_eq!(std::fs::read(tmp.path()).unwrap(), b"known-good-cache");
    }

    #[test]
    fn test_blank_database_url_failure_preserves_existing_cache() {
        assert_invalid_database_url_preserves_existing_cache("");
    }

    #[test]
    fn test_whitespace_database_url_failure_preserves_existing_cache() {
        assert_invalid_database_url_preserves_existing_cache(" \t\r\n");
    }

    #[test]
    fn test_remote_host_detection_keeps_local_connections_supported() {
        assert!(is_local_host("localhost"));
        assert!(is_local_host("127.0.0.1"));
        assert!(is_local_host("::1"));
        assert!(is_local_host("[::1]"));
        assert!(is_local_host("/var/run/postgresql"));
        assert!(!is_local_host("db.internal.example"));
        assert!(!is_local_host("127.0.0.1.attacker.example"));
    }

    #[test]
    fn test_database_config_rejects_remote_hostaddr() {
        let local: postgres::Config = "host=localhost hostaddr=127.0.0.1 dbname=safe_migrate"
            .parse()
            .unwrap();
        let remote: postgres::Config = "host=localhost hostaddr=10.0.0.5 dbname=safe_migrate"
            .parse()
            .unwrap();

        assert!(database_config_is_local(&local));
        assert!(!database_config_is_local(&remote));
    }

    #[test]
    fn remote_database_rejection_does_not_echo_credentials() {
        let tmp = NamedTempFile::new().unwrap();
        let secret = "phase5-password-must-not-leak";
        let database_url =
            format!("postgres://migration_user:{secret}@db.internal.example/safe_migrate");
        let _database_url = EnvironmentValueGuard::set("DATABASE_URL", &database_url);

        let error = sync_cache(tmp.path(), None, false).unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("Remote DATABASE_URL connections are not supported"));
        assert!(!diagnostic.contains(secret));
        assert!(!diagnostic.contains(&database_url));
    }

    #[test]
    fn test_sync_requires_postgresql_14_or_newer() {
        let error = ensure_supported_postgres_version(130_012).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires PostgreSQL 14 or newer")
        );
        assert!(ensure_supported_postgres_version(140_000).is_ok());
    }

    #[test]
    fn test_scoped_sync_uses_the_explicit_scope_as_search_path() {
        let database_search_path = vec!["tenant".into(), "public".into()];
        let schemas = vec!["public".into(), "auth".into()];

        assert_eq!(
            cache_search_path(database_search_path, Some(&schemas)),
            ["public", "auth"]
        );
    }

    #[test]
    fn test_scoped_sync_preserves_live_priority_within_the_scope() {
        let database_search_path = vec!["tenant".into(), "public".into()];
        let schemas = vec!["public".into(), "tenant".into(), "auth".into()];

        assert_eq!(
            cache_search_path(database_search_path, Some(&schemas)),
            ["tenant", "public", "auth"]
        );
    }

    #[test]
    fn test_unscoped_sync_preserves_the_database_search_path() {
        let database_search_path = vec!["tenant".into(), "public".into()];

        assert_eq!(
            cache_search_path(database_search_path.clone(), None),
            database_search_path
        );
    }

    #[test]
    fn test_search_path_setting_parser_preserves_user_and_quoted_identifiers() {
        assert_eq!(
            parse_search_path_setting("\"$user\", public, \"Mixed,Schema\", \"a\"\"b\""),
            ["$user", "public", "Mixed,Schema", "a\"b"]
        );
    }

    #[test]
    fn test_synced_relation_owner_uses_role_identity() {
        assert_eq!(
            relation_owner_id("app_owner"),
            ObjectId::new("", "app_owner")
        );
    }

    #[test]
    fn test_system_schema_detection_covers_catalog_and_toast() {
        assert!(is_system_schema("pg_catalog"));
        assert!(is_system_schema("pg_toast"));
        assert!(is_system_schema("information_schema"));
        assert!(!is_system_schema("public"));
        assert!(!is_system_schema("app"));
    }

    #[test]
    fn test_db_cache_serialization_roundtrip() {
        let mut cache = DbCache::new();
        cache.pg_version_num = Some(160000);
        cache.metadata.created_at_unix_secs = Some(1_700_000_000);
        cache.metadata.source_database = Some("app".into());
        cache.metadata.source_role = Some("app_user".into());
        cache.metadata.source_session_role = Some("login_user".into());
        cache.metadata.source_search_path = Some(vec!["$user".into(), "public".into()]);
        cache.metadata.source_lock_timeout_ms = 750;
        cache.metadata.source_statement_timeout_ms = 30_000;
        cache.metadata.schemas = Some(vec!["app".into(), "public".into()]);
        cache.search_path = vec!["app".into(), "public".into()];

        // Add a relation
        let id = ObjectId::new("public", "test_table");
        let mut rel = RelationState::new(
            id.clone(),
            ObjectId::new("public", "postgres"),
            0,
            Some(1000),
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        rel.columns.push(crate::_internal::model::column::Column {
            name: "id".into(),
            data_type: Some("integer".into()),
            type_id: None,
            is_nullable: false,
            default: None,
            avg_width: Some(4),
            default_expr_text: None,
            type_modifier: None,
        });
        cache.insert_baseline(id.clone(), rel);

        // Add foreign key
        cache
            .foreign_keys
            .push(crate::_internal::db::cache::ForeignKeyCache {
                constraint_name: "fk_test".into(),
                from_table: ObjectId::new("public", "child"),
                to_table: ObjectId::new("public", "parent"),
                from_columns: vec!["parent_id".into()],
                to_columns: vec!["id".into()],
                pk_fk_equality_operators: vec!["=".into()],
                pk_pk_equality_operators: vec!["=".into()],
                fk_fk_equality_operators: vec!["=".into()],
            });

        // Add index
        cache.indexes.push(crate::_internal::db::cache::IndexCache {
            index_id: ObjectId::new("public", "idx_test"),
            table_id: ObjectId::new("public", "test_table"),
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
        let type_id = ObjectId::new("app", "status");
        cache.types.insert(
            type_id.clone(),
            crate::_internal::model::types::TypeState {
                id: type_id.clone(),
                generation: 0,
                kind: crate::_internal::model::types::TypeKind::Enum {
                    variants: vec!["new".into(), "active".into()],
                },
            },
        );
        cache.publications.insert(
            "app_changes".into(),
            crate::_internal::model::replication::PublicationState {
                name: "app_changes".into(),
                owner: Some("app_user".into()),
                scope: crate::_internal::analysis::facts::PublicationScope::Explicit(vec![
                    crate::_internal::analysis::facts::PublicationObjectFact::Table {
                        name: crate::_internal::ast::identifiers::QualifiedName::new(
                            Some(crate::_internal::ast::identifiers::Ident::new(
                                "public", true,
                            )),
                            crate::_internal::ast::identifiers::Ident::new("test_table", true),
                        ),
                        only: true,
                        include_partitions: false,
                        columns: Some(vec!["id".into()]),
                        row_filter: Some(
                            crate::_internal::analysis::facts::PublicationRowFilter::CatalogSql(
                                "id > 0".into(),
                            ),
                        ),
                    },
                ]),
                params: vec![crate::_internal::analysis::facts::AttributeFact {
                    name: "publish".into(),
                    value: "insert, update".into(),
                }],
                generation: 0,
            },
        );
        cache.subscriptions.insert(
            "app_subscriber".into(),
            crate::_internal::model::replication::SubscriptionState {
                name: "app_subscriber".into(),
                owner: Some("app_user".into()),
                connection: crate::_internal::analysis::facts::ConnectionTarget::Redacted,
                publications: vec!["app_changes".into()],
                params: Some(vec![crate::_internal::analysis::facts::AttributeFact {
                    name: "streaming".into(),
                    value: "parallel".into(),
                }]),
                enabled: false,
                slot_name: None,
                generation: 0,
            },
        );

        // Cache V7 uses bincode.
        let versioned = crate::_internal::db::cache::DbCacheVersioned::V7(Box::new(cache));
        let config = bincode::config::standard().with_variable_int_encoding();
        let encoded = bincode::serde::encode_to_vec(&versioned, config).unwrap();

        let decoded: crate::_internal::db::cache::DbCacheVersioned =
            bincode::serde::decode_from_slice(&encoded, config)
                .unwrap()
                .0;
        let crate::_internal::db::cache::DbCacheVersioned::V7(deserialized) = decoded else {
            panic!("Expected V7");
        };
        assert_eq!(deserialized.pg_version_num, Some(160000));
        assert_eq!(
            deserialized.metadata.created_at_unix_secs,
            Some(1_700_000_000)
        );
        assert_eq!(
            deserialized.metadata.source_database.as_deref(),
            Some("app")
        );
        assert_eq!(
            deserialized.metadata.source_role.as_deref(),
            Some("app_user")
        );
        assert_eq!(
            deserialized.metadata.source_session_role.as_deref(),
            Some("login_user")
        );
        assert_eq!(
            deserialized.metadata.source_search_path.as_deref(),
            Some(["$user".to_string(), "public".to_string()].as_slice())
        );
        assert_eq!(deserialized.metadata.source_lock_timeout_ms, 750);
        assert_eq!(deserialized.metadata.source_statement_timeout_ms, 30_000);
        assert_eq!(
            deserialized.metadata.schemas.as_deref(),
            Some(["app".to_string(), "public".to_string()].as_slice())
        );
        assert_eq!(deserialized.search_path, ["app", "public"]);
        assert!(matches!(
            deserialized
                .subscriptions
                .get("app_subscriber")
                .map(|subscription| &subscription.connection),
            Some(crate::_internal::analysis::facts::ConnectionTarget::Redacted)
        ));
        assert_eq!(deserialized.publications.len(), 1);
        assert_eq!(deserialized.subscriptions.len(), 1);
        assert!(
            deserialized
                .relations
                .contains_key(&ObjectId::new("public", "test_table"))
        );
        assert_eq!(deserialized.foreign_keys.len(), 1);
        assert_eq!(deserialized.indexes.len(), 1);
        assert_eq!(
            deserialized.types.get(&type_id).map(|state| &state.kind),
            Some(&crate::_internal::model::types::TypeKind::Enum {
                variants: vec!["new".into(), "active".into()]
            })
        );

        // Verify relation stats survived
        let rel = deserialized
            .relations
            .get(&ObjectId::new("public", "test_table"))
            .unwrap();
        assert_eq!(rel.estimated_rows, Some(1000));
        assert_eq!(rel.columns.len(), 1);
        assert_eq!(rel.columns[0].name, "id");
    }

    #[test]
    fn test_db_cache_column_sync_fields() {
        let mut cache = DbCache::new();
        let id = ObjectId::new("public", "test_table");
        let mut rel = RelationState::new(
            id.clone(),
            ObjectId::new("public", "postgres"),
            0,
            None,
            RelationKind::Table,
            Persistence::Permanent,
            0,
        );
        rel.columns.push(crate::_internal::model::column::Column {
            name: "val".into(),
            data_type: Some("varchar".into()),
            type_id: None,
            is_nullable: true,
            default: None,
            avg_width: Some(10),
            default_expr_text: Some("now()".into()),
            type_modifier: Some(255 + 4),
        });
        cache.insert_baseline(id.clone(), rel);

        let versioned = crate::_internal::db::cache::DbCacheVersioned::V7(Box::new(cache));
        let config = bincode::config::standard().with_variable_int_encoding();
        let encoded = bincode::serde::encode_to_vec(&versioned, config).unwrap();
        let decoded: crate::_internal::db::cache::DbCacheVersioned =
            bincode::serde::decode_from_slice(&encoded, config)
                .unwrap()
                .0;
        let crate::_internal::db::cache::DbCacheVersioned::V7(deserialized) = decoded else {
            panic!("Expected V7");
        };
        let rel = deserialized.relations.get(&id).unwrap();
        assert_eq!(rel.columns[0].default_expr_text, Some("now()".into()));
        assert_eq!(rel.columns[0].type_modifier, Some(259));
    }

    #[test]
    fn test_db_cache_empty_serialization() {
        let cache = DbCache::new();
        let json = serde_json::to_string_pretty(&cache).unwrap();
        assert!(json.contains("pg_version_num"));

        let deserialized: DbCache = serde_json::from_str(&json).unwrap();
        assert!(deserialized.pg_version_num.is_none());
        assert!(deserialized.relations.is_empty());
        assert!(deserialized.foreign_keys.is_empty());
        assert!(deserialized.indexes.is_empty());
    }

    #[test]
    fn routine_kind_is_part_of_the_final_v6_layout() {
        #[derive(Serialize)]
        struct LegacyFunctionState {
            id: ObjectId,
            arg_types: Vec<String>,
            return_type: String,
            volatility: crate::_internal::model::function::Volatility,
            language: String,
            security: crate::_internal::model::function::SecurityMode,
        }

        let id = ObjectId::new("public", "accepts_mood(mood)");
        let legacy = LegacyFunctionState {
            id: id.clone(),
            arg_types: vec!["mood".into()],
            return_type: "mood".into(),
            volatility: crate::_internal::model::function::Volatility::Volatile,
            language: "sql".into(),
            security: crate::_internal::model::function::SecurityMode::Invoker,
        };
        let config = bincode::config::standard().with_variable_int_encoding();
        let legacy_bytes = bincode::serde::encode_to_vec(&legacy, config).unwrap();

        for routine_kind in [
            crate::_internal::model::function::RoutineKind::Function,
            crate::_internal::model::function::RoutineKind::Procedure,
            crate::_internal::model::function::RoutineKind::Aggregate,
            crate::_internal::model::function::RoutineKind::Window,
        ] {
            let current = crate::_internal::model::function::FunctionState {
                id: id.clone(),
                routine_kind,
                arg_types: vec!["mood".into()],
                arg_type_ids: vec![Some(ObjectId::new("public", "mood"))],
                return_type: "mood".into(),
                return_type_id: Some(ObjectId::new("public", "mood")),
                volatility: crate::_internal::model::function::Volatility::Volatile,
                language: "sql".into(),
                security: crate::_internal::model::function::SecurityMode::Invoker,
            };
            let current_bytes = bincode::serde::encode_to_vec(&current, config).unwrap();
            assert_ne!(current_bytes, legacy_bytes);
            let restored: crate::_internal::model::function::FunctionState =
                bincode::serde::decode_from_slice(&current_bytes, config)
                    .unwrap()
                    .0;
            assert_eq!(restored.routine_kind, routine_kind);
            assert!(restored.arg_type_ids.is_empty());
            assert!(restored.return_type_id.is_none());
        }

        assert!(
            bincode::serde::decode_from_slice::<crate::_internal::model::function::FunctionState, _>(
                &legacy_bytes,
                config,
            )
            .is_err(),
            "the pre-release routine layout must require a fresh V7 sync"
        );
    }

    #[test]
    fn cache_column_payloads_missing_semantic_fields_require_resync() {
        #[derive(Serialize)]
        struct LegacyColumn {
            name: String,
            data_type: Option<String>,
            is_nullable: bool,
            default: Option<crate::_internal::analysis::expr_ir::ExprIr>,
            avg_width: Option<i32>,
        }

        let legacy = LegacyColumn {
            name: "created_at".into(),
            data_type: Some("timestamp".into()),
            is_nullable: false,
            default: None,
            avg_width: Some(8),
        };
        let config = bincode::config::standard().with_variable_int_encoding();
        let bytes = bincode::serde::encode_to_vec(legacy, config).unwrap();
        assert!(
            bincode::serde::decode_from_slice::<crate::_internal::model::column::Column, _>(
                &bytes, config
            )
            .is_err(),
            "cache payloads without default/type evidence must require a fresh V7 sync"
        );
    }

    #[test]
    fn domain_type_identity_link_does_not_change_the_cache_bincode_layout() {
        #[allow(dead_code)]
        #[derive(Serialize)]
        enum LegacyTypeKind {
            Enum { variants: Vec<String> },
            Domain { base_type: String },
            Base,
            Composite,
            Range,
        }

        let legacy = LegacyTypeKind::Domain {
            base_type: "mood".into(),
        };
        let current = crate::_internal::model::types::TypeKind::Domain {
            base_type: "mood".into(),
            base_type_id: Some(ObjectId::new("public", "mood")),
        };
        let config = bincode::config::standard().with_variable_int_encoding();
        let legacy_bytes = bincode::serde::encode_to_vec(&legacy, config).unwrap();
        let current_bytes = bincode::serde::encode_to_vec(&current, config).unwrap();

        assert_eq!(current_bytes, legacy_bytes);
        let restored: crate::_internal::model::types::TypeKind =
            bincode::serde::decode_from_slice(&legacy_bytes, config)
                .unwrap()
                .0;
        assert!(matches!(
            restored,
            crate::_internal::model::types::TypeKind::Domain {
                base_type,
                base_type_id: None,
            } if base_type == "mood"
        ));
    }

    #[test]
    fn test_v3_cache_requires_resync() {
        let error = crate::_internal::db::cache::DbCacheVersioned::V3
            .into_cache()
            .unwrap_err();
        assert!(error.contains("unsupported"));
    }
}
