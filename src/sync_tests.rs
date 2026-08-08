use crate::ast::identifiers::ObjectId;
use crate::db::cache::DbCache;
use crate::model::relation::{Persistence, RelationKind, RelationState};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{
        cache_search_path, is_local_host, is_system_schema, parse_search_path_setting,
        relation_owner_id, sync_cache,
    };
    use crate::test_support::EnvironmentValueGuard;
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
        rel.columns.push(crate::model::column::Column {
            name: "id".into(),
            data_type: Some("integer".into()),
            is_nullable: false,
            default: None,
            avg_width: Some(4),
            default_expr_text: None,
            type_modifier: None,
        });
        cache.insert_baseline(id.clone(), rel);

        // Add foreign key
        cache.foreign_keys.push(crate::db::cache::ForeignKeyCache {
            constraint_name: "fk_test".into(),
            from_table: ObjectId::new("public", "child"),
            to_table: ObjectId::new("public", "parent"),
        });

        // Add index
        cache.indexes.push(crate::db::cache::IndexCache {
            index_id: ObjectId::new("public", "idx_test"),
            table_id: ObjectId::new("public", "test_table"),
        });
        let type_id = ObjectId::new("app", "status");
        cache.types.insert(
            type_id.clone(),
            crate::model::types::TypeState {
                id: type_id.clone(),
                generation: 0,
                kind: crate::model::types::TypeKind::Enum {
                    variants: vec!["new".into(), "active".into()],
                },
            },
        );

        // Serialize to JSON
        let versioned = crate::db::cache::DbCacheVersioned::V5(Box::new(cache));
        let config = bincode::config::standard().with_variable_int_encoding();
        let encoded = bincode::serde::encode_to_vec(&versioned, config).unwrap();

        // Deserialize back
        let decoded: crate::db::cache::DbCacheVersioned =
            bincode::serde::decode_from_slice(&encoded, config)
                .unwrap()
                .0;
        let crate::db::cache::DbCacheVersioned::V5(deserialized) = decoded else {
            panic!("Expected V5");
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
        assert_eq!(
            deserialized.metadata.schemas.as_deref(),
            Some(["app".to_string(), "public".to_string()].as_slice())
        );
        assert_eq!(deserialized.search_path, ["app", "public"]);
        assert!(
            deserialized
                .relations
                .contains_key(&ObjectId::new("public", "test_table"))
        );
        assert_eq!(deserialized.foreign_keys.len(), 1);
        assert_eq!(deserialized.indexes.len(), 1);
        assert_eq!(
            deserialized.types.get(&type_id).map(|state| &state.kind),
            Some(&crate::model::types::TypeKind::Enum {
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
        rel.columns.push(crate::model::column::Column {
            name: "val".into(),
            data_type: Some("varchar".into()),
            is_nullable: true,
            default: None,
            avg_width: Some(10),
            default_expr_text: Some("now()".into()),
            type_modifier: Some(255 + 4),
        });
        cache.insert_baseline(id.clone(), rel);

        let versioned = crate::db::cache::DbCacheVersioned::V5(Box::new(cache));
        let config = bincode::config::standard().with_variable_int_encoding();
        let encoded = bincode::serde::encode_to_vec(&versioned, config).unwrap();
        let decoded: crate::db::cache::DbCacheVersioned =
            bincode::serde::decode_from_slice(&encoded, config)
                .unwrap()
                .0;
        let crate::db::cache::DbCacheVersioned::V5(deserialized) = decoded else {
            panic!("Expected V5");
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
    fn test_v3_cache_requires_resync() {
        let error = crate::db::cache::DbCacheVersioned::V3
            .into_cache()
            .unwrap_err();
        assert!(error.contains("unsupported"));
    }
}
