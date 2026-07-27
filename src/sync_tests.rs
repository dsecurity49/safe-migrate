use crate::ast::identifiers::ObjectId;
use crate::db::cache::DbCache;
use crate::model::relation::{Persistence, RelationKind, RelationState};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::sync_cache;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_sync_cache_failure_no_db_url() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path();

        // Ensure DATABASE_URL is not set
        unsafe {
            std::env::remove_var("DATABASE_URL");
        }

        let result = sync_cache(path, None, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_sync_failure_preserves_existing_cache() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"known-good-cache").unwrap();
        tmp.flush().unwrap();

        unsafe {
            std::env::remove_var("DATABASE_URL");
        }

        assert!(sync_cache(tmp.path(), None, false).is_err());
        assert_eq!(std::fs::read(tmp.path()).unwrap(), b"known-good-cache");
    }

    #[test]
    fn test_db_cache_serialization_roundtrip() {
        let mut cache = DbCache::new();
        cache.pg_version_num = Some(160000);
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
        let versioned = crate::db::cache::DbCacheVersioned::V5(cache);
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

        let versioned = crate::db::cache::DbCacheVersioned::V5(cache);
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
    fn test_db_cache_atomic_write_pattern() {
        // This test validates that the temp->rename atomic write pattern used
        // in sync_cache works correctly by manually simulating it.
        let tmp_file = NamedTempFile::new().unwrap();
        let final_path = tmp_file.path().to_path_buf();
        let tmp_path = final_path.with_extension("tmp");

        // Write to temp
        let cache = DbCache::new();
        let json = serde_json::to_string_pretty(&cache).unwrap();
        let mut tmp = std::fs::File::create(&tmp_path).unwrap();
        tmp.write_all(json.as_bytes()).unwrap();
        drop(tmp);

        // Atomically rename
        std::fs::rename(&tmp_path, &final_path).unwrap();

        // Verify temp is gone and final exists
        assert!(!tmp_path.exists());
        assert!(final_path.exists());

        // Read back
        let content = std::fs::read_to_string(&final_path).unwrap();
        let deserialized: DbCache = serde_json::from_str(&content).unwrap();
        assert!(deserialized.pg_version_num.is_none());
    }
}
