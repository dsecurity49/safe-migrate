// FILE: src/sync.rs

use crate::ast::identifiers::ObjectId;
use crate::db::cache::DbCache;
use crate::model::relation::{Persistence, RelationKind, RelationState};
use anyhow::{Context, Result};
use postgres::{Client, NoTls};
use std::fs;
use std::path::Path;

pub fn sync_cache(db_url: &str, out_path: &Path) -> Result<()> {
    let mut client =
        Client::connect(db_url, NoTls).context("Failed to connect to PostgreSQL")?;

    let mut cache = DbCache::new();

    // Query 1: Relations + Staleness
    let table_query = "
        SELECT
            n.nspname AS schema_name,
            c.relname AS relation_name,
            c.relkind AS relation_kind,
            c.relpersistence AS persistence,
            CASE WHEN c.reltuples < 0 THEN -1 ELSE c.reltuples::bigint END AS estimated_rows,
            GREATEST(c.relpages::bigint, 0) AS relpages,
            to_char(s.last_analyze, 'YYYY-MM-DD HH24:MI:SS') AS last_analyze,
            to_char(s.last_autoanalyze, 'YYYY-MM-DD HH24:MI:SS') AS last_autoanalyze
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
        WHERE c.relkind IN ('r', 'p', 'v', 'm')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema');
    ";

    for row in client.query(table_query, &[])? {
        let schema_name: String = row.get("schema_name");
        let relation_name: String = row.get("relation_name");
        let relkind: i8 = row.get("relation_kind");
        let persistence_char: i8 = row.get("persistence");
        let raw_rows: i64 = row.get("estimated_rows");
        let relpages: i64 = row.get("relpages");
        
        let last_analyze: Option<String> = row.get("last_analyze");
        let last_autoanalyze: Option<String> = row.get("last_autoanalyze");

        let object_id = ObjectId::new(schema_name, relation_name);

        let kind = match relkind as u8 {
            b'v' => RelationKind::View,
            b'm' => RelationKind::MaterializedView,
            _ => RelationKind::Table,
        };

        let persistence = match persistence_char as u8 {
            b't' => Persistence::Temporary,
            b'u' => Persistence::Unlogged,
            _ => Persistence::Permanent,
        };

        let estimated_rows = if raw_rows < 0 {
            None
        } else {
            Some(raw_rows as u64)
        };

        let mut state = RelationState::new(object_id.clone(), 0, estimated_rows, kind, persistence);
        state.relpages = Some(relpages as u64);
        state.last_analyze = last_analyze;
        state.last_autoanalyze = last_autoanalyze;

        cache.insert_baseline(object_id, state);
    }

    // Query 2: Columns + Width
    let col_query = "
        SELECT
            n.nspname AS schema_name,
            c.relname AS relation_name,
            a.attname AS column_name,
            pg_catalog.format_type(a.atttypid, a.atttypmod) AS type_name,
            a.attnotnull AS not_null,
            s.avg_width AS avg_width
        FROM pg_attribute a
        JOIN pg_class c ON a.attrelid = c.oid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_stats s ON s.schemaname = n.nspname AND s.tablename = c.relname AND s.attname = a.attname
        WHERE a.attnum > 0 AND NOT a.attisdropped
          AND c.relkind IN ('r', 'p', 'v', 'm')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema');
    ";

    for row in client.query(col_query, &[])? {
        let schema_name: String = row.get("schema_name");
        let relation_name: String = row.get("relation_name");
        let column_name: String = row.get("column_name");
        let type_name: String = row.get("type_name");
        let not_null: bool = row.get("not_null");
        let avg_width: Option<i32> = row.get("avg_width");

        let object_id = ObjectId::new(schema_name, relation_name);

        if let Some(rel) = cache.relations.get_mut(&object_id) {
            rel.columns.push(crate::model::column::Column {
                name: column_name,
                data_type: Some(type_name),
                is_nullable: !not_null,
                default: None,
                avg_width,
            });
        }
    }

    let json = serde_json::to_string_pretty(&cache)?;
    fs::write(out_path, json).context("Failed to write cache file")?;

    Ok(())
}
