// FILE: src/sync.rs

use crate::ast::identifiers::ObjectId;
use crate::db::cache::{DbCache, ForeignKeyCache, IndexCache};
use crate::model::relation::{Persistence, RelationKind, RelationState};
use anyhow::{Context, Result};
use postgres::{Client, NoTls};
use std::fs;
use std::path::Path;

pub fn sync_cache(out_path: &Path) -> Result<()> {
    // Strict env-only credential enforcement
    let db_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL environment variable is required to sync database stats. Do not pass credentials via CLI flags or config files.")?;

    // Destructive cache removal prevents corrupted reads on failures
    if out_path.exists() {
        fs::remove_file(out_path).context("Failed to remove old cache file before sync")?;
    }

    let mut client = Client::connect(&db_url, NoTls).context("Failed to connect to PostgreSQL")?;

    let mut cache = DbCache::new();

    // Query 1: Server Version
    let version_row = client.query_one("SHOW server_version_num;", &[])?;
    let version_str: String = version_row.get(0);
    cache.pg_version_num = version_str.parse::<u32>().ok();

    // Query 2: Relations + Staleness
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

        let object_id = ObjectId::new(&schema_name, &relation_name);

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

        let mut state =
            RelationState::new(object_id.clone(), ObjectId::new("public", "postgres"), 0, estimated_rows, kind, persistence, 0);
        state.relpages = Some(relpages as u64);
        state.last_analyze = last_analyze;
        state.last_autoanalyze = last_autoanalyze;

        cache.insert_baseline(object_id, state);
    }

    // Query 3: Columns + Width
    let col_query = "
        SELECT
            n.nspname AS schema_name,
            c.relname AS relation_name,
            a.attname AS column_name,
            pg_catalog.format_type(a.atttypid, a.atttypmod) AS type_name,
            a.attnotnull AS not_null,
            s.avg_width AS avg_width,
            pg_get_expr(ad.adbin, ad.adrelid) AS default_expr_text,
            a.atttypmod AS type_modifier
        FROM pg_attribute a
        JOIN pg_class c ON a.attrelid = c.oid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_stats s ON s.schemaname = n.nspname AND s.tablename = c.relname AND s.attname = a.attname
        LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
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
        let default_expr_text: Option<String> = row.get("default_expr_text");
        let type_modifier: Option<i32> = row.get("type_modifier");

        let object_id = ObjectId::new(&schema_name, &relation_name);

        if let Some(rel) = cache.relations.get_mut(&object_id) {
            rel.columns.push(crate::model::column::Column {
                name: column_name,
                data_type: Some(type_name),
                is_nullable: !not_null,
                default: None,
                avg_width,
                default_expr_text,
                type_modifier,
            });
        }
    }

    // Query 4: Triggers & Policies
    let tp_query = "
        SELECT 
            n.nspname AS schema_name,
            c.relname AS relation_name,
            COALESCE(array_agg(DISTINCT t.tgname) FILTER (WHERE t.tgname IS NOT NULL AND t.tgisinternal = false), '{}') as triggers,
            COALESCE(array_agg(DISTINCT p.polname) FILTER (WHERE p.polname IS NOT NULL), '{}') as policies
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_trigger t ON t.tgrelid = c.oid
        LEFT JOIN pg_policy p ON p.polrelid = c.oid
        WHERE c.relkind IN ('r', 'p', 'v', 'm') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
        GROUP BY n.nspname, c.relname;
    ";

    for row in client.query(tp_query, &[])? {
        let schema_name: String = row.get("schema_name");
        let relation_name: String = row.get("relation_name");
        let triggers: Vec<String> = row.get("triggers");
        let policies: Vec<String> = row.get("policies");

        let object_id = ObjectId::new(&schema_name, &relation_name);

        if let Some(rel) = cache.relations.get_mut(&object_id) {
            rel.triggers.extend(triggers);
            rel.policies.extend(policies);
        }
    }

    // Query 5: Foreign Keys
    let fk_query = "
        SELECT 
            c.conname AS constraint_name,
            n1.nspname AS from_schema, t1.relname AS from_table,
            n2.nspname AS to_schema, t2.relname AS to_table
        FROM pg_constraint c
        JOIN pg_class t1 ON t1.oid = c.conrelid
        JOIN pg_namespace n1 ON n1.oid = t1.relnamespace
        JOIN pg_class t2 ON t2.oid = c.confrelid
        JOIN pg_namespace n2 ON n2.oid = t2.relnamespace
        WHERE c.contype = 'f';
    ";

    for row in client.query(fk_query, &[])? {
        let constraint_name: String = row.get("constraint_name");
        let from_schema: String = row.get("from_schema");
        let from_table: String = row.get("from_table");
        let to_schema: String = row.get("to_schema");
        let to_table: String = row.get("to_table");

        cache.foreign_keys.push(ForeignKeyCache {
            constraint_name,
            from_table: ObjectId::new(&from_schema, &from_table),
            to_table: ObjectId::new(&to_schema, &to_table),
        });
    }

    // Query 6: Indexes
    let idx_query = "
        SELECT 
            n_i.nspname AS index_schema, i.relname AS index_name,
            n_t.nspname AS table_schema, t.relname AS table_name
        FROM pg_index x
        JOIN pg_class i ON i.oid = x.indexrelid
        JOIN pg_namespace n_i ON n_i.oid = i.relnamespace
        JOIN pg_class t ON t.oid = x.indrelid
        JOIN pg_namespace n_t ON n_t.oid = t.relnamespace
        WHERE x.indisvalid = true;
    ";

    for row in client.query(idx_query, &[])? {
        let index_schema: String = row.get("index_schema");
        let index_name: String = row.get("index_name");
        let table_schema: String = row.get("table_schema");
        let table_name: String = row.get("table_name");

        cache.indexes.push(IndexCache {
            index_id: ObjectId::new(&index_schema, &index_name),
            table_id: ObjectId::new(&table_schema, &table_name),
        });
    }

    // Atomic write via temp file
    let json = serde_json::to_string_pretty(&cache)?;
    let tmp_path = out_path.with_extension("tmp");

    fs::write(&tmp_path, json).context("Failed to write temporary cache file")?;
    fs::rename(&tmp_path, out_path).context("Failed to atomically rename cache file")?;

    Ok(())
}
