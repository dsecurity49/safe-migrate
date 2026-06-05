use crate::model::{CacheData, CacheEntry};
use anyhow::{Context, Result};
use postgres::{Client, NoTls};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn sync_cache(db_url: &str, out_path: &Path) -> Result<()> {
    let mut client = Client::connect(db_url, NoTls).context("Failed to connect to PostgreSQL")?;

    let mut tables = HashMap::new();

    // FIX: Explcitly trap -1 (unanalyzed tables) to safely force a fallback to u64::MAX
    let table_query = "
        SELECT
            n.nspname || '.' || c.relname AS canonical_key,
            CASE WHEN c.reltuples < 0 THEN -1 ELSE c.reltuples::bigint END AS estimated_rows,
            GREATEST(c.relpages::bigint, 0) AS relpages
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema');
    ";

    for row in client.query(table_query, &[])? {
        let key: String = row.get("canonical_key");
        let raw_rows: i64 = row.get("estimated_rows");
        let relpages: i64 = row.get("relpages");

        // If table is unanalyzed (-1), assume worst case scenario
        let estimated_rows = if raw_rows < 0 {
            u64::MAX
        } else {
            raw_rows as u64
        };

        tables.insert(
            key,
            CacheEntry {
                estimated_rows,
                relpages: Some(relpages as u64),
            },
        );
    }

    let mut indexes = HashMap::new();
    let index_query = "
        SELECT
            n.nspname || '.' || i.relname AS index_key,
            n.nspname || '.' || t.relname AS table_key
        FROM pg_index x
        JOIN pg_class i ON i.oid = x.indexrelid
        JOIN pg_class t ON t.oid = x.indrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace;
    ";

    for row in client.query(index_query, &[])? {
        let index_key: String = row.get("index_key");
        let table_key: String = row.get("table_key");
        indexes.insert(index_key, table_key);
    }

    let cache = CacheData {
        last_updated: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        tables,
        indexes,
    };

    let json = serde_json::to_string_pretty(&cache)?;
    fs::write(out_path, json).context("Failed to write cache file")?;

    Ok(())
}
