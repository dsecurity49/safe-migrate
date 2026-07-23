// FILE: src/sync.rs

use crate::ast::identifiers::ObjectId;
use crate::db::cache::{DbCache, ForeignKeyCache, IndexCache};
use crate::model::relation::{Persistence, RelationKind, RelationState};
use anyhow::{Context, Result};
use postgres::{Client, NoTls};
use std::fs;
use std::path::Path;

pub fn sync_cache(out_path: &Path, schemas: Option<&[String]>) -> Result<()> {
    // Strict env-only credential enforcement
    let db_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL environment variable is required to sync database stats. Do not pass credentials via CLI flags or config files.")?;

    // Destructive cache removal prevents corrupted reads on failures
    if out_path.exists() {
        fs::remove_file(out_path).context("Failed to remove old cache file before sync")?;
    }

    // Warn if connecting to a non-local host without TLS
    let host = db_url
        .split('@')
        .nth(1)
        .and_then(|h| h.split('/').next())
        .unwrap_or("localhost");
    if !host.starts_with("localhost")
        && !host.starts_with("127.")
        && !host.starts_with("/")
        && host != "::1"
    {
        eprintln!(
            "[WARN] Connecting to PostgreSQL at {} without TLS encryption.\n\
             The database password will be sent in cleartext over the network.\n\
             Use an SSH tunnel or a local connection for sensitive databases,\n\
             or add native-tls support (see https://github.com/dsecurity49/safe-migrate).",
            host
        );
    }

    let mut client = Client::connect(&db_url, NoTls).context("Failed to connect to PostgreSQL")?;

    let cache = populate_cache(&mut client, schemas)?;

    // Atomic write via temp file
    let tmp_path = out_path.with_extension("tmp");
    let file = std::fs::File::create(&tmp_path).context("Failed to create temporary cache file")?;
    let writer = std::io::BufWriter::new(file);
    let mut encoder =
        zstd::stream::Encoder::new(writer, 3).context("Failed to init zstd compression")?;

    let versioned = crate::db::cache::DbCacheVersioned::V2(cache);
    let bincode_config = bincode::config::standard().with_variable_int_encoding();

    bincode::serde::encode_into_std_write(&versioned, &mut encoder, bincode_config)
        .context("Failed binary bincode 2.0 schema compilation and write")?;

    encoder
        .finish()
        .context("Failed to flush final zstd stream to disk")?;

    fs::rename(&tmp_path, out_path).context("Failed to atomically rename cache file")?;

    Ok(())
}

pub fn populate_cache(client: &mut Client, schemas: Option<&[String]>) -> Result<DbCache> {
    let mut cache = DbCache::new();

    let schema_filter = if let Some(s) = schemas {
        format!("AND n.nspname = ANY(ARRAY['{}'])", s.join("','"))
    } else {
        "".to_string()
    };

    let schema_filter_with_fk = if let Some(s) = schemas {
        let arr = format!("ARRAY['{}']", s.join("','"));
        format!(
            "AND (
            n.nspname = ANY({arr})
            OR c.oid IN (
                SELECT conrelid FROM pg_constraint cst
                JOIN pg_class c2 ON c2.oid = cst.confrelid
                JOIN pg_namespace n2 ON n2.oid = c2.relnamespace
                WHERE n2.nspname = ANY({arr})
            )
            OR c.oid IN (
                SELECT confrelid FROM pg_constraint cst
                JOIN pg_class c2 ON c2.oid = cst.conrelid
                JOIN pg_namespace n2 ON n2.oid = c2.relnamespace
                WHERE n2.nspname = ANY({arr})
            )
        )"
        )
    } else {
        "".to_string()
    };

    let schema_filter_n1_or_n2 = if let Some(s) = schemas {
        let arr = format!("ARRAY['{}']", s.join("','"));
        format!("AND (n1.nspname = ANY({arr}) OR n2.nspname = ANY({arr}))")
    } else {
        "".to_string()
    };

    let schema_filter_nt = if let Some(s) = schemas {
        let arr = format!("ARRAY['{}']", s.join("','"));
        format!(
            "AND (
            n_t.nspname = ANY({arr})
            OR t.oid IN (
                SELECT conrelid FROM pg_constraint cst
                JOIN pg_class c2 ON c2.oid = cst.confrelid
                JOIN pg_namespace n2 ON n2.oid = c2.relnamespace
                WHERE n2.nspname = ANY({arr})
            )
            OR t.oid IN (
                SELECT confrelid FROM pg_constraint cst
                JOIN pg_class c2 ON c2.oid = cst.conrelid
                JOIN pg_namespace n2 ON n2.oid = c2.relnamespace
                WHERE n2.nspname = ANY({arr})
            )
        )"
        )
    } else {
        "".to_string()
    };

    // Query 1: Server Version
    let version_row = client.query_one("SHOW server_version_num;", &[])?;
    let version_str: String = version_row.get(0);
    cache.pg_version_num = version_str.parse::<u32>().ok();

    // Query 2: Relations + Staleness
    let table_query = format!(
        "
        SELECT
            n.nspname AS schema_name,
            c.relname AS relation_name,
            c.relkind AS relation_kind,
            c.relpersistence AS persistence,
            CASE WHEN c.reltuples < 0 THEN -1 ELSE c.reltuples::bigint END AS estimated_rows,
            c.relpages::bigint AS relpages,
            to_char(s.last_analyze, 'YYYY-MM-DD HH24:MI:SS') AS last_analyze,
            to_char(s.last_autoanalyze, 'YYYY-MM-DD HH24:MI:SS') AS last_autoanalyze,
            p.partstrat::text AS partition_strategy
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
        LEFT JOIN pg_partitioned_table p ON p.partrelid = c.oid
        WHERE c.relkind IN ('r', 'p', 'v', 'm')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk};
    "
    );

    for row in client.query(&table_query, &[])? {
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

        let mut state = RelationState::new(
            object_id.clone(),
            ObjectId::new("public", "postgres"),
            0,
            estimated_rows,
            kind,
            persistence,
            0,
        );
        state.relpages = Some(relpages as u64);
        state.last_analyze = last_analyze;
        state.last_autoanalyze = last_autoanalyze;

        let partition_strategy: Option<String> = row.get("partition_strategy");
        if let Some(ref strat) = partition_strategy {
            state.partition_type = Some(match strat.as_str() {
                "r" => "RANGE".to_string(),
                "l" => "LIST".to_string(),
                "h" => "HASH".to_string(),
                _ => strat.to_uppercase(),
            });
        }

        if let Some(s) = schemas
            && !s.contains(&schema_name)
        {
            state.mark_fk_dependency();
        }

        cache.insert_baseline(object_id, state);
    }

    // Query 3: Columns + Width
    let col_query = format!("
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
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk}
        ORDER BY n.nspname, c.relname;
    ");

    let mut current_object_id: Option<ObjectId> = None;
    let mut current_rel: Option<*mut crate::model::relation::RelationState> = None;

    for row in client.query(&col_query, &[])? {
        let schema_name: String = row.get("schema_name");
        let relation_name: String = row.get("relation_name");
        let column_name: String = row.get("column_name");
        let type_name: String = row.get("type_name");
        let not_null: bool = row.get("not_null");
        let avg_width: Option<i32> = row.get("avg_width");
        let default_expr_text: Option<String> = row.get("default_expr_text");
        let type_modifier: Option<i32> = row.get("type_modifier");

        // Fast path: reuse the mutable reference if the relation hasn't changed
        let is_same_rel = if let Some(ref cur) = current_object_id {
            cur.schema == schema_name && cur.name == relation_name
        } else {
            false
        };

        if !is_same_rel {
            let new_oid = ObjectId::new(&schema_name, &relation_name);
            if let Some(rel) = cache.relations.get_mut(&new_oid) {
                current_rel = Some(rel as *mut _);
            } else {
                current_rel = None;
            }
            current_object_id = Some(new_oid);
        }

        if let Some(rel_ptr) = current_rel {
            // SAFE: We are strictly single-threaded here, iterating rows sequentially.
            // We just need a way to bypass the borrow checker for caching the map lookup.
            let rel = unsafe { &mut *rel_ptr };
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
    let tp_query = format!("
        SELECT 
            n.nspname AS schema_name,
            c.relname AS relation_name,
            COALESCE(array_agg(DISTINCT t.tgname) FILTER (WHERE t.tgname IS NOT NULL AND t.tgisinternal = false), '{{}}') as triggers,
            COALESCE(array_agg(DISTINCT p.polname) FILTER (WHERE p.polname IS NOT NULL), '{{}}') as policies
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_trigger t ON t.tgrelid = c.oid
        LEFT JOIN pg_policy p ON p.polrelid = c.oid
        WHERE c.relkind IN ('r', 'p', 'v', 'm') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
        {schema_filter_with_fk}
        GROUP BY n.nspname, c.relname;
    ");

    for row in client.query(&tp_query, &[])? {
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

    // Query 4.5: Trigger Functions
    let trig_query = format!(
        "
        SELECT 
            n.nspname AS table_schema,
            c.relname AS table_name,
            t.tgname AS trigger_name,
            fn.nspname AS function_schema,
            f.proname || '()' AS function_name
        FROM pg_trigger t
        JOIN pg_class c ON c.oid = t.tgrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_proc f ON f.oid = t.tgfoid
        JOIN pg_namespace fn ON fn.oid = f.pronamespace
        WHERE t.tgisinternal = false
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          {schema_filter_with_fk};
    "
    );

    for row in client.query(&trig_query, &[])? {
        let table_schema: String = row.get("table_schema");
        let table_name: String = row.get("table_name");
        let trigger_name: String = row.get("trigger_name");
        let function_schema: String = row.get("function_schema");
        let function_name: String = row.get("function_name");

        cache.triggers.push(crate::db::cache::TriggerCache {
            trigger_id: ObjectId::new(&table_schema, &trigger_name),
            table_id: ObjectId::new(&table_schema, &table_name),
            function_id: ObjectId::new(&function_schema, &function_name),
        });
    }

    // Query 5: Foreign Keys
    let fk_query = format!(
        "
        SELECT 
            c.conname AS constraint_name,
            n1.nspname AS from_schema, t1.relname AS from_table,
            n2.nspname AS to_schema, t2.relname AS to_table
        FROM pg_constraint c
        JOIN pg_class t1 ON t1.oid = c.conrelid
        JOIN pg_namespace n1 ON n1.oid = t1.relnamespace
        JOIN pg_class t2 ON t2.oid = c.confrelid
        JOIN pg_namespace n2 ON n2.oid = t2.relnamespace
        WHERE c.contype = 'f'
        {schema_filter_n1_or_n2};
    "
    );

    for row in client.query(&fk_query, &[])? {
        let constraint_name: String = row.get("constraint_name");
        let from_schema: String = row.get("from_schema");
        let from_table: String = row.get("from_table");
        let to_schema: String = row.get("to_schema");
        let to_table: String = row.get("to_table");

        if let Some(s) = schemas
            && (!s.contains(&from_schema) || !s.contains(&to_schema))
        {
            // Determine which one is out of scope to print a helpful warning
            let out_of_scope_schema = if !s.contains(&from_schema) {
                &from_schema
            } else {
                &to_schema
            };
            let out_of_scope_table = if !s.contains(&from_schema) {
                &from_table
            } else {
                &to_table
            };
            eprintln!(
                "[WARN] Foreign key '{}' crosses schema boundary. Table '{}.{}' was pulled into cache as a dependency to evaluate cross-team locks.",
                constraint_name, out_of_scope_schema, out_of_scope_table
            );
        }

        cache.foreign_keys.push(ForeignKeyCache {
            constraint_name,
            from_table: ObjectId::new(&from_schema, &from_table),
            to_table: ObjectId::new(&to_schema, &to_table),
        });
    }

    // Query 6: Indexes
    let idx_query = format!(
        "
        SELECT 
            n_i.nspname AS index_schema, i.relname AS index_name,
            n_t.nspname AS table_schema, t.relname AS table_name
        FROM pg_index x
        JOIN pg_class i ON i.oid = x.indexrelid
        JOIN pg_namespace n_i ON n_i.oid = i.relnamespace
        JOIN pg_class t ON t.oid = x.indrelid
        JOIN pg_namespace n_t ON n_t.oid = t.relnamespace
        WHERE x.indisvalid = true
        {schema_filter_nt};
    "
    );

    for row in client.query(&idx_query, &[])? {
        let index_schema: String = row.get("index_schema");
        let index_name: String = row.get("index_name");
        let table_schema: String = row.get("table_schema");
        let table_name: String = row.get("table_name");

        cache.indexes.push(IndexCache {
            index_id: ObjectId::new(&index_schema, &index_name),
            table_id: ObjectId::new(&table_schema, &table_name),
        });
    }

    // Query 7: Functions
    let func_query = format!(
        "
        SELECT
            n.nspname AS schema_name,
            p.proname AS func_name,
            COALESCE(
                (SELECT string_agg(pg_catalog.format_type(t, NULL), ',' ORDER BY n)
                 FROM unnest(p.proargtypes::int[]) WITH ORDINALITY AS u(t, n)),
                ''
            ) AS arg_types,
            pg_catalog.pg_get_function_result(p.oid) AS return_type,
            p.provolatile::text AS volatility,
            l.lanname AS language,
            p.prosecdef AS security_definer
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_language l ON l.oid = p.prolang
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND p.prokind = 'f'
          {schema_filter};
    "
    );

    for row in client.query(&func_query, &[])? {
        let schema_name: String = row.get("schema_name");
        let func_name: String = row.get("func_name");
        let arg_types_str: String = row.get("arg_types");
        let return_type: Option<String> = row.get("return_type");
        let volatility_char: String = row.get("volatility");
        let language: String = row.get("language");
        let security_definer: bool = row.get("security_definer");

        let volatility = match volatility_char.as_str() {
            "v" => crate::model::function::Volatility::Volatile,
            "s" => crate::model::function::Volatility::Stable,
            "i" => crate::model::function::Volatility::Immutable,
            _ => crate::model::function::Volatility::Volatile,
        };

        let security = if security_definer {
            crate::model::function::SecurityMode::Definer
        } else {
            crate::model::function::SecurityMode::Invoker
        };

        // Normalize argument types in sync just like in resolver
        let arg_types_str = arg_types_str
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .collect::<Vec<_>>()
            .join(",");

        let id = ObjectId::new(&schema_name, format!("{}({})", func_name, arg_types_str));

        let arg_types = if arg_types_str.is_empty() {
            Vec::new()
        } else {
            arg_types_str.split(',').map(|s| s.to_string()).collect()
        };

        cache.functions.insert(
            id.clone(),
            crate::model::function::FunctionState {
                id,
                arg_types,
                return_type: return_type.unwrap_or_default(),
                volatility,
                language,
                security,
            },
        );
    }

    // 7. Dependencies (pg_depend)
    let depend_query = r#"
        SELECT
            d.classid, d.objid, d.objsubid,
            d.refclassid, d.refobjid, d.refobjsubid,
            d.deptype::text,
            n1.nspname AS obj_schema, COALESCE(c1.relname, p1.proname, t1.typname) AS obj_name,
            n2.nspname AS ref_schema, COALESCE(c2.relname, p2.proname, t2.typname) AS ref_name
        FROM pg_depend d
        LEFT JOIN pg_class c1 ON c1.oid = d.objid AND d.classid = 'pg_class'::regclass
        LEFT JOIN pg_namespace n1 ON n1.oid = c1.relnamespace
        LEFT JOIN pg_proc p1 ON p1.oid = d.objid AND d.classid = 'pg_proc'::regclass
        LEFT JOIN pg_namespace n1p ON n1p.oid = p1.pronamespace
        LEFT JOIN pg_type t1 ON t1.oid = d.objid AND d.classid = 'pg_type'::regclass
        LEFT JOIN pg_namespace n1t ON n1t.oid = t1.typnamespace
        LEFT JOIN pg_class c2 ON c2.oid = d.refobjid AND d.refclassid = 'pg_class'::regclass
        LEFT JOIN pg_namespace n2 ON n2.oid = c2.relnamespace
        LEFT JOIN pg_proc p2 ON p2.oid = d.refobjid AND d.refclassid = 'pg_proc'::regclass
        LEFT JOIN pg_namespace n2p ON n2p.oid = p2.pronamespace
        LEFT JOIN pg_type t2 ON t2.oid = d.refobjid AND d.refclassid = 'pg_type'::regclass
        LEFT JOIN pg_namespace n2t ON n2t.oid = t2.typnamespace
        WHERE d.deptype IN ('n', 'a', 'i')
          AND (n1.nspname NOT IN ('pg_catalog', 'information_schema') OR n1.nspname IS NULL)
    "#;

    for row in client.query(depend_query, &[])? {
        let classid: u32 = row.get(0);
        let objid: u32 = row.get(1);
        let objsubid: i32 = row.get(2);
        let refclassid: u32 = row.get(3);
        let refobjid: u32 = row.get(4);
        let refobjsubid: i32 = row.get(5);
        let deptype: String = row.get(6);
        let obj_schema: Option<String> = row.get(7);
        let obj_name: Option<String> = row.get(8);
        let ref_schema: Option<String> = row.get(9);
        let ref_name: Option<String> = row.get(10);

        cache.dependencies.push(crate::db::cache::DependencyCache {
            classid,
            objid,
            objsubid,
            refclassid,
            refobjid,
            refobjsubid,
            deptype,
            obj_schema,
            obj_name,
            ref_schema,
            ref_name,
        });
    }

    Ok(cache)
}
