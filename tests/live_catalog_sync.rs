mod common;

use crate::common::database_hosts_are_local;
use std::fs;
use std::io::Read;

use safe_migrate::analysis::facts::{
    ConnectionTarget, PublicationObjectFact, PublicationRowFilter, PublicationScope,
};
use safe_migrate::analysis::state::AnalysisState;
use safe_migrate::ast::identifiers::ObjectId;
use safe_migrate::db::cache::{CACHE_V6_MAGIC, DbCacheVersioned};
use safe_migrate::engine::config::Config;
use safe_migrate::engine::engine::SafeMigrateEngine;
use safe_migrate::model::function::{FunctionOverlay, RoutineKind, SecurityMode, Volatility};
use safe_migrate::model::replication::{PublicationOverlay, SubscriptionOverlay};
use safe_migrate::sync::sync_cache;

const SCHEMA: &str = "sm_v6_catalog";
const SECOND_SCHEMA: &str = "sm_v6_catalog_extra";
const PUBLICATION: &str = "sm_v6_catalog_publication";
const SCHEMA_PUBLICATION: &str = "sm_v6_schema_publication";
const SUBSCRIPTION: &str = "sm_v6_catalog_subscription";
const CONNECTION_SENTINEL: &str = "sm_v6_connection_secret_must_not_enter_cache";

fn cleanup(client: &mut postgres::Client) {
    let subscription_exists: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_subscription WHERE subname = $1)",
            &[&SUBSCRIPTION],
        )
        .expect("check live catalog subscription")
        .get(0);
    if subscription_exists {
        client
            .batch_execute(&format!(
                "ALTER SUBSCRIPTION {SUBSCRIPTION} DISABLE;
                 ALTER SUBSCRIPTION {SUBSCRIPTION} SET (slot_name = NONE);
                 DROP SUBSCRIPTION {SUBSCRIPTION};"
            ))
            .expect("remove live catalog subscription");
    }
    client
        .batch_execute(&format!(
            "DROP PUBLICATION IF EXISTS {PUBLICATION};
             DROP PUBLICATION IF EXISTS {SCHEMA_PUBLICATION};
             DROP SCHEMA IF EXISTS {SCHEMA} CASCADE;
             DROP SCHEMA IF EXISTS {SECOND_SCHEMA} CASCADE;"
        ))
        .expect("remove live catalog objects");
}

struct CatalogCleanup(postgres::Config);

impl Drop for CatalogCleanup {
    fn drop(&mut self) {
        if let Ok(mut client) = self.0.connect(postgres::NoTls) {
            cleanup(&mut client);
        }
    }
}

fn decode_cache(path: &std::path::Path) -> (safe_migrate::DbCache, Vec<u8>) {
    let encoded = fs::read(path).expect("read synchronized cache");
    let mut decoder = zstd::stream::Decoder::new(encoded.as_slice()).expect("decode cache zstd");
    let mut payload = Vec::new();
    decoder
        .read_to_end(&mut payload)
        .expect("read decoded cache payload");
    let v6_payload = payload
        .strip_prefix(CACHE_V6_MAGIC)
        .expect("catalog sync must write a V6 cache");
    let config = bincode::config::standard().with_variable_int_encoding();
    let (versioned, bytes_read): (DbCacheVersioned, usize) =
        bincode::serde::decode_from_slice(v6_payload, config).expect("decode V6 cache");
    assert_eq!(bytes_read, v6_payload.len());
    let DbCacheVersioned::V6(cache) = versioned else {
        panic!("catalog sync must encode the V6 cache variant");
    };
    (*cache, payload)
}

fn live_database() -> (postgres::Config, String, i32) {
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL is required for live catalog sync");
    let database_config: postgres::Config = database_url
        .parse()
        .expect("live catalog DATABASE_URL is invalid");
    assert!(
        database_hosts_are_local(&database_config),
        "live catalog sync accepts only localhost or Unix-socket databases"
    );
    let mut client = database_config
        .connect(postgres::NoTls)
        .expect("connect for live catalog sync");
    let identity = client
        .query_one(
            "SELECT current_database(), current_user, current_setting('server_version_num')::int",
            &[],
        )
        .expect("identify live catalog database");
    let database: String = identity.get(0);
    let owner: String = identity.get(1);
    let version: i32 = identity.get(2);
    assert_eq!(
        database, "safe_migrate",
        "live catalog sync refuses to modify a database not named safe_migrate"
    );
    (database_config, owner, version)
}

fn seed_catalog(client: &mut postgres::Client, version: i32) {
    cleanup(client);
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {SCHEMA};
             CREATE SCHEMA {SECOND_SCHEMA};
             CREATE TABLE {SCHEMA}.entries (id integer PRIMARY KEY, note text);
             CREATE TABLE {SECOND_SCHEMA}.audit_entries (id integer PRIMARY KEY);
             CREATE FUNCTION {SCHEMA}.with_out(value integer, OUT doubled integer)
               LANGUAGE sql IMMUTABLE AS 'SELECT value * 2';
             CREATE PROCEDURE {SCHEMA}.record_value(value integer)
               LANGUAGE sql AS 'SELECT value';
             CREATE FUNCTION {SCHEMA}.add_values(state integer, value integer)
               RETURNS integer LANGUAGE sql IMMUTABLE
               AS 'SELECT COALESCE(state, 0) + value';
             CREATE AGGREGATE {SCHEMA}.total(integer) (
               SFUNC = {SCHEMA}.add_values,
               STYPE = integer,
               INITCOND = '0'
             );
             CREATE FUNCTION {SCHEMA}.win_rank() RETURNS bigint
               AS 'window_row_number' LANGUAGE internal WINDOW;"
        ))
        .expect("create live routine catalog");

    let publication_sql = if version >= 180_000 {
        format!(
            "CREATE PUBLICATION {PUBLICATION}
               FOR TABLE {SCHEMA}.entries (id) WHERE (id > 0)
               WITH (publish = 'insert, update', publish_generated_columns = stored);
             CREATE PUBLICATION {SCHEMA_PUBLICATION}
               FOR TABLES IN SCHEMA {SECOND_SCHEMA};"
        )
    } else if version >= 150_000 {
        format!(
            "CREATE PUBLICATION {PUBLICATION}
               FOR TABLE {SCHEMA}.entries (id) WHERE (id > 0)
               WITH (publish = 'insert, update');
             CREATE PUBLICATION {SCHEMA_PUBLICATION}
               FOR TABLES IN SCHEMA {SECOND_SCHEMA};"
        )
    } else {
        format!(
            "CREATE PUBLICATION {PUBLICATION}
               FOR TABLE {SCHEMA}.entries
               WITH (publish = 'insert, update');"
        )
    };
    client
        .batch_execute(&publication_sql)
        .expect("create live publication catalog");
    let mut subscription_options = vec![
        "connect = false",
        "slot_name = NONE",
        "binary = true",
        "streaming = off",
        "synchronous_commit = local",
    ];
    if version >= 150_000 {
        subscription_options.extend(["two_phase = false", "disable_on_error = true"]);
    }
    if version >= 160_000 {
        subscription_options.extend([
            "password_required = false",
            "run_as_owner = true",
            "origin = none",
        ]);
    }
    if version >= 170_000 {
        subscription_options.push("failover = false");
    }
    client
        .batch_execute(&format!(
            "CREATE SUBSCRIPTION {SUBSCRIPTION}
               CONNECTION 'host=127.0.0.1 port=1 dbname=publisher user=replicator password={CONNECTION_SENTINEL}'
               PUBLICATION remote_publication
               WITH ({});",
            subscription_options.join(", ")
        ))
        .expect("create disconnected live subscription");
}

fn inspect_cache(path: &std::path::Path) -> serde_json::Value {
    let mut command = assert_cmd::Command::cargo_bin("safe-migrate").expect("safe-migrate binary");
    let output = command
        .arg("cache")
        .arg("inspect")
        .arg("--cache")
        .arg(path)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).expect("cache inspect JSON")
}

fn attributes(
    values: &[safe_migrate::analysis::facts::AttributeFact],
) -> std::collections::BTreeMap<&str, &str> {
    values
        .iter()
        .map(|attribute| (attribute.name.as_str(), attribute.value.as_str()))
        .collect()
}

fn assert_routine_matches(state: &AnalysisState, cache: &safe_migrate::DbCache, id: &ObjectId) {
    let Some(FunctionOverlay::Present(simulated)) = state.local.functions.get(id) else {
        panic!("simulator routine {id} is not present");
    };
    let synchronized = cache
        .functions
        .get(id)
        .unwrap_or_else(|| panic!("PostgreSQL routine {id} is not present"));
    let mut simulated = simulated.clone();
    simulated.arg_type_ids.clear();
    simulated.return_type_id = None;
    assert_eq!(&simulated, synchronized, "routine state differs for {id}");
}

fn assert_publication_matches(state: &AnalysisState, cache: &safe_migrate::DbCache, name: &str) {
    let Some(PublicationOverlay::Present(simulated)) = state.local.publications.get(name) else {
        panic!("simulator publication {name} is not present");
    };
    let synchronized = cache
        .publications
        .get(name)
        .unwrap_or_else(|| panic!("PostgreSQL publication {name} is not present"));
    let mut simulated = simulated.clone();
    simulated.generation = 0;
    simulated
        .params
        .sort_by(|left, right| left.name.cmp(&right.name));
    let mut synchronized = synchronized.clone();
    synchronized
        .params
        .sort_by(|left, right| left.name.cmp(&right.name));
    assert_eq!(
        simulated, synchronized,
        "publication state differs for {name}"
    );
}

fn assert_subscription_matches(state: &AnalysisState, cache: &safe_migrate::DbCache, name: &str) {
    let Some(SubscriptionOverlay::Present(simulated)) = state.local.subscriptions.get(name) else {
        panic!("simulator subscription {name} is not present");
    };
    let synchronized = cache
        .subscriptions
        .get(name)
        .unwrap_or_else(|| panic!("PostgreSQL subscription {name} is not present"));
    let mut simulated = simulated.clone();
    simulated.generation = 0;
    if let Some(params) = &mut simulated.params {
        params.sort_by(|left, right| left.name.cmp(&right.name));
    }
    let mut synchronized = synchronized.clone();
    if let Some(params) = &mut synchronized.params {
        params.sort_by(|left, right| left.name.cmp(&right.name));
    }
    assert_eq!(
        simulated, synchronized,
        "subscription state differs for {name}"
    );
}

#[test]
fn live_catalog_database_guard_accepts_only_local_hosts() {
    for value in [
        "host=/tmp dbname=safe_migrate",
        "host=localhost dbname=safe_migrate",
        "host=127.0.0.1 dbname=safe_migrate",
        "host=::1 dbname=safe_migrate",
    ] {
        let config: postgres::Config = value.parse().unwrap();
        assert!(database_hosts_are_local(&config), "{value}");
    }
    for value in [
        "host=db.internal.example dbname=safe_migrate",
        "host=127.0.0.1.attacker.example dbname=safe_migrate",
        "host=localhost hostaddr=10.0.0.5 dbname=safe_migrate",
    ] {
        let config: postgres::Config = value.parse().unwrap();
        assert!(!database_hosts_are_local(&config), "{value}");
    }
}

#[test]
#[ignore = "requires a live local PostgreSQL database via DATABASE_URL"]
fn live_sync_preserves_routine_and_replication_catalogs_without_connection_secrets() {
    let (database_config, expected_owner, version) = live_database();
    let _cleanup = CatalogCleanup(database_config.clone());
    let mut client = database_config
        .connect(postgres::NoTls)
        .expect("connect for live catalog sync");

    seed_catalog(&mut client, version);

    let temp_dir = tempfile::tempdir().expect("create live catalog temp directory");
    let cache_path = temp_dir.path().join("catalog.cache");
    sync_cache(&cache_path, None, false).expect("sync seeded live catalog");
    let (cache, decoded_payload) = decode_cache(&cache_path);

    let routine_kinds = cache
        .functions
        .values()
        .filter(|routine| routine.id.schema == SCHEMA)
        .map(|routine| routine.routine_kind)
        .collect::<Vec<_>>();
    for expected in [
        RoutineKind::Function,
        RoutineKind::Procedure,
        RoutineKind::Aggregate,
        RoutineKind::Window,
    ] {
        assert!(
            routine_kinds.contains(&expected),
            "synchronized routines omitted {expected:?} on PostgreSQL {version}"
        );
    }
    assert!(
        cache
            .functions
            .contains_key(&safe_migrate::ast::identifiers::ObjectId::new(
                SCHEMA,
                "with_out(integer)"
            ))
    );
    for (name, kind, args, result, volatility, language) in [
        (
            "with_out(integer)",
            RoutineKind::Function,
            vec!["integer"],
            "integer",
            Volatility::Immutable,
            "sql",
        ),
        (
            "record_value(integer)",
            RoutineKind::Procedure,
            vec!["integer"],
            "",
            Volatility::Volatile,
            "sql",
        ),
        (
            "add_values(integer,integer)",
            RoutineKind::Function,
            vec!["integer", "integer"],
            "integer",
            Volatility::Immutable,
            "sql",
        ),
        (
            "total(integer)",
            RoutineKind::Aggregate,
            vec!["integer"],
            "integer",
            Volatility::Immutable,
            "internal",
        ),
        (
            "win_rank()",
            RoutineKind::Window,
            Vec::new(),
            "bigint",
            Volatility::Volatile,
            "internal",
        ),
    ] {
        let routine = cache
            .functions
            .get(&ObjectId::new(SCHEMA, name))
            .unwrap_or_else(|| panic!("synchronized routine {name}"));
        assert_eq!(routine.routine_kind, kind, "routine kind for {name}");
        assert_eq!(
            routine.arg_types,
            args.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "argument types for {name}"
        );
        assert_eq!(routine.return_type, result, "return type for {name}");
        assert_eq!(routine.volatility, volatility, "volatility for {name}");
        assert_eq!(routine.language, language, "language for {name}");
        assert_eq!(
            routine.security,
            SecurityMode::Invoker,
            "security for {name}"
        );
    }

    let publication = cache
        .publications
        .get(PUBLICATION)
        .expect("synchronized publication");
    assert_eq!(publication.owner.as_deref(), Some(expected_owner.as_str()));
    assert_eq!(publication.name, PUBLICATION);
    assert_eq!(publication.generation, 0);
    let publication_params = attributes(&publication.params);
    let mut expected_publication_params = std::collections::BTreeMap::from([
        ("publish", "insert, update"),
        ("publish_via_partition_root", "false"),
    ]);
    if version >= 180_000 {
        expected_publication_params.insert("publish_generated_columns", "stored");
    }
    assert_eq!(publication_params, expected_publication_params);
    let PublicationScope::Explicit(objects) = &publication.scope else {
        panic!("seeded publication must have explicit scope");
    };
    let table = objects
        .iter()
        .find_map(|object| match object {
            PublicationObjectFact::Table {
                name,
                columns,
                row_filter,
                ..
            } if name.name.resolve() == "entries" => Some((columns, row_filter)),
            _ => None,
        })
        .expect("synchronized publication table");
    if version >= 150_000 {
        assert_eq!(table.0.as_deref(), Some(["id".to_string()].as_slice()));
        assert!(matches!(
            table.1,
            Some(PublicationRowFilter::CatalogSql(filter)) if filter.contains("id")
        ));
        let schema_publication = cache
            .publications
            .get(SCHEMA_PUBLICATION)
            .expect("synchronized schema publication");
        assert!(matches!(
            &schema_publication.scope,
            PublicationScope::Explicit(schema_objects)
                if schema_objects.iter().any(|object| matches!(
                    object,
                    PublicationObjectFact::SchemaTables { schema, .. }
                        if schema == SECOND_SCHEMA
                ))
        ));
    } else {
        assert!(table.0.is_none());
        assert!(table.1.is_none());
    }

    let subscription = cache
        .subscriptions
        .get(SUBSCRIPTION)
        .expect("synchronized subscription");
    assert_eq!(subscription.name, SUBSCRIPTION);
    assert_eq!(subscription.owner.as_deref(), Some(expected_owner.as_str()));
    assert_eq!(subscription.connection, ConnectionTarget::Redacted);
    assert!(!subscription.enabled);
    assert!(subscription.slot_name.is_none());
    assert_eq!(subscription.publications, ["remote_publication"]);
    assert_eq!(subscription.generation, 0);
    let subscription_params = attributes(
        subscription
            .params
            .as_deref()
            .expect("synchronized subscription parameters"),
    );
    let mut expected_subscription_params = std::collections::BTreeMap::from([
        ("binary", "true"),
        ("streaming", "false"),
        ("synchronous_commit", "local"),
    ]);
    if version >= 150_000 {
        expected_subscription_params.insert("two_phase", "false");
        expected_subscription_params.insert("disable_on_error", "true");
    }
    if version >= 160_000 {
        expected_subscription_params.insert("password_required", "false");
        expected_subscription_params.insert("run_as_owner", "true");
        expected_subscription_params.insert("origin", "none");
    }
    if version >= 170_000 {
        expected_subscription_params.insert("failover", "false");
    }
    assert_eq!(subscription_params, expected_subscription_params);
    assert!(
        !decoded_payload
            .windows(CONNECTION_SENTINEL.len())
            .any(|bytes| bytes == CONNECTION_SENTINEL.as_bytes()),
        "subscription connection information entered the decoded cache"
    );

    let inspection = inspect_cache(&cache_path);
    let contents = &inspection["contents"];
    for (field, expected) in [
        (
            "functions",
            cache
                .functions
                .values()
                .filter(|routine| routine.routine_kind == RoutineKind::Function)
                .count(),
        ),
        (
            "procedures",
            cache
                .functions
                .values()
                .filter(|routine| routine.routine_kind == RoutineKind::Procedure)
                .count(),
        ),
        (
            "aggregates",
            cache
                .functions
                .values()
                .filter(|routine| routine.routine_kind == RoutineKind::Aggregate)
                .count(),
        ),
        (
            "window_functions",
            cache
                .functions
                .values()
                .filter(|routine| routine.routine_kind == RoutineKind::Window)
                .count(),
        ),
        ("publications", cache.publications.len()),
        ("subscriptions", cache.subscriptions.len()),
    ] {
        assert!(expected > 0, "seeded cache count {field} must be nonzero");
        assert_eq!(contents[field], expected, "cache inspect count {field}");
    }

    cleanup(&mut client);
}

#[test]
#[ignore = "requires a live local PostgreSQL database via DATABASE_URL"]
fn live_routine_and_replication_mutations_match_postgresql() {
    let (database_config, _expected_owner, version) = live_database();
    let _cleanup = CatalogCleanup(database_config.clone());
    let mut client = database_config
        .connect(postgres::NoTls)
        .expect("connect for live catalog differential");
    seed_catalog(&mut client, version);

    let temp_dir = tempfile::tempdir().expect("create live catalog differential directory");
    let cache_path = temp_dir.path().join("catalog.cache");
    sync_cache(&cache_path, None, false).expect("sync live catalog baseline");
    let (baseline, _) = decode_cache(&cache_path);
    let mut state = AnalysisState::new(baseline);
    let engine = SafeMigrateEngine::new(Config::default());

    let alter_sql = format!(
        "ALTER FUNCTION {SCHEMA}.with_out(integer) STABLE;
         ALTER PROCEDURE {SCHEMA}.record_value(integer) RENAME TO record_value_renamed;
         ALTER AGGREGATE {SCHEMA}.total(integer) RENAME TO total_renamed;
         ALTER FUNCTION {SCHEMA}.win_rank() STABLE;
         ALTER PUBLICATION {PUBLICATION} ADD TABLE ONLY {SECOND_SCHEMA}.audit_entries;
         ALTER PUBLICATION {PUBLICATION} SET (publish = 'insert');
         ALTER SUBSCRIPTION {SUBSCRIPTION}
           SET PUBLICATION remote_publication, archive_publication
           WITH (refresh = false);"
    );
    let violations = engine
        .analyze(&alter_sql, &mut state)
        .expect("analyze live catalog alterations");
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "simulator rejected PostgreSQL-valid catalog alterations: {violations:#?}"
    );
    client
        .batch_execute(&alter_sql)
        .expect("apply live catalog alterations to PostgreSQL");
    sync_cache(&cache_path, None, false).expect("resync altered live catalog");
    let (altered, _) = decode_cache(&cache_path);

    for name in [
        "with_out(integer)",
        "record_value_renamed(integer)",
        "add_values(integer,integer)",
        "total_renamed(integer)",
        "win_rank()",
    ] {
        assert_routine_matches(&state, &altered, &ObjectId::new(SCHEMA, name));
    }
    assert_publication_matches(&state, &altered, PUBLICATION);
    assert_subscription_matches(&state, &altered, SUBSCRIPTION);

    let drop_sql = format!(
        "DROP SUBSCRIPTION {SUBSCRIPTION};
         DROP PUBLICATION {PUBLICATION};
         DROP PROCEDURE {SCHEMA}.record_value_renamed(integer);
         DROP AGGREGATE {SCHEMA}.total_renamed(integer);
         DROP FUNCTION {SCHEMA}.win_rank();
         DROP FUNCTION {SCHEMA}.with_out(integer);
         DROP FUNCTION {SCHEMA}.add_values(integer, integer);"
    );
    let violations = engine
        .analyze(&drop_sql, &mut state)
        .expect("analyze live catalog drops");
    assert!(
        !violations
            .iter()
            .any(|violation| violation.rule_id == "chain-conflict"),
        "simulator rejected PostgreSQL-valid catalog drops: {violations:#?}"
    );
    client
        .batch_execute(&drop_sql)
        .expect("apply live catalog drops to PostgreSQL");
    sync_cache(&cache_path, None, false).expect("resync dropped live catalog");
    let (dropped, _) = decode_cache(&cache_path);

    for name in [
        "with_out(integer)",
        "record_value_renamed(integer)",
        "add_values(integer,integer)",
        "total_renamed(integer)",
        "win_rank()",
    ] {
        let id = ObjectId::new(SCHEMA, name);
        assert!(
            matches!(
                state.local.functions.get(&id),
                Some(FunctionOverlay::Dropped)
            ),
            "simulator routine {id} was not dropped"
        );
        assert!(
            !dropped.functions.contains_key(&id),
            "PostgreSQL routine {id} was not dropped"
        );
    }
    assert!(matches!(
        state.local.publications.get(PUBLICATION),
        Some(PublicationOverlay::Dropped)
    ));
    assert!(!dropped.publications.contains_key(PUBLICATION));
    assert!(matches!(
        state.local.subscriptions.get(SUBSCRIPTION),
        Some(SubscriptionOverlay::Dropped)
    ));
    assert!(!dropped.subscriptions.contains_key(SUBSCRIPTION));

    cleanup(&mut client);
}
