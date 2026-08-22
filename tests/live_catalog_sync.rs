mod common;

use crate::common::database_hosts_are_local;
use std::fs;
use std::io::Read;

use safe_migrate::analysis::facts::{
    ConnectionTarget, PublicationObjectFact, PublicationRowFilter, PublicationScope,
};
use safe_migrate::db::cache::{CACHE_V6_MAGIC, DbCacheVersioned};
use safe_migrate::model::function::RoutineKind;
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
    ] {
        let config: postgres::Config = value.parse().unwrap();
        assert!(!database_hosts_are_local(&config), "{value}");
    }
}

#[test]
#[ignore = "requires a live local PostgreSQL database via DATABASE_URL"]
fn live_sync_preserves_routine_and_replication_catalogs_without_connection_secrets() {
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL is required for live catalog sync");
    let database_config: postgres::Config = database_url
        .parse()
        .expect("live catalog DATABASE_URL is invalid");
    assert!(
        database_hosts_are_local(&database_config),
        "live catalog sync accepts only localhost or Unix-socket databases"
    );
    let mut validation_client = database_config
        .connect(postgres::NoTls)
        .expect("connect for live catalog sync");
    let identity = validation_client
        .query_one(
            "SELECT current_database(), current_user, current_setting('server_version_num')::int",
            &[],
        )
        .expect("identify live catalog database");
    let database: String = identity.get(0);
    let expected_owner: String = identity.get(1);
    let version: i32 = identity.get(2);
    assert_eq!(
        database, "safe_migrate",
        "live catalog sync refuses to modify a database not named safe_migrate"
    );
    drop(validation_client);
    let _cleanup = CatalogCleanup(database_config.clone());
    let mut client = database_config
        .connect(postgres::NoTls)
        .expect("connect for live catalog sync");

    cleanup(&mut client);
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
    client
        .batch_execute(&format!(
            "CREATE SUBSCRIPTION {SUBSCRIPTION}
               CONNECTION 'host=127.0.0.1 port=1 dbname=publisher user=replicator password={CONNECTION_SENTINEL}'
               PUBLICATION remote_publication
               WITH (connect = false, slot_name = NONE);"
        ))
        .expect("create disconnected live subscription");

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

    let publication = cache
        .publications
        .get(PUBLICATION)
        .expect("synchronized publication");
    assert_eq!(publication.owner.as_deref(), Some(expected_owner.as_str()));
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
    assert_eq!(subscription.connection, ConnectionTarget::Redacted);
    assert!(!subscription.enabled);
    assert!(subscription.slot_name.is_none());
    assert_eq!(subscription.publications, ["remote_publication"]);
    assert!(subscription.params.as_ref().is_some_and(|params| {
        params.iter().any(|param| param.name == "streaming")
            && params
                .iter()
                .any(|param| param.name == "synchronous_commit")
    }));
    assert!(
        !decoded_payload
            .windows(CONNECTION_SENTINEL.len())
            .any(|bytes| bytes == CONNECTION_SENTINEL.as_bytes()),
        "subscription connection information entered the decoded cache"
    );

    cleanup(&mut client);
}
