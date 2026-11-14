use crate::common::database_hosts_are_local;
use postgres::{Config as PostgresConfig, GenericClient, NoTls};

fn live_client() -> (crate::internal_tests::LiveDatabaseGuard, postgres::Client) {
    let guard = crate::internal_tests::live_database_test_lock();
    let database_url = guard
        .url()
        .expect("DATABASE_URL is required for live lock-mode verification");
    let config: PostgresConfig = database_url
        .parse()
        .expect("live lock-mode DATABASE_URL is invalid");
    assert!(
        database_hosts_are_local(&config),
        "live lock-mode verification accepts only localhost or Unix-socket databases"
    );
    let mut client = config
        .connect(NoTls)
        .expect("connect for live lock-mode verification");
    let database: String = client
        .query_one("SELECT current_database()", &[])
        .expect("identify live lock-mode database")
        .get(0);
    assert_eq!(
        database, "safe_migrate",
        "live lock-mode verification refuses to modify a database not named safe_migrate"
    );
    (guard, client)
}

fn relation_lock_modes(client: &mut impl GenericClient, relation: &str) -> Vec<String> {
    client
        .query(
            "SELECT DISTINCT mode::text
             FROM pg_locks
             WHERE locktype = 'relation'
               AND relation = $1::text::regclass
               AND pid = pg_backend_pid()",
            &[&relation],
        )
        .expect("read relation locks")
        .into_iter()
        .map(|row| row.get(0))
        .collect()
}

fn assert_lock_mode(
    client: &mut impl GenericClient,
    relation: &str,
    expected: &str,
    context: &str,
) {
    let modes = relation_lock_modes(client, relation);
    assert!(
        modes.iter().any(|mode| mode == expected),
        "{context} must hold {expected} on {relation}: {modes:?}"
    );
}

fn assert_no_lock_mode(
    client: &mut impl GenericClient,
    relation: &str,
    unexpected: &str,
    context: &str,
) {
    let modes = relation_lock_modes(client, relation);
    assert!(
        !modes.iter().any(|mode| mode == unexpected),
        "{context} must not hold {unexpected} on {relation}: {modes:?}"
    );
}

#[test]
#[ignore = "requires a live local PostgreSQL database via DATABASE_URL"]
fn constraint_lock_modes_match_postgresql() {
    let (_guard, mut client) = live_client();
    let schema = "sm_v7_lock_constraint";
    client
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE;
             CREATE SCHEMA {schema};
             CREATE TABLE {schema}.parent (id integer PRIMARY KEY);
             CREATE TABLE {schema}.child (id integer, parent_id integer);"
        ))
        .expect("seed constraint lock fixtures");

    let mut transaction = client.transaction().expect("begin CHECK lock probe");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE {schema}.child ADD CONSTRAINT child_check CHECK (id > 0);"
        ))
        .expect("add valid CHECK constraint");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.child"),
        "AccessExclusiveLock",
        "valid CHECK",
    );
    transaction.rollback().expect("rollback CHECK lock probe");

    let mut transaction = client
        .transaction()
        .expect("begin NOT VALID CHECK lock probe");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE {schema}.child ADD CONSTRAINT child_check_pending CHECK (id > 0) NOT VALID;"
        ))
        .expect("add NOT VALID CHECK constraint");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.child"),
        "AccessExclusiveLock",
        "NOT VALID CHECK",
    );
    transaction
        .rollback()
        .expect("rollback NOT VALID CHECK lock probe");

    let mut transaction = client.transaction().expect("begin FOREIGN KEY lock probe");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE {schema}.child ADD CONSTRAINT child_fk
             FOREIGN KEY (parent_id) REFERENCES {schema}.parent(id);"
        ))
        .expect("add valid FOREIGN KEY constraint");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.child"),
        "ShareRowExclusiveLock",
        "FOREIGN KEY referencing table",
    );
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.parent"),
        "ShareRowExclusiveLock",
        "FOREIGN KEY referenced table",
    );
    transaction
        .rollback()
        .expect("rollback FOREIGN KEY lock probe");

    let mut transaction = client
        .transaction()
        .expect("begin NOT VALID FOREIGN KEY lock probe");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE {schema}.child ADD CONSTRAINT child_fk_pending_direct
             FOREIGN KEY (parent_id) REFERENCES {schema}.parent(id) NOT VALID;"
        ))
        .expect("add NOT VALID FOREIGN KEY constraint");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.child"),
        "ShareRowExclusiveLock",
        "NOT VALID FOREIGN KEY referencing table",
    );
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.parent"),
        "ShareRowExclusiveLock",
        "NOT VALID FOREIGN KEY referenced table",
    );
    transaction
        .rollback()
        .expect("rollback NOT VALID FOREIGN KEY lock probe");

    client
        .batch_execute(&format!(
            "ALTER TABLE {schema}.child ADD CONSTRAINT child_fk_pending
             FOREIGN KEY (parent_id) REFERENCES {schema}.parent(id) NOT VALID;"
        ))
        .expect("add pending FOREIGN KEY constraint");
    let mut transaction = client.transaction().expect("begin VALIDATE lock probe");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE {schema}.child VALIDATE CONSTRAINT child_fk_pending;"
        ))
        .expect("validate pending FOREIGN KEY constraint");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.child"),
        "ShareUpdateExclusiveLock",
        "VALIDATE CONSTRAINT",
    );
    assert_no_lock_mode(
        &mut transaction,
        &format!("{schema}.child"),
        "AccessExclusiveLock",
        "VALIDATE CONSTRAINT",
    );
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.parent"),
        "RowShareLock",
        "VALIDATE FOREIGN KEY referenced table",
    );
    transaction
        .rollback()
        .expect("rollback VALIDATE lock probe");

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE;"))
        .expect("remove constraint lock fixtures");
}

#[test]
#[ignore = "requires a live local PostgreSQL database via DATABASE_URL"]
fn table_ddl_lock_modes_match_postgresql() {
    let (_guard, mut client) = live_client();
    let schema = "sm_v7_lock_table";
    client
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE;
             CREATE SCHEMA {schema};
             CREATE TABLE {schema}.t (id integer, note varchar(10));
             CREATE TABLE {schema}.part_parent (id integer) PARTITION BY RANGE (id);
             CREATE TABLE {schema}.part_child_attached (id integer);
             CREATE TABLE {schema}.part_child_new (id integer);
             ALTER TABLE {schema}.part_parent
                ATTACH PARTITION {schema}.part_child_attached FOR VALUES FROM (0) TO (10);
             CREATE TABLE {schema}.default_parent (id integer) PARTITION BY RANGE (id);
             CREATE TABLE {schema}.default_child
                PARTITION OF {schema}.default_parent DEFAULT;
             CREATE TABLE {schema}.default_attach (id integer);
             CREATE TABLE {schema}.sub_parent (id integer NOT NULL) PARTITION BY RANGE (id);
             CREATE TABLE {schema}.sub_child (id integer NOT NULL) PARTITION BY RANGE (id);
             CREATE TABLE {schema}.sub_leaf (id integer NOT NULL);
             ALTER TABLE {schema}.sub_child
                ATTACH PARTITION {schema}.sub_leaf FOR VALUES FROM (0) TO (10);
             CREATE TABLE {schema}.pk_t (id integer);
             CREATE UNIQUE INDEX pk_t_id_key ON {schema}.pk_t (id);
             CREATE TABLE {schema}.det_parent (id integer PRIMARY KEY) PARTITION BY RANGE (id);
             CREATE TABLE {schema}.det_child (id integer NOT NULL);
             ALTER TABLE {schema}.det_parent
                ATTACH PARTITION {schema}.det_child FOR VALUES FROM (0) TO (10);
             CREATE TABLE {schema}.det_ref
                (parent_id integer REFERENCES {schema}.det_parent(id));
             CREATE DOMAIN {schema}.posint AS integer;
             CREATE TABLE {schema}.domtab (value {schema}.posint);"
        ))
        .expect("seed table lock fixtures");

    let mut transaction = client.transaction().expect("begin SET STORAGE lock probe");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE {schema}.t ALTER COLUMN note SET STORAGE EXTERNAL;"
        ))
        .expect("set storage");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.t"),
        "AccessExclusiveLock",
        "SET STORAGE",
    );
    transaction.rollback().expect("rollback SET STORAGE probe");

    let mut transaction = client
        .transaction()
        .expect("begin SET ACCESS METHOD lock probe");
    transaction
        .batch_execute(&format!("ALTER TABLE {schema}.t SET ACCESS METHOD heap;"))
        .expect("set access method");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.t"),
        "AccessExclusiveLock",
        "SET ACCESS METHOD",
    );
    transaction
        .rollback()
        .expect("rollback SET ACCESS METHOD probe");

    let mut transaction = client.transaction().expect("begin SET NOT NULL lock probe");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE {schema}.t ALTER COLUMN note SET NOT NULL;"
        ))
        .expect("set not null");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.t"),
        "AccessExclusiveLock",
        "SET NOT NULL",
    );
    transaction.rollback().expect("rollback SET NOT NULL probe");

    let mut transaction = client.transaction().expect("begin ADD UNIQUE lock probe");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE {schema}.t ADD CONSTRAINT t_note_unique UNIQUE (note);"
        ))
        .expect("add unique constraint");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.t"),
        "AccessExclusiveLock",
        "ADD UNIQUE",
    );
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.t"),
        "ShareLock",
        "ADD UNIQUE",
    );
    transaction.rollback().expect("rollback ADD UNIQUE probe");

    let mut transaction = client.transaction().expect("begin SET TYPE lock probe");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE {schema}.t ALTER COLUMN note TYPE varchar(20);"
        ))
        .expect("change type");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.t"),
        "AccessExclusiveLock",
        "ALTER COLUMN TYPE",
    );
    transaction.rollback().expect("rollback SET TYPE probe");

    let mut transaction = client.transaction().expect("begin DETACH lock probe");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE {schema}.part_parent DETACH PARTITION {schema}.part_child_attached;"
        ))
        .expect("detach partition");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.part_parent"),
        "AccessExclusiveLock",
        "DETACH PARTITION parent",
    );
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.part_child_attached"),
        "AccessExclusiveLock",
        "DETACH PARTITION child",
    );
    transaction.rollback().expect("rollback DETACH probe");
    // DETACH PARTITION CONCURRENTLY cannot run inside a transaction block, so
    // its lock behavior is verified by the unit test
    // `detach_partition_concurrently_predicts_share_update_exclusive_on_parent`
    // in tests/lock_predictions.rs instead.

    let mut transaction = client.transaction().expect("begin ATTACH lock probe");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE {schema}.part_parent
               ATTACH PARTITION {schema}.part_child_new FOR VALUES FROM (10) TO (20);"
        ))
        .expect("attach partition");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.part_parent"),
        "ShareUpdateExclusiveLock",
        "ATTACH PARTITION parent",
    );
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.part_child_new"),
        "AccessExclusiveLock",
        "ATTACH PARTITION child",
    );
    transaction.rollback().expect("rollback ATTACH probe");

    let mut transaction = client
        .transaction()
        .expect("begin ATTACH default partition lock probe");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE {schema}.default_parent
               ATTACH PARTITION {schema}.default_attach FOR VALUES FROM (10) TO (20);"
        ))
        .expect("attach partition with default present");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.default_parent"),
        "ShareUpdateExclusiveLock",
        "ATTACH PARTITION with default parent",
    );
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.default_attach"),
        "AccessExclusiveLock",
        "ATTACH PARTITION with default child",
    );
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.default_child"),
        "AccessExclusiveLock",
        "ATTACH PARTITION default partition",
    );
    transaction
        .rollback()
        .expect("rollback ATTACH default partition probe");

    let mut transaction = client
        .transaction()
        .expect("begin ATTACH subpartition lock probe");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE {schema}.sub_parent
               ATTACH PARTITION {schema}.sub_child FOR VALUES FROM (0) TO (100);"
        ))
        .expect("attach partitioned partition");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.sub_parent"),
        "ShareUpdateExclusiveLock",
        "ATTACH PARTITION subpartition parent",
    );
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.sub_child"),
        "AccessExclusiveLock",
        "ATTACH PARTITION partitioned child",
    );
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.sub_leaf"),
        "AccessExclusiveLock",
        "ATTACH PARTITION subpartition",
    );
    transaction
        .rollback()
        .expect("rollback ATTACH subpartition probe");

    let mut transaction = client
        .transaction()
        .expect("begin PRIMARY KEY USING INDEX lock probe");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE {schema}.pk_t
               ADD CONSTRAINT pk_t_pkey PRIMARY KEY USING INDEX pk_t_id_key;"
        ))
        .expect("add primary key using index");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.pk_t"),
        "AccessExclusiveLock",
        "PRIMARY KEY USING INDEX",
    );
    transaction
        .rollback()
        .expect("rollback PRIMARY KEY USING INDEX probe");

    let mut transaction = client
        .transaction()
        .expect("begin DETACH referencing table lock probe");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE {schema}.det_parent DETACH PARTITION {schema}.det_child;"
        ))
        .expect("detach referenced partition");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.det_parent"),
        "AccessExclusiveLock",
        "DETACH referenced partition parent",
    );
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.det_child"),
        "AccessExclusiveLock",
        "DETACH referenced partition child",
    );
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.det_ref"),
        "ShareLock",
        "DETACH referencing table",
    );
    transaction
        .rollback()
        .expect("rollback DETACH referencing table probe");

    let mut transaction = client.transaction().expect("begin TRUNCATE lock probe");
    transaction
        .batch_execute(&format!("TRUNCATE {schema}.t;"))
        .expect("truncate");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.t"),
        "AccessExclusiveLock",
        "TRUNCATE",
    );
    transaction.rollback().expect("rollback TRUNCATE probe");

    let mut transaction = client.transaction().expect("begin DOMAIN lock probe");
    transaction
        .batch_execute(&format!(
            "ALTER DOMAIN {schema}.posint ADD CONSTRAINT pos_check CHECK (VALUE > 0);"
        ))
        .expect("add domain constraint");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.domtab"),
        "ShareLock",
        "ALTER DOMAIN ADD CONSTRAINT",
    );
    transaction.rollback().expect("rollback DOMAIN probe");

    let mut transaction = client
        .transaction()
        .expect("begin DOMAIN SET NOT NULL lock probe");
    transaction
        .batch_execute(&format!("ALTER DOMAIN {schema}.posint SET NOT NULL;"))
        .expect("set domain not null");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.domtab"),
        "ShareLock",
        "ALTER DOMAIN SET NOT NULL",
    );
    transaction
        .rollback()
        .expect("rollback DOMAIN SET NOT NULL probe");

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE;"))
        .expect("remove table lock fixtures");
}

#[test]
#[ignore = "requires a live local PostgreSQL database via DATABASE_URL"]
fn index_and_refresh_lock_modes_match_postgresql() {
    let (_guard, mut client) = live_client();
    let schema = "sm_v7_lock_index";
    client
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE;
             CREATE SCHEMA {schema};
             CREATE TABLE {schema}.t (id integer, note text);
             CREATE MATERIALIZED VIEW {schema}.t_mv AS SELECT id FROM {schema}.t;"
        ))
        .expect("seed index lock fixtures");

    let mut transaction = client.transaction().expect("begin CREATE INDEX lock probe");
    transaction
        .batch_execute(&format!("CREATE INDEX t_note_idx ON {schema}.t(note);"))
        .expect("create index");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.t"),
        "ShareLock",
        "CREATE INDEX",
    );
    transaction.rollback().expect("rollback CREATE INDEX probe");

    client
        .batch_execute(&format!("CREATE INDEX t_note_idx ON {schema}.t(note);"))
        .expect("create index for drop probe");
    let mut transaction = client.transaction().expect("begin DROP INDEX lock probe");
    transaction
        .batch_execute(&format!("DROP INDEX {schema}.t_note_idx;"))
        .expect("drop index");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.t"),
        "AccessExclusiveLock",
        "DROP INDEX",
    );
    transaction.rollback().expect("rollback DROP INDEX probe");

    let mut transaction = client.transaction().expect("begin REINDEX lock probe");
    transaction
        .batch_execute(&format!("REINDEX TABLE {schema}.t;"))
        .expect("reindex table");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.t"),
        "ShareLock",
        "REINDEX TABLE",
    );
    transaction.rollback().expect("rollback REINDEX probe");

    let mut transaction = client
        .transaction()
        .expect("begin REINDEX INDEX lock probe");
    transaction
        .batch_execute(&format!("REINDEX INDEX {schema}.t_note_idx;"))
        .expect("reindex index");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.t"),
        "ShareLock",
        "REINDEX INDEX table",
    );
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.t_note_idx"),
        "AccessExclusiveLock",
        "REINDEX INDEX index",
    );
    transaction
        .rollback()
        .expect("rollback REINDEX INDEX probe");

    let mut transaction = client
        .transaction()
        .expect("begin REFRESH MATERIALIZED VIEW lock probe");
    transaction
        .batch_execute(&format!("REFRESH MATERIALIZED VIEW {schema}.t_mv;"))
        .expect("refresh materialized view");
    assert_lock_mode(
        &mut transaction,
        &format!("{schema}.t_mv"),
        "AccessExclusiveLock",
        "REFRESH MATERIALIZED VIEW",
    );
    transaction
        .rollback()
        .expect("rollback REFRESH MATERIALIZED VIEW probe");

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE;"))
        .expect("remove index lock fixtures");
}
