#!/bin/bash
# Generate a deterministic 400+ SQL migration corpus.
set -eu

if [ "$#" -ne 1 ]; then
    echo "Usage: tests/fuzz_migrations/generate.sh OUTPUT_DIRECTORY" >&2
    exit 2
fi

DIR=$1
mkdir -p "$DIR"
if find "$DIR" -mindepth 1 -print -quit | grep -q .; then
    echo "Output directory must be empty: $DIR" >&2
    exit 2
fi

N=1
write() {
    local name
    name=$(printf "%04d_%s" "$N" "$1")
    echo "$2" > "$DIR/$name.sql"
    N=$((N+1))
}

# === CATEGORY 1: Safe baseline operations (1-50) ===
write "create_simple_table" "CREATE TABLE users (id serial PRIMARY KEY, name text NOT NULL);"
write "create_table_if_not_exists" "CREATE TABLE IF NOT EXISTS users (id serial PRIMARY KEY);"
write "create_table_with_defaults" "CREATE TABLE users (id serial PRIMARY KEY, created_at timestamptz DEFAULT now());"
write "create_table_unlogged" "CREATE UNLOGGED TABLE temp_data (id int, val text);"
write "create_table_temp" "CREATE TEMPORARY TABLE scratch (id int);"
write "create_table_partition" "CREATE TABLE logs (id int, ts timestamptz) PARTITION BY RANGE (ts);"
write "create_table_partition_of" "CREATE TABLE logs_2024 PARTITION OF logs FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');"
write "create_index" "CREATE INDEX idx_users_name ON users (name);"
write "create_index_concurrently" "CREATE INDEX CONCURRENTLY idx_users_email ON users (email);"
write "create_unique_index" "CREATE UNIQUE INDEX idx_users_email_unique ON users (email);"
write "create_index_withPredicate" "CREATE INDEX idx_active ON users (name) WHERE active = true;"
write "create_index_hash" "CREATE INDEX idx_users_id_hash ON users USING hash (id);"
write "create_view" "CREATE VIEW active_users AS SELECT * FROM users WHERE active = true;"
write "create_materialized_view" "CREATE MATERIALIZED VIEW mv_stats AS SELECT count(*) FROM users;"
write "create_schema" "CREATE SCHEMA analytics;"
write "create_schema_if_not_exists" "CREATE SCHEMA IF NOT EXISTS analytics;"
write "alter_table_add_column" "ALTER TABLE users ADD COLUMN email text;"
write "alter_table_add_column_if_not_exists" "ALTER TABLE users ADD COLUMN IF NOT EXISTS email text;"
write "alter_table_drop_column" "ALTER TABLE users DROP COLUMN temp_col;"
write "alter_table_set_not_null" "ALTER TABLE users ALTER COLUMN name SET NOT NULL;"
write "alter_table_drop_not_null" "ALTER TABLE users ALTER COLUMN name DROP NOT NULL;"
write "alter_table_rename_column" "ALTER TABLE users RENAME COLUMN name TO full_name;"
write "alter_table_rename_table" "ALTER TABLE users RENAME TO accounts;"
write "alter_table_set_default" "ALTER TABLE users ALTER COLUMN created_at SET DEFAULT now();"
write "alter_table_drop_default" "ALTER TABLE users ALTER COLUMN created_at DROP DEFAULT;"
write "alter_table_set_type" "ALTER TABLE users ALTER COLUMN age TYPE bigint;"
write "alter_table_add_check" "ALTER TABLE users ADD CONSTRAINT positive_age CHECK (age > 0);"
write "alter_table_add_fk" "ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id);"
write "drop_table" "DROP TABLE temp_data;"
write "drop_table_if_exists" "DROP TABLE IF EXISTS temp_data;"
write "drop_table_cascade" "DROP TABLE temp_data CASCADE;"
write "drop_index" "DROP INDEX idx_users_name;"
write "drop_index_concurrently" "DROP INDEX CONCURRENTLY idx_users_email;"
write "drop_view" "DROP VIEW active_users;"
write "drop_materialized_view" "DROP MATERIALIZED VIEW mv_stats;"
write "drop_schema" "DROP SCHEMA analytics;"
write "drop_schema_cascade" "DROP SCHEMA analytics CASCADE;"
write "create_function_immutable" "CREATE FUNCTION add(a int, b int) RETURNS int LANGUAGE sql IMMUTABLE AS \$\$ SELECT a + b \$\$;"
write "create_function_volatile" "CREATE FUNCTION gen_val() RETURNS int LANGUAGE sql VOLATILE AS \$\$ SELECT random()::int \$\$;"
write "create_function_stable" "CREATE FUNCTION get_now() RETURNS timestamptz LANGUAGE sql STABLE AS \$\$ SELECT now() \$\$;"
write "create_trigger" "CREATE TRIGGER audit_trigger BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION audit_func();"
write "create_policy" "CREATE POLICY user_isolation ON users FOR ALL USING (user_id = current_user::int);"
write "grant_select" "GRANT SELECT ON users TO reader_role;"
write "grant_all" "GRANT ALL PRIVILEGES ON users TO admin_role;"
write "revoke_select" "REVOKE SELECT ON users FROM reader_role;"
write "vacuum_analyze" "VACUUM ANALYZE users;"
write "vacuum" "VACUUM users;"
write "alter_type_add_value" "ALTER TYPE mood ADD VALUE 'excited';"
write "create_sequence" "CREATE SEQUENCE order_seq START 1;"
write "alter_sequence" "ALTER SEQUENCE order_seq RESTART WITH 1000;"

# === CATEGORY 2: Destructive operations (51-100) ===
write "drop_table_large" "DROP TABLE users;"  # with baseline
write "drop_table_cascade_large" "DROP TABLE users CASCADE;"
write "drop_column_nullable" "ALTER TABLE users DROP COLUMN email;"
write "drop_column_cascade" "ALTER TABLE users DROP COLUMN email CASCADE;"
write "drop_index_concurrent" "DROP INDEX CONCURRENTLY idx_users_email;"
write "truncate_table" "TRUNCATE TABLE users;"
write "truncate_cascade" "TRUNCATE TABLE users CASCADE;"
write "drop_database" "DROP DATABASE legacy_db;"
write "drop_schema_cascade2" "DROP SCHEMA old_schema CASCADE;"
write "alter_table_alter_type_bad" "ALTER TABLE users ALTER COLUMN data TYPE jsonb USING data::jsonb;"
write "drop_function" "DROP FUNCTION add(int, int);"
write "drop_trigger" "DROP TRIGGER audit_trigger ON users;"
write "drop_policy" "DROP POLICY user_isolation ON users;"
write "drop_role" "DROP ROLE old_user;"
write "drop_sequence" "DROP SEQUENCE order_seq;"
write "alter_column_not_null_add" "ALTER TABLE users ALTER COLUMN name SET NOT NULL;"
write "add_column_not_null_default" "ALTER TABLE users ADD COLUMN status text NOT NULL DEFAULT 'active';"
write "add_column_not_null_no_default" "ALTER TABLE users ADD COLUMN required_field text NOT NULL;"
write "rename_table_to_existing" "ALTER TABLE users RENAME TO accounts;"  # conflicts
write "alter_type_rename_value" "ALTER TYPE mood RENAME VALUE 'sad' TO 'melancholy';"
write "drop_type" "DROP TYPE mood;"
write "create_table_as_select" "CREATE TABLE backup AS SELECT * FROM users;"
write "drop_column_with_index" "ALTER TABLE users DROP COLUMN id CASCADE;"  # index depends
write "vacuum_full" "VACUUM FULL users;"
write "vacuum_full2" "VACUUM (FULL) users;"
write "reindex_table" "REINDEX TABLE users;"
write "reindex_concurrently" "REINDEX TABLE CONCURRENTLY users;"
write "alter_table_set_tablespace" "ALTER TABLE users SET TABLESPACE fast_disk;"
write "alter_column_compression" "ALTER TABLE users ALTER COLUMN data SET COMPRESSION pglz;"

# === CATEGORY 3: Opaque/DO blocks (101-130) ===
write "do_block_simple" "DO \$\$ BEGIN RAISE NOTICE 'hello'; END \$\$;"
write "do_block_execute" "DO \$\$ BEGIN EXECUTE 'ALTER TABLE users ADD COLUMN IF NOT EXISTS x int'; END \$\$;"
write "do_block_loop" "DO \$\$ BEGIN FOR i IN 1..10 LOOP RAISE NOTICE '%', i; END LOOP; END \$\$ LANGUAGE plpgsql;"
write "do_block_exception" "DO \$\$ BEGIN BEGIN RAISE EXCEPTION 'test'; EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'caught'; END; END \$\$ LANGUAGE plpgsql;"
write "do_block_query" "DO \$\$ BEGIN IF EXISTS (SELECT 1 FROM users WHERE false) THEN RAISE NOTICE 'has rows'; END IF; END \$\$ LANGUAGE plpgsql;"
write "do_block_create_table" "DO \$\$ BEGIN EXECUTE 'CREATE TABLE IF NOT EXISTS dyn_table (id int)'; END \$\$;"
write "do_block_alter_type" "DO \$\$ BEGIN EXECUTE 'ALTER TYPE mood ADD VALUE IF NOT EXISTS ''neutral'''; END \$\$;"
write "do_block_grant" "DO \$\$ BEGIN EXECUTE 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO reader'; END \$\$;"
write "do_block_multi" "DO \$\$ BEGIN RAISE NOTICE 'step1'; RAISE NOTICE 'step2'; END \$\$;"
write "do_block_cursor" "DO \$\$ DECLARE r RECORD; BEGIN FOR r IN SELECT tablename FROM pg_tables LOOP RAISE NOTICE '%', r.tablename; END LOOP; END \$\$ LANGUAGE plpgsql;"
write "do_block_variable" "DO \$\$ DECLARE cnt int; BEGIN SELECT count(*) INTO cnt FROM users; RAISE NOTICE '%', cnt; END \$\$ LANGUAGE plpgsql;"
write "do_block_transaction" "DO \$\$ BEGIN RAISE NOTICE 'in txn'; END \$\$;"
write "do_block_nested" "DO \$\$ BEGIN DO \$\$inner\$\$ BEGIN RAISE NOTICE 'nested'; END; END \$\$;"
write "do_block_with_exception_handling" "DO \$\$ BEGIN BEGIN RAISE NOTICE 'test'; EXCEPTION WHEN OTHERS THEN NULL; END; END \$\$ LANGUAGE plpgsql;"
write "do_block_dynamic_sql" "DO \$\$ BEGIN EXECUTE format('CREATE TABLE IF NOT EXISTS t%s (id int)', 1); END \$\$;"
write "two_do_blocks" "DO \$\$ BEGIN RAISE NOTICE 'first'; END \$\$; DO \$\$ BEGIN RAISE NOTICE 'second'; END \$\$;"
write "do_block_before_ddl" "DO \$\$ BEGIN RAISE NOTICE 'before'; END \$\$; CREATE TABLE t1 (id int);"
write "do_block_after_ddl" "CREATE TABLE t2 (id int); DO \$\$ BEGIN RAISE NOTICE 'after'; END \$\$;"
write "do_block_between_ddl" "CREATE TABLE t3 (id int); DO \$\$ BEGIN RAISE NOTICE 'mid'; END \$\$; ALTER TABLE t3 ADD COLUMN x int;"

# === CATEGORY 4: Transaction patterns (131-170) ===
write "begin_commit" "BEGIN; CREATE TABLE t1 (id int); COMMIT;"
write "begin_rollback" "BEGIN; CREATE TABLE t1 (id int); ROLLBACK;"
write "begin_do_rollback" "BEGIN; DO \$\$ BEGIN RAISE NOTICE 'x'; END \$\$; ROLLBACK;"
write "begin_drop_commit" "BEGIN; DROP TABLE temp_data; COMMIT;"
write "begin_drop_rollback" "BEGIN; DROP TABLE temp_data; ROLLBACK;"
write "begin_create_drop_rollback" "BEGIN; CREATE TABLE tmp (id int); DROP TABLE tmp; ROLLBACK;"
write "begin_alter_rollback" "BEGIN; ALTER TABLE users ADD COLUMN x int; ROLLBACK;"
write "begin_nested_savepoint" "BEGIN; SAVEPOINT sp1; CREATE TABLE t1 (id int); ROLLBACK TO sp1; COMMIT;"
write "begin_multi_savepoint" "BEGIN; SAVEPOINT s1; CREATE TABLE t1 (id int); SAVEPOINT s2; DROP TABLE t1; ROLLBACK TO s2; RELEASE SAVEPOINT s2; COMMIT;"
write "begin_do_rollback_restores" "BEGIN; DO \$\$ BEGIN RAISE NOTICE 'taint'; END \$\$; ROLLBACK;"
write "begin_transaction_chain" "BEGIN; CREATE TABLE t1 (id int); COMMIT; BEGIN; DROP TABLE t1; COMMIT;"
write "begin_nested_rollback" "BEGIN; SAVEPOINT s1; DO \$\$ BEGIN NULL; END \$\$; ROLLBACK TO s1; DROP TABLE t1; ROLLBACK;"
write "begin_long_transaction" "BEGIN; CREATE TABLE t1 (id int); ALTER TABLE t1 ADD COLUMN x int; ALTER TABLE t1 ADD COLUMN y text; ALTER TABLE t1 DROP COLUMN x; COMMIT;"
write "begin_concurrent_index" "BEGIN; CREATE INDEX CONCURRENTLY idx ON users(id); COMMIT;"
write "begin_multiple_savepoints" "BEGIN; SAVEPOINT s1; SAVEPOINT s2; SAVEPOINT s3; ROLLBACK TO s2; RELEASE SAVEPOINT s3; COMMIT;"
write "begin_drop_multiple" "BEGIN; DROP TABLE IF EXISTS t1; DROP TABLE IF EXISTS t2; DROP TABLE IF EXISTS t3; COMMIT;"

# === CATEGORY 5: Confidence taint scenarios (171-220) ===
write "do_then_exact" "DO \$\$ BEGIN NULL; END \$\$; CREATE TABLE t1 (id int);"
write "exact_then_do" "CREATE TABLE t1 (id int); DO \$\$ BEGIN NULL; END \$\$;"
write "do_rollback_exact" "BEGIN; DO \$\$ BEGIN NULL; END \$\$; ROLLBACK; CREATE TABLE t1 (id int);"
write "do_rollback_do" "BEGIN; DO \$\$ BEGIN NULL; END \$\$; ROLLBACK; DO \$\$ BEGIN NULL; END \$\$;"
write "drop_taint_restore_exact" "BEGIN; DROP TABLE IF EXISTS nonexistent; ROLLBACK; CREATE TABLE t1 (id int);"
write "taint_chain" "DO \$\$ BEGIN NULL; END \$\$; DO \$\$ BEGIN NULL; END \$\$; DO \$\$ BEGIN NULL; END \$\$;"
write "taint_restore_taint" "BEGIN; DO \$\$ BEGIN NULL; END \$\$; ROLLBACK; DO \$\$ BEGIN NULL; END \$\$;"
write "exact_do_exact_do" "CREATE TABLE t1 (id int); DO \$\$ BEGIN NULL; END \$\$; CREATE TABLE t2 (id int); DO \$\$ BEGIN NULL; END \$\$;"
write "do_begin_exact" "DO \$\$ BEGIN NULL; END \$\$; BEGIN; CREATE TABLE t1 (id int); COMMIT;"
write "savepoint_taint" "BEGIN; SAVEPOINT s1; DO \$\$ BEGIN NULL; END \$\$; ROLLBACK TO s1; CREATE TABLE t1 (id int); COMMIT;"
write "multi_savepoint_taint" "BEGIN; SAVEPOINT s1; DO \$\$ BEGIN NULL; END \$\$; RELEASE SAVEPOINT s1; SAVEPOINT s2; CREATE TABLE t1 (id int); COMMIT;"
write "rollback_to_savepoint_restores" "BEGIN; DO \$\$ BEGIN NULL; END \$\$; SAVEPOINT s2; ROLLBACK TO s2; CREATE TABLE t1 (id int); COMMIT;"

# === CATEGORY 6: Cascade drop patterns (221-260) ===
write "cascade_drop_no_deps" "DROP TABLE t_unknown CASCADE;"
write "cascade_drop_if_exists" "DROP TABLE IF EXISTS t_unknown CASCADE;"
write "drop_no_cascade_unknown" "DROP TABLE t_unknown;"
write "drop_if_exists_unknown" "DROP TABLE IF EXISTS t_unknown;"
write "drop_multiple_tables" "DROP TABLE t1, t2, t3;"
write "drop_multiple_if_exists" "DROP TABLE IF EXISTS t1, t2, t3;"
write "drop_schema_then_table" "DROP SCHEMA old CASCADE; DROP TABLE IF EXISTS old_table;"
write "drop_view_cascade" "DROP VIEW IF EXISTS v_unknown CASCADE;"
write "drop_materialized_cascade" "DROP MATERIALIZED VIEW IF EXISTS mv_unknown CASCADE;"
write "drop_index_concurrent_safe" "DROP INDEX CONCURRENTLY IF EXISTS idx_unknown;"
write "alter_table_add_drop_column" "ALTER TABLE users ADD COLUMN tmp int; ALTER TABLE users DROP COLUMN tmp;"
write "create_drop_table" "CREATE TABLE tmp (id int); DROP TABLE tmp;"
write "create_alter_drop" "CREATE TABLE tmp (id int); ALTER TABLE tmp ADD COLUMN x int; DROP TABLE tmp;"
write "create_drop_index" "CREATE INDEX idx_tmp ON users(name); DROP INDEX idx_tmp;"
write "create_drop_view" "CREATE VIEW v_tmp AS SELECT 1; DROP VIEW v_tmp;"

# === CATEGORY 7: Type changes (261-290) ===
write "alter_type_add_value_safe" "ALTER TYPE status ADD VALUE IF NOT EXISTS 'pending';"
write "alter_type_add_value_unsafe" "ALTER TYPE status ADD VALUE 'shipped';"
write "alter_column_type_int_to_bigint" "ALTER TABLE users ALTER COLUMN id TYPE bigint;"
write "alter_column_type_text_to_varchar" "ALTER TABLE users ALTER COLUMN name TYPE varchar(255);"
write "alter_column_type_with_using" "ALTER TABLE users ALTER COLUMN val TYPE numeric USING val::numeric;"
write "create_composite_type" "CREATE TYPE address AS (street text, city text, zip text);"
write "create_enum_type" "CREATE TYPE mood AS ENUM ('happy', 'sad', 'neutral');"
write "create_range_type" "CREATE TYPE floatrange AS RANGE (subtype = float8);"
write "drop_type_cascade" "DROP TYPE IF EXISTS unknown_type CASCADE;"
write "alter_type_rename" "ALTER TYPE mood RENAME TO emotion;"

# === CATEGORY 8: Partition operations (291-320) ===
write "create_partitioned_table" "CREATE TABLE metrics (id int, ts timestamptz, val double precision) PARTITION BY RANGE (ts);"
write "create_partition" "CREATE TABLE metrics_2024 PARTITION OF metrics FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');"
write "create_default_partition" "CREATE TABLE metrics_default PARTITION OF metrics DEFAULT;"
write "detach_partition" "ALTER TABLE metrics DETACH PARTITION metrics_2024;"
write "detach_partition_concurrently" "ALTER TABLE metrics DETACH PARTITION metrics_2024 CONCURRENTLY;"
write "attach_partition" "ALTER TABLE metrics ATTACH PARTITION metrics_2024 FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');"
write "drop_partition" "DROP TABLE metrics_2024;"
write "drop_partition_cascade" "DROP TABLE metrics_2024 CASCADE;"
write "create_hash_partitioned" "CREATE TABLE sessions (id int, user_id int) PARTITION BY HASH (user_id);"
write "create_list_partitioned" "CREATE TABLE regions (id int, region text) PARTITION BY LIST (region);"

# === CATEGORY 9: Security (321-350) ===
write "grant_all_on_schema" "GRANT ALL ON SCHEMA public TO admin;"
write "grant_select_on_all" "GRANT SELECT ON ALL TABLES IN SCHEMA public TO reader;"
write "grant_specific" "GRANT SELECT, INSERT ON users TO writer;"
write "revoke_all" "REVOKE ALL ON users FROM old_user;"
write "create_role" "CREATE ROLE new_app LOGIN PASSWORD 'changeme';"
write "drop_role_cascade" "DROP ROLE IF EXISTS old_user;"
write "alter_role_super" "ALTER ROLE admin WITH SUPERUSER;"
write "create_role_noLogin" "CREATE ROLE readonly NOLOGIN;"
write "grant_execute" "GRANT EXECUTE ON FUNCTION add(int, int) TO app_role;"
write "revoke_execute" "REVOKE EXECUTE ON FUNCTION add(int, int) FROM app_role;"
write "row_level_security" "ALTER TABLE users ENABLE ROW LEVEL SECURITY;"
write "create_policy_select" "CREATE POLICY read_own ON users FOR SELECT USING (id = current_setting('app.user_id')::int);"
write "create_policy_insert" "CREATE POLICY insert_own ON users FOR INSERT WITH CHECK (id = current_setting('app.user_id')::int);"
write "force_row_level" "ALTER TABLE users FORCE ROW LEVEL SECURITY;"
write "grant_usage_schema" "GRANT USAGE ON SCHEMA public TO reader;"

# === CATEGORY 10: Complex multi-statement (351-450) ===
write "full_migration_1" "
CREATE TABLE IF NOT EXISTS products (
    id serial PRIMARY KEY,
    name text NOT NULL,
    price numeric(10,2) NOT NULL CHECK (price >= 0),
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
);
CREATE INDEX idx_products_name ON products (name);
CREATE INDEX idx_products_price ON products (price);
GRANT SELECT ON products TO reader_role;
"
write "full_migration_2" "
BEGIN;
CREATE TABLE orders (
    id serial PRIMARY KEY,
    product_id int REFERENCES products(id),
    quantity int NOT NULL DEFAULT 1,
    total numeric(12,2) GENERATED ALWAYS AS (quantity * price) STORED,
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz DEFAULT now()
);
CREATE INDEX idx_orders_product ON orders (product_id);
CREATE INDEX idx_orders_status ON orders (status);
COMMIT;
"
write "full_migration_3" "
BEGIN;
ALTER TABLE products ADD COLUMN description text;
ALTER TABLE products ADD COLUMN sku text UNIQUE;
ALTER TABLE products ADD COLUMN category_id int;
CREATE INDEX idx_products_category ON products (category_id);
COMMIT;
"
write "full_migration_4" "
DO \$\$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_products_sku') THEN
        CREATE UNIQUE INDEX idx_products_sku ON products (sku);
    END IF;
END \$\$;
"
write "full_migration_5" "
BEGIN;
SAVEPOINT sp1;
ALTER TABLE products DROP COLUMN description;
ROLLBACK TO sp1;
ALTER TABLE products ALTER COLUMN description SET DEFAULT '';
COMMIT;
"
write "full_migration_6" "
CREATE TABLE audit_log (
    id bigserial PRIMARY KEY,
    table_name text NOT NULL,
    action text NOT NULL,
    old_data jsonb,
    new_data jsonb,
    created_at timestamptz DEFAULT now()
);
CREATE INDEX idx_audit_table ON audit_log (table_name);
CREATE INDEX idx_audit_created ON audit_log (created_at);
"
write "full_migration_7" "
DO \$\$ BEGIN
    EXECUTE 'ALTER TABLE products ADD COLUMN IF NOT EXISTS search_vector tsvector';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_products_search ON products USING gin(search_vector)';
END \$\$;
"
write "full_migration_8" "
BEGIN;
CREATE TABLE user_roles (
    user_id int REFERENCES users(id) ON DELETE CASCADE,
    role_id int REFERENCES roles(id) ON DELETE CASCADE,
    granted_at timestamptz DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);
COMMIT;
"
write "full_migration_9" "
CREATE MATERIALIZED VIEW mv_product_stats AS
SELECT category_id, count(*) as cnt, avg(price) as avg_price
FROM products
GROUP BY category_id;
CREATE UNIQUE INDEX idx_mv_product_stats ON mv_product_stats (category_id);
"
write "full_migration_10" "
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_product_stats;
"

write "complex_alter_chain" "
ALTER TABLE users ADD COLUMN col1 int;
ALTER TABLE users ADD COLUMN col2 text;
ALTER TABLE users ALTER COLUMN col1 SET NOT NULL;
ALTER TABLE users ADD CONSTRAINT chk_col2 CHECK (length(col2) > 0);
ALTER TABLE users DROP COLUMN col1;
"
write "complex_create_chain" "
CREATE SCHEMA app;
CREATE TABLE app.config (key text PRIMARY KEY, value jsonb);
CREATE TABLE app.sessions (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id int REFERENCES users(id));
CREATE VIEW app.active_sessions AS SELECT * FROM app.sessions WHERE expires_at > now();
"
write "complex_rollback_chain" "
BEGIN;
CREATE TABLE tmp1 (id int);
SAVEPOINT s1;
CREATE TABLE tmp2 (id int);
ROLLBACK TO s1;
DROP TABLE tmp1;
CREATE TABLE tmp3 (id int);
COMMIT;
"
write "complex_do_ddl_mix" "
CREATE TABLE events (id serial PRIMARY KEY, name text);
DO \$\$ BEGIN RAISE NOTICE 'events table created'; END \$\$;
ALTER TABLE events ADD COLUMN payload jsonb;
DO \$\$ BEGIN
    EXECUTE format('CREATE INDEX idx_events_%s ON events(name)', 'idx');
END \$\$;
CREATE INDEX idx_events_name ON events (name);
"
write "complex_grant_chain" "
GRANT USAGE ON SCHEMA public TO app_role;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO app_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO app_role;
"

# === CATEGORY 11: Edge cases / unusual patterns (451-500) ===
write "empty_migration" "-- empty migration, nothing to do"
write "comments_only" "-- This is a comment\n-- Another comment\n-- Yet another"
write "multiple_statements_one_line" "SELECT 1; SELECT 2; SELECT 3;"
write "very_long_name" "CREATE TABLE this_is_a_very_long_table_name_that_exceeds_normal_limits (id int);"
write "quoted_identifiers" "CREATE TABLE \"My Table\" (\"My Column\" int);"
write "schema_qualified" "CREATE TABLE myschema.mytable (id int);"
write "multi_schema" "CREATE TABLE s1.t1 (id int); CREATE TABLE s2.t2 (id int);"
write "create_and_drop_same_statement" "CREATE TABLE tmp (id int); DROP TABLE tmp;"
write "alter_add_drop_same_column" "ALTER TABLE users ADD COLUMN tmp int; ALTER TABLE users DROP COLUMN tmp;"
write "double_begin" "BEGIN; BEGIN; CREATE TABLE t1 (id int); COMMIT; COMMIT;"
write "rollback_without_begin" "ROLLBACK;"
write "commit_without_begin" "COMMIT;"
write "savepoint_without_begin" "SAVEPOINT sp1;"
write "nested_transaction" "BEGIN; SAVEPOINT s1; SAVEPOINT s2; CREATE TABLE t1 (id int); ROLLBACK TO s2; COMMIT;"
write "create_drop_create" "CREATE TABLE t1 (id int); DROP TABLE t1; CREATE TABLE t1 (name text);"
write "concurrent_operations" "
CREATE INDEX CONCURRENTLY idx1 ON users(id);
CREATE INDEX CONCURRENTLY idx2 ON users(name);
DROP INDEX CONCURRENTLY IF EXISTS idx_old;
"
write "mixed_concurrent_safe" "
BEGIN;
CREATE INDEX idx_safe ON users(id);
COMMIT;
CREATE INDEX CONCURRENTLY idx_concurrent ON users(name);
"
write "do_block_with_ddl_error" "DO \$\$ BEGIN EXECUTE 'DROP TABLE totally_nonexistent_table_xyz'; EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'caught'; END \$\$;"
write "grant_revoke_grant" "GRANT SELECT ON users TO reader; REVOKE SELECT ON users FROM reader; GRANT SELECT ON users TO reader;"
write "multi_alter_single_table" "
ALTER TABLE users
    ADD COLUMN a int,
    ADD COLUMN b text,
    ALTER COLUMN a SET DEFAULT 0,
    ADD CONSTRAINT chk CHECK (a >= 0);
"
write "create_table_with_everything" "
CREATE TABLE mega_table (
    id serial PRIMARY KEY,
    name text NOT NULL UNIQUE,
    email text NOT NULL,
    age int CHECK (age >= 0 AND age <= 200),
    data jsonb DEFAULT '{}',
    ts timestamptz DEFAULT now(),
    status text DEFAULT 'active' NOT NULL,
    parent_id int REFERENCES users(id) ON DELETE SET NULL
);
"
write "drop_everything" "
DROP TABLE IF EXISTS mega_table CASCADE;
DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS user_roles CASCADE;
DROP VIEW IF EXISTS mv_product_stats;
DROP SCHEMA IF EXISTS app CASCADE;
"

for i in $(seq 1 50); do
    write "gen_create_table_$i" "CREATE TABLE t_$i (id serial PRIMARY KEY, val text DEFAULT 'x$i');"
done

for i in $(seq 1 50); do
    write "gen_drop_table_$i" "DROP TABLE IF EXISTS t_$i;"
done

for i in $(seq 1 50); do
    write "gen_do_block_$i" "DO \$\$ BEGIN RAISE NOTICE 'block_$i'; END \$\$;"
done

for i in $(seq 1 30); do
    write "gen_add_column_$i" "ALTER TABLE users ADD COLUMN gen_col_$i int DEFAULT $i;"
done

for i in $(seq 1 20); do
    write "gen_grant_$i" "GRANT SELECT ON users TO role_$i;"
done

echo "Generated $((N-1)) SQL migration files in $DIR/"
find "$DIR" -maxdepth 1 -type f -name '*.sql' | wc -l
