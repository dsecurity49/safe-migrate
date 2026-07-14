#!/bin/bash
# Generate complex multi-statement migration fuzz tests
set -e

DIR="tests/fuzz_migrations/complex_sql"
rm -rf "$DIR"
mkdir -p "$DIR"

N=1
write() {
    local name=$(printf "%04d_%s" "$N" "$1")
    echo "$2" > "$DIR/$name.sql"
    N=$((N+1))
}

# Transaction + DO block + DDL combos
write "txn_do_ddl_rollback" "
BEGIN;
CREATE TABLE t1 (id serial PRIMARY KEY, name text);
DO \$\$ BEGIN RAISE NOTICE 'created t1'; END \$\$;
ALTER TABLE t1 ADD COLUMN created_at timestamptz DEFAULT now();
ROLLBACK;
"

write "txn_do_drop_rollback" "
BEGIN;
DO \$\$ BEGIN EXECUTE 'DROP TABLE IF EXISTS nonexistent_xyz'; END \$\$;
DROP TABLE IF EXISTS temp_staging;
ROLLBACK;
"

write "savepoint_do_alter" "
BEGIN;
CREATE TABLE users (id int, name text);
SAVEPOINT sp1;
DO \$\$ BEGIN RAISE NOTICE 'in savepoint'; END \$\$;
ALTER TABLE users ADD COLUMN email text;
ROLLBACK TO sp1;
COMMIT;
"

write "multi_savepoint_do" "
BEGIN;
SAVEPOINT s1;
CREATE TABLE t1 (id int);
SAVEPOINT s2;
DO \$\$ BEGIN NULL; END \$\$;
CREATE TABLE t2 (id int);
ROLLBACK TO s2;
RELEASE SAVEPOINT s2;
CREATE TABLE t3 (id int);
COMMIT;
"

write "chain_do_blocks" "
CREATE TABLE t1 (id int);
DO \$\$ BEGIN RAISE NOTICE 'step1'; END \$\$;
CREATE INDEX idx_t1 ON t1(id);
DO \$\$ BEGIN RAISE NOTICE 'step2'; END \$\$;
ALTER TABLE t1 ADD COLUMN x int;
DO \$\$ BEGIN RAISE NOTICE 'step3'; END \$\$;
"

write "rollback_cascade_effects" "
BEGIN;
CREATE TABLE parent (id int PRIMARY KEY);
CREATE TABLE child (id int, parent_id int REFERENCES parent(id));
DO \$\$ BEGIN RAISE NOTICE 'tables created'; END \$\$;
ROLLBACK;
-- After rollback, neither table should exist
CREATE TABLE parent (id int PRIMARY KEY);
"

write "nested_savepoint_rollback" "
BEGIN;
SAVEPOINT s1;
CREATE TABLE t1 (id int);
SAVEPOINT s2;
CREATE TABLE t2 (id int);
DO \$\$ BEGIN NULL; END \$\$;
ROLLBACK TO s2;
-- t2 dropped, t1 still exists
DROP TABLE t1;
CREATE TABLE t3 (id int);
COMMIT;
"

write "do_block_in_transaction" "
BEGIN;
CREATE TABLE audit (id int, msg text);
DO \$\$ BEGIN
    RAISE NOTICE 'audit table created';
END \$\$;
INSERT INTO audit VALUES (1, 'migration');
COMMIT;
"

write "complex_alter_with_savepoint" "
BEGIN;
CREATE TABLE products (id int PRIMARY KEY, name text, price numeric);
SAVEPOINT sp_before;
ALTER TABLE products ADD COLUMN category text NOT NULL DEFAULT 'general';
ALTER TABLE products ADD CONSTRAINT price_check CHECK (price > 0);
SAVEPOINT sp_after;
DROP TABLE products;
ROLLBACK TO sp_after;
ROLLBACK TO sp_before;
COMMIT;
"

write "multi_table_transaction" "
BEGIN;
CREATE TABLE schema_a.users (id serial PRIMARY KEY, name text);
CREATE TABLE schema_a.orders (id serial PRIMARY KEY, user_id int REFERENCES schema_a.users(id));
CREATE TABLE schema_a.payments (id serial PRIMARY KEY, order_id int REFERENCES schema_a.orders(id));
DO \$\$ BEGIN RAISE NOTICE '3 tables created'; END \$\$;
COMMIT;
"

# Real-world migration patterns
write "add_not_null_column_safely" "
BEGIN;
ALTER TABLE users ADD COLUMN temp_email text;
-- backfill
UPDATE users SET temp_email = 'unknown' WHERE temp_email IS NULL;
ALTER TABLE users ALTER COLUMN temp_email SET NOT NULL;
ALTER TABLE users RENAME COLUMN temp_email TO email;
COMMIT;
"

write "rename_table_safely" "
BEGIN;
-- Create new table
CREATE TABLE accounts_new (id serial PRIMARY KEY, name text);
-- Copy data
INSERT INTO accounts_new SELECT * FROM users;
-- Drop old, rename new
DROP TABLE users;
ALTER TABLE accounts_new RENAME TO users;
COMMIT;
"

write "add_column_default_backfill" "
BEGIN;
ALTER TABLE orders ADD COLUMN status_v2 text;
UPDATE orders SET status_v2 = COALESCE(status, 'pending');
ALTER TABLE orders ALTER COLUMN status_v2 SET DEFAULT 'pending';
ALTER TABLE orders ALTER COLUMN status_v2 SET NOT NULL;
COMMIT;
"

write "create_index_concurrently_outside_txn" "
CREATE INDEX CONCURRENTLY idx_users_email ON users (email);
CREATE INDEX CONCURRENTLY idx_users_name ON users (name);
CREATE UNIQUE INDEX CONCURRENTLY idx_users_id ON users (id);
"

write "partition_management" "
BEGIN;
CREATE TABLE events (
    id bigserial PRIMARY KEY,
    ts timestamptz NOT NULL,
    payload jsonb
) PARTITION BY RANGE (ts);
CREATE TABLE events_2024q1 PARTITION OF events FOR VALUES FROM ('2024-01-01') TO ('2024-04-01');
CREATE TABLE events_2024q2 PARTITION OF events FOR VALUES FROM ('2024-04-01') TO ('2024-07-01');
CREATE TABLE events_2024q3 PARTITION OF events FOR VALUES FROM ('2024-07-01') TO ('2024-10-01');
CREATE TABLE events_2024q4 PARTITION OF events FOR VALUES FROM ('2024-10-01') TO ('2025-01-01');
COMMIT;
"

write "security_migration" "
BEGIN;
CREATE ROLE app_readonly NOLOGIN;
CREATE ROLE app_readwrite NOLOGIN;
GRANT USAGE ON SCHEMA public TO app_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_readonly;
GRANT USAGE ON SCHEMA public TO app_readwrite;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_readwrite;
COMMIT;
"

write "mat_view_refresh_pattern" "
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_dashboard_stats;
VACUUM ANALYZE mv_dashboard_stats;
"

write "type_evolution" "
BEGIN;
CREATE TYPE color AS ENUM ('red', 'green', 'blue');
ALTER TABLE products ADD COLUMN color color DEFAULT 'red';
COMMIT;
"

write "function_with_ddl" "
CREATE OR REPLACE FUNCTION migrate_data() RETURNS void LANGUAGE plpgsql AS \$\$
BEGIN
    RAISE NOTICE 'Starting data migration';
    -- This would be dynamic SQL in real migration
    RAISE NOTICE 'Data migration complete';
END;
\$\$;
"

write "complex_do_with_queries" "
DO \$\$ DECLARE
    cnt integer;
    tname text;
BEGIN
    SELECT count(*) INTO cnt FROM information_schema.tables WHERE table_schema = 'public';
    RAISE NOTICE 'Found % tables', cnt;
    FOR tname IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
        RAISE NOTICE 'Table: %', tname;
    END LOOP;
END \$\$ LANGUAGE plpgsql;
"

# Edge cases with multiple operations
write "rapid_create_drop" "
CREATE TABLE t1 (id int);
CREATE TABLE t2 (id int);
CREATE TABLE t3 (id int);
DROP TABLE t3;
DROP TABLE t2;
DROP TABLE t1;
"

write "create_alter_drop_chain" "
CREATE TABLE tmp (id int, old_col text);
ALTER TABLE tmp ADD COLUMN new_col int;
ALTER TABLE tmp ALTER COLUMN old_col TYPE text USING old_col;
ALTER TABLE tmp DROP COLUMN old_col;
DROP TABLE tmp;
"

write "parallel_index_operations" "
CREATE INDEX CONCURRENTLY idx1 ON users(id);
CREATE INDEX CONCURRENTLY idx2 ON users(name);
CREATE INDEX CONCURRENTLY idx3 ON users(email);
DROP INDEX CONCURRENTLY IF EXISTS idx_old1;
DROP INDEX CONCURRENTLY IF EXISTS idx_old2;
"

write "schema_cross_reference" "
BEGIN;
CREATE SCHEMA app;
CREATE TABLE app.users (id serial PRIMARY KEY, name text);
CREATE TABLE app.roles (id serial PRIMARY KEY, name text);
CREATE TABLE app.user_roles (
    user_id int REFERENCES app.users(id),
    role_id int REFERENCES app.roles(id),
    PRIMARY KEY (user_id, role_id)
);
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_user;
COMMIT;
"

write "do_block_error_handling" "
DO \$\$ BEGIN
    BEGIN
        ALTER TABLE users ADD COLUMNIF NOT EXISTS temp int;
    EXCEPTION WHEN duplicate_column THEN
        RAISE NOTICE 'column already exists';
    WHEN undefined_table THEN
        RAISE NOTICE 'table does not exist';
    END;
END \$\$;
"

write "massive_alter_table" "
BEGIN;
ALTER TABLE users ADD COLUMN c1 int;
ALTER TABLE users ADD COLUMN c2 text;
ALTER TABLE users ADD COLUMN c3 boolean DEFAULT false;
ALTER TABLE users ADD COLUMN c4 timestamptz;
ALTER TABLE users ADD COLUMN c5 jsonb DEFAULT '{}';
ALTER TABLE users ALTER COLUMN c1 SET DEFAULT 0;
ALTER TABLE users ALTER COLUMN c2 SET DEFAULT '';
ALTER TABLE users ADD CONSTRAINT chk_c1 CHECK (c1 >= 0);
ALTER TABLE users ADD CONSTRAINT chk_c3 CHECK (c3 IN (true, false));
COMMIT;
"

# Transaction with rollback that should restore everything
write "full_rollback_restores" "
BEGIN;
CREATE TABLE should_not_exist_1 (id int);
CREATE TABLE should_not_exist_2 (id int);
ALTER TABLE users ADD COLUMN should_not_exist_3 int;
DO \$\$ BEGIN RAISE NOTICE 'this should all be rolled back'; END \$\$;
ROLLBACK;
-- Verify users table is unchanged
SELECT * FROM users;
"

# Mixed safe/unsafe
write "mixed_safe_unsafe" "
CREATE TABLE IF NOT EXISTS safe_table (id int);
CREATE INDEX CONCURRENTLY idx_safe ON users(id);
ALTER TABLE users ADD COLUMN new_col text;
VACUUM FULL users;
"

# Generate randomized multi-statement files
for i in $(seq 1 100); do
    stmts=""
    num_stmts=$((RANDOM % 8 + 2))
    for j in $(seq 1 $num_stmts); do
        op=$((RANDOM % 6))
        case $op in
            0) stmts="${stmts}CREATE TABLE IF NOT EXISTS fuzz_t_$((RANDOM % 50)) (id int, v$((RANDOM % 10)) text);\n";;
            1) stmts="${stmts}ALTER TABLE users ADD COLUMN IF NOT EXISTS fuzz_c_$((RANDOM % 50)) int DEFAULT $((RANDOM % 100));\n";;
            2) stmts="${stmts}DROP TABLE IF EXISTS fuzz_t_$((RANDOM % 50));\n";;
            3) stmts="${stmts}DO \$\$ BEGIN RAISE NOTICE 'fuzz_$((RANDOM % 1000))'; END \$\$;\n";;
            4) stmts="${stmts}CREATE INDEX IF NOT EXISTS fuzz_idx_$((RANDOM % 50)) ON users(id);\n";;
            5) stmts="${stmts}DROP INDEX IF EXISTS fuzz_idx_$((RANDOM % 50));\n";;
        esac
    done
    # Sometimes wrap in transaction
    if [ $((RANDOM % 3)) -eq 0 ]; then
        if [ $((RANDOM % 2)) -eq 0 ]; then
            stmts="BEGIN;\n${stmts}COMMIT;"
        else
            stmts="BEGIN;\n${stmts}ROLLBACK;"
        fi
    fi
    write "random_$i" "$(echo -e "$stmts")"
done

echo "Generated $((N-1)) complex SQL migration files"
