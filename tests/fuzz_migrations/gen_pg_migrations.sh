#!/bin/bash
# Generate migrations that reference real PostgreSQL tables
set -e

DIR="tests/fuzz_migrations/pg_migrations"
rm -rf "$DIR"
mkdir -p "$DIR"

N=1
write() {
    local name=$(printf "%04d_%s" "$N" "$1")
    echo "$2" > "$DIR/$name.sql"
    N=$((N+1))
}

# === Safe migrations against real schema ===
write "safe_add_column" "ALTER TABLE app.users ADD COLUMN phone text;"
write "safe_add_column_if_not_exists" "ALTER TABLE app.users ADD COLUMN IF NOT EXISTS phone text;"
write "safe_add_index" "CREATE INDEX CONCURRENTLY idx_users_phone ON app.users (phone);"
write "safe_create_table" "CREATE TABLE app.notifications (id serial PRIMARY KEY, user_id int REFERENCES app.users(id), message text, read boolean DEFAULT false, created_at timestamptz DEFAULT now());"
write "safe_drop_column" "ALTER TABLE app.users DROP COLUMN phone;"
write "safe_drop_column_cascade" "ALTER TABLE app.users DROP COLUMN phone CASCADE;"
write "safe_create_view" "CREATE VIEW app.user_summary AS SELECT id, name, email FROM app.users WHERE is_active = true;"
write "safe_grant" "GRANT SELECT ON app.users TO PUBLIC;"
write "safe_revoke" "REVOKE SELECT ON app.users FROM PUBLIC;"
write "safe_vacuum" "VACUUM ANALYZE app.users;"
write "safe_refresh_mv" "REFRESH MATERIALIZED VIEW CONCURRENTLY analytics.post_stats;"
write "safe_do_block" "DO \$\$ BEGIN RAISE NOTICE 'safe migration'; END \$\$;"

# === Destructive migrations against real schema ===
write "drop_users_table" "DROP TABLE app.users;"
write "drop_users_cascade" "DROP TABLE app.users CASCADE;"
write "drop_users_if_exists" "DROP TABLE IF EXISTS app.users;"
write "drop_all_app_tables" "
DROP TABLE app.comments;
DROP TABLE app.post_tags;
DROP TABLE app.posts;
DROP TABLE app.user_roles;
DROP TABLE app.roles;
DROP TABLE app.users;
"
write "drop_app_schema" "DROP SCHEMA app CASCADE;"
write "drop_analytics_schema" "DROP SCHEMA analytics CASCADE;"
write "drop_all_schemas" "DROP SCHEMA app CASCADE; DROP SCHEMA analytics CASCADE;"
write "drop_view" "DROP VIEW app.active_posts;"
write "drop_mv" "DROP MATERIALIZED VIEW analytics.post_stats;"
write "vacuum_full_users" "VACUUM FULL app.users;"
write "vacuum_full_all" "VACUUM FULL app.users; VACUUM FULL app.posts;"

# === Destructive column operations ===
write "drop_pk_column" "ALTER TABLE app.users DROP COLUMN id;"
write "drop_fk_referenced_column" "ALTER TABLE app.users DROP COLUMN email;"
write "drop_column_with_index" "ALTER TABLE app.posts DROP COLUMN user_id CASCADE;"
write "alter_type_incompatible" "ALTER TABLE app.users ALTER COLUMN id TYPE text;"

# === Transaction patterns with real tables ===
write "txn_safe_add" "BEGIN; ALTER TABLE app.users ADD COLUMN phone text; COMMIT;"
write "txn_rollback_add" "BEGIN; ALTER TABLE app.users ADD COLUMN phone text; ROLLBACK;"
write "txn_drop_rollback" "BEGIN; DROP TABLE app.users; ROLLBACK;"
write "txn_do_rollback" "BEGIN; DO \$\$ BEGIN RAISE NOTICE 'taint'; END \$\$; ROLLBACK;"
write "txn_do_drop_rollback" "BEGIN; DO \$\$ BEGIN NULL; END \$\$; DROP TABLE app.users; ROLLBACK;"
write "savepoint_rollback" "
BEGIN;
ALTER TABLE app.users ADD COLUMN tmp1 int;
SAVEPOINT sp1;
ALTER TABLE app.users ADD COLUMN tmp2 int;
DO \$\$ BEGIN NULL; END \$\$;
ROLLBACK TO sp1;
COMMIT;
"
write "nested_savepoints" "
BEGIN;
CREATE TABLE app.temp_table (id int);
SAVEPOINT s1;
DO \$\$ BEGIN NULL; END \$\$;
SAVEPOINT s2;
ALTER TABLE app.users ADD COLUMN temp_col int;
ROLLBACK TO s2;
RELEASE SAVEPOINT s2;
DROP TABLE app.temp_table;
COMMIT;
"

# === Real-world migration patterns ===
write "add_user_avatar" "
BEGIN;
ALTER TABLE app.users ADD COLUMN avatar_url text;
ALTER TABLE app.users ADD COLUMN avatar_updated_at timestamptz;
CREATE INDEX idx_users_avatar ON app.users (avatar_url) WHERE avatar_url IS NOT NULL;
COMMIT;
"
write "add_post_likes" "
BEGIN;
CREATE TABLE app.post_likes (
    user_id int NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
    post_id int NOT NULL REFERENCES app.posts(id) ON DELETE CASCADE,
    created_at timestamptz DEFAULT now(),
    PRIMARY KEY (user_id, post_id)
);
CREATE INDEX idx_post_likes_post ON app.post_likes (post_id);
COMMIT;
"
write "refactor_status_enum" "
BEGIN;
CREATE TYPE app.new_post_status AS ENUM ('draft', 'review', 'published', 'archived');
ALTER TABLE app.posts ALTER COLUMN status TYPE app.new_post_status USING status::app.new_post_status;
DROP TYPE app.post_status;
ALTER TYPE app.new_post_status RENAME TO post_status;
COMMIT;
"
write "add_audit_trail" "
BEGIN;
CREATE TABLE app.audit_log (
    id bigserial PRIMARY KEY,
    table_name text NOT NULL,
    record_id int NOT NULL,
    action text NOT NULL CHECK (action IN ('INSERT', 'UPDATE', 'DELETE')),
    old_data jsonb,
    new_data jsonb,
    performed_by int REFERENCES app.users(id),
    performed_at timestamptz DEFAULT now()
);
CREATE INDEX idx_audit_table ON app.audit_log (table_name, record_id);
CREATE INDEX idx_audit_performed ON app.audit_log (performed_at);
COMMIT;
"
write "rename_column_safely" "
BEGIN;
ALTER TABLE app.users ADD COLUMN full_name text;
UPDATE app.users SET full_name = name;
ALTER TABLE app.users ALTER COLUMN full_name SET NOT NULL;
ALTER TABLE app.users DROP COLUMN name;
ALTER TABLE app.users RENAME COLUMN full_name TO name;
COMMIT;
"
write "multi_schema_migration" "
BEGIN;
CREATE SCHEMA billing;
CREATE TABLE billing.invoices (
    id serial PRIMARY KEY,
    user_id int REFERENCES app.users(id),
    amount numeric(12,2) NOT NULL,
    status text DEFAULT 'pending',
    created_at timestamptz DEFAULT now()
);
CREATE TABLE billing.payments (
    id serial PRIMARY KEY,
    invoice_id int REFERENCES billing.invoices(id),
    amount numeric(12,2) NOT NULL,
    method text NOT NULL,
    paid_at timestamptz DEFAULT now()
);
CREATE INDEX idx_invoices_user ON billing.invoices (user_id);
CREATE INDEX idx_payments_invoice ON billing.payments (invoice_id);
GRANT USAGE ON SCHEMA billing TO app_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA billing TO app_readonly;
COMMIT;
"
write "partition_existing_table" "
BEGIN;
CREATE TABLE app.events (
    id bigserial PRIMARY KEY,
    user_id int REFERENCES app.users(id),
    event_type text NOT NULL,
    payload jsonb,
    created_at timestamptz DEFAULT now()
) PARTITION BY RANGE (created_at);
CREATE TABLE app.events_2024 PARTITION OF app.events FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');
CREATE TABLE app.events_2025 PARTITION OF app.events FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
CREATE TABLE app.events_default PARTITION OF app.events DEFAULT;
COMMIT;
"
write "create_function_trigger" "
BEGIN;
CREATE OR REPLACE FUNCTION app.update_updated_at() RETURNS trigger LANGUAGE plpgsql AS \$\$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
\$\$;

CREATE TRIGGER trg_users_updated BEFORE UPDATE ON app.users
    FOR EACH ROW EXECUTE FUNCTION app.update_updated_at();

CREATE TRIGGER trg_posts_updated BEFORE UPDATE ON app.posts
    FOR EACH ROW EXECUTE FUNCTION app.update_updated_at();
COMMIT;
"
write "enable_rls" "
BEGIN;
ALTER TABLE app.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.posts ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_isolation ON app.users USING (id = current_setting('app.current_user_id')::int);
CREATE POLICY post_visibility ON app.posts USING (status = 'published' OR user_id = current_setting('app.current_user_id')::int);
COMMIT;
"
write "drop_with_dependents" "
BEGIN;
DROP TRIGGER trg_users_updated ON app.users;
DROP FUNCTION app.update_updated_at();
ALTER TABLE app.users DROP COLUMN updated_at;
COMMIT;
"

# === Edge cases with real tables ===
write "drop_and_recreate" "
BEGIN;
DROP TABLE app.comments;
CREATE TABLE app.comments (
    id serial PRIMARY KEY,
    post_id int NOT NULL REFERENCES app.posts(id) ON DELETE CASCADE,
    user_id int NOT NULL REFERENCES app.users(id),
    body text NOT NULL,
    parent_id int REFERENCES app.comments(id),
    created_at timestamptz DEFAULT now()
);
COMMIT;
"
write "modify_pk_type" "ALTER TABLE app.users ALTER COLUMN id TYPE bigint;"
write "add_not_null_without_default" "ALTER TABLE app.users ADD COLUMN required_field text NOT NULL;"
write "concurrent_index_drop_create" "
DROP INDEX CONCURRENTLY IF EXISTS idx_posts_user;
CREATE INDEX CONCURRENTLY idx_posts_user_v2 ON app.posts (user_id, created_at);
"
write "mixed_operations" "
BEGIN;
ALTER TABLE app.users ADD COLUMN last_login_at timestamptz;
ALTER TABLE app.posts ADD COLUMN view_count int DEFAULT 0;
CREATE INDEX idx_posts_views ON app.posts (view_count DESC);
DO \$\$ BEGIN RAISE NOTICE 'migration step complete'; END \$\$;
COMMIT;
"
write "drop_table_referenced_by_fk" "DROP TABLE app.users;"
write "alter_table_with_active_view" "ALTER TABLE app.posts ADD COLUMN category text;"

echo "Generated $((N-1)) PostgreSQL-specific migration files"
