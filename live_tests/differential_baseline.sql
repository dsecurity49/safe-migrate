-- Canonical enterprise-scale baseline owned by the live differential harness.
-- Every harness schema is prefixed with sm_ so reset remains narrowly scoped.
DROP SCHEMA IF EXISTS sm_analytics CASCADE;
DROP SCHEMA IF EXISTS sm_audit CASCADE;
DROP SCHEMA IF EXISTS sm_fulfillment CASCADE;
DROP SCHEMA IF EXISTS sm_billing CASCADE;
DROP SCHEMA IF EXISTS sm_catalog CASCADE;
DROP SCHEMA IF EXISTS sm_core CASCADE;
DROP SCHEMA IF EXISTS sm_identity CASCADE;
DROP SCHEMA IF EXISTS sm_role_quote CASCADE;
DROP SCHEMA IF EXISTS app_user CASCADE;
DROP SCHEMA IF EXISTS staging CASCADE;
DROP SCHEMA IF EXISTS pub CASCADE;
DROP FUNCTION IF EXISTS public.g() CASCADE;
DROP FUNCTION IF EXISTS public.f() CASCADE;
DROP TABLE IF EXISTS public.new_table CASCADE;
DROP TABLE IF EXISTS public.test_table_renamed CASCADE;
DROP TABLE IF EXISTS public.test_table_new CASCADE;
DROP TABLE IF EXISTS public.child CASCADE;
DROP TABLE IF EXISTS public.parent CASCADE;
DROP TABLE IF EXISTS public.child_table CASCADE;
DROP TABLE IF EXISTS public.list_child CASCADE;
DROP TABLE IF EXISTS public.range_child CASCADE;
DROP TABLE IF EXISTS public.hash_child CASCADE;
DROP TABLE IF EXISTS public.list_parent CASCADE;
DROP TABLE IF EXISTS public.range_parent CASCADE;
DROP TABLE IF EXISTS public.hash_parent CASCADE;
DROP TABLE IF EXISTS public.test_table CASCADE;

CREATE SCHEMA IF NOT EXISTS public;
DO $baseline_role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
        CREATE ROLE app_user;
    END IF;
END
$baseline_role$;
DO $quoted_baseline_role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'owner''s_role') THEN
        CREATE ROLE "owner's_role";
    END IF;
END
$quoted_baseline_role$;
DO $membership_roles$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'sm_set_member',
        'sm_set_bridge',
        'sm_set_target',
        'sm_no_set_target'
    ] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN', role_name);
        END IF;
    END LOOP;
END
$membership_roles$;

GRANT sm_set_target TO sm_set_bridge;
GRANT sm_set_bridge TO sm_set_member;
DO $set_option_membership$
BEGIN
    IF current_setting('server_version_num')::integer >= 160000 THEN
        EXECUTE 'GRANT sm_no_set_target TO sm_set_member WITH SET FALSE';
    END IF;
END
$set_option_membership$;

CREATE SCHEMA sm_identity;
CREATE SCHEMA sm_core;
CREATE SCHEMA sm_catalog;
CREATE SCHEMA sm_billing;
CREATE SCHEMA sm_fulfillment;
CREATE SCHEMA sm_audit;
CREATE SCHEMA sm_analytics;
CREATE SCHEMA app_user AUTHORIZATION app_user;
CREATE SCHEMA sm_role_quote AUTHORIZATION "owner's_role";
GRANT CREATE ON SCHEMA sm_core TO sm_set_target;

CREATE TYPE sm_identity.user_state AS ENUM ('invited', 'active', 'suspended', 'deleted');
CREATE TYPE sm_core.environment_kind AS ENUM ('development', 'staging', 'production');
CREATE TYPE sm_core.my_enum AS ENUM ('a', 'b', 'c', 'old', 'existing_val');
CREATE TYPE sm_core.status_type AS ENUM ('active', 'disabled');
CREATE TYPE sm_core."MyEnum" AS ENUM ('first', 'second');
CREATE TYPE sm_catalog.product_state AS ENUM ('draft', 'active', 'retired');
CREATE TYPE sm_billing.invoice_state AS ENUM ('draft', 'open', 'paid', 'void');
CREATE TYPE sm_billing.payment_state AS ENUM ('pending', 'settled', 'failed', 'refunded');
CREATE TYPE sm_fulfillment.order_state AS ENUM ('pending', 'confirmed', 'shipped', 'delivered', 'cancelled');
CREATE TYPE sm_audit.job_state AS ENUM ('queued', 'running', 'succeeded', 'failed');

CREATE DOMAIN sm_identity.email_address AS text
    CHECK (VALUE = lower(VALUE) AND position('@' IN VALUE) > 1);
CREATE DOMAIN sm_core.slug AS text
    CHECK (VALUE ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$');
CREATE DOMAIN sm_catalog.sku AS text CHECK (length(VALUE) BETWEEN 3 AND 64);
CREATE DOMAIN sm_billing.currency_code AS text CHECK (VALUE ~ '^[A-Z]{3}$');
CREATE DOMAIN sm_billing.money_amount AS numeric(19, 4) CHECK (VALUE >= 0);
CREATE DOMAIN sm_fulfillment.country_code AS text CHECK (VALUE ~ '^[A-Z]{2}$');

-- Seven bounded contexts, nine relations each (63 service tables).
DO $baseline$
DECLARE
    relation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY[
        'tenants', 'users', 'user_profiles', 'roles', 'permissions',
        'user_roles', 'role_permissions', 'api_clients', 'sessions'
    ] LOOP
        EXECUTE format(
            'CREATE TABLE sm_identity.%I (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT clock_timestamp())',
            relation_name
        );
    END LOOP;

    FOREACH relation_name IN ARRAY ARRAY[
        'organizations', 'teams', 'team_members', 'projects', 'project_members',
        'environments', 'feature_flags', 'tags', 'webhooks'
    ] LOOP
        EXECUTE format(
            'CREATE TABLE sm_core.%I (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT clock_timestamp())',
            relation_name
        );
    END LOOP;

    FOREACH relation_name IN ARRAY ARRAY[
        'categories', 'brands', 'products', 'product_variants', 'price_lists',
        'prices', 'warehouses', 'inventory_items', 'inventory_balances'
    ] LOOP
        EXECUTE format(
            'CREATE TABLE sm_catalog.%I (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT clock_timestamp())',
            relation_name
        );
    END LOOP;

    FOREACH relation_name IN ARRAY ARRAY[
        'customers', 'payment_methods', 'subscriptions', 'subscription_items',
        'invoices', 'invoice_lines', 'payments', 'refunds', 'credit_notes'
    ] LOOP
        EXECUTE format(
            'CREATE TABLE sm_billing.%I (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT clock_timestamp())',
            relation_name
        );
    END LOOP;

    FOREACH relation_name IN ARRAY ARRAY[
        'addresses', 'carts', 'cart_items', 'orders', 'order_items',
        'shipments', 'shipment_items', 'returns', 'tracking_events'
    ] LOOP
        EXECUTE format(
            'CREATE TABLE sm_fulfillment.%I (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT clock_timestamp())',
            relation_name
        );
    END LOOP;

    FOREACH relation_name IN ARRAY ARRAY[
        'outbox_events', 'audit_events', 'login_events', 'webhook_deliveries',
        'job_runs', 'data_exports', 'data_imports', 'change_requests', 'retention_runs'
    ] LOOP
        EXECUTE format(
            'CREATE TABLE sm_audit.%I (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT clock_timestamp())',
            relation_name
        );
    END LOOP;

    FOREACH relation_name IN ARRAY ARRAY[
        'daily_tenant_metrics', 'daily_product_metrics', 'funnel_events',
        'report_definitions', 'report_runs', 'dashboard_definitions',
        'dashboard_widgets', 'metric_alerts', 'metric_samples'
    ] LOOP
        EXECUTE format(
            'CREATE TABLE sm_analytics.%I (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT clock_timestamp())',
            relation_name
        );
    END LOOP;
END
$baseline$;

CREATE TABLE sm_core.t (
    id integer,
    name text
);

CREATE TABLE sm_core.t_large (
    id integer,
    name text,
    data jsonb,
    col1 integer,
    col2 integer,
    created_at timestamptz
);
CREATE UNIQUE INDEX t_large_col1_prebuilt_key ON sm_core.t_large (col1);

CREATE TABLE sm_core.items (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name text
);

CREATE TABLE sm_core.a (
    id integer PRIMARY KEY
);

CREATE TABLE sm_core.b (
    id integer PRIMARY KEY,
    name text
);

CREATE VIEW sm_core.v AS
SELECT 1 AS id, 'baseline'::text AS name;

CREATE MATERIALIZED VIEW sm_core.mv AS
SELECT 0::bigint AS row_count
WITH NO DATA;

CREATE VIEW sm_core.myview AS
SELECT 1 AS id;

CREATE MATERIALIZED VIEW sm_core.mymat AS
SELECT 1 AS id
WITH NO DATA;

CREATE TABLE sm_core.matview_source (
    id integer PRIMARY KEY,
    name text
);

CREATE MATERIALIZED VIEW sm_core.mymatview AS
SELECT id, name
FROM sm_core.matview_source;
CREATE UNIQUE INDEX mymatview_id_idx ON sm_core.mymatview (id);

CREATE TABLE public.test_table (
    id integer PRIMARY KEY,
    tenant_id bigint REFERENCES sm_identity.tenants(id),
    name varchar(100),
    note text,
    category text,
    status text,
    created timestamptz,
    price numeric(12, 4),
    data text,
    ts timestamptz
);
CREATE INDEX test_table_note_idx ON public.test_table (note);

CREATE TABLE public.child_table (
    id integer PRIMARY KEY,
    test_table_id integer,
    CONSTRAINT child_table_test_table_fk
        FOREIGN KEY (test_table_id) REFERENCES public.test_table(id)
);

CREATE TABLE public.list_parent (id integer) PARTITION BY LIST (id);
CREATE TABLE public.list_child (id integer) PARTITION BY LIST (id);
CREATE TABLE public.range_parent (id integer) PARTITION BY RANGE (id);
CREATE TABLE public.range_child (id integer) PARTITION BY RANGE (id);
CREATE TABLE public.hash_parent (id integer) PARTITION BY HASH (id);
CREATE TABLE public.hash_child (id integer) PARTITION BY HASH (id);

CREATE TABLE public.parent (
    id integer,
    region text,
    occurred_on date
) PARTITION BY LIST (id);

CREATE TABLE public.child (
    LIKE public.parent INCLUDING ALL
);

-- Representative intra- and cross-schema dependency chains.
ALTER TABLE sm_identity.users
    ADD COLUMN tenant_id bigint NOT NULL REFERENCES sm_identity.tenants(id),
    ADD COLUMN email sm_identity.email_address NOT NULL UNIQUE,
    ADD COLUMN state sm_identity.user_state NOT NULL DEFAULT 'invited';
ALTER TABLE sm_identity.user_profiles
    ADD COLUMN user_id bigint NOT NULL UNIQUE REFERENCES sm_identity.users(id) ON DELETE CASCADE;
ALTER TABLE sm_identity.user_roles
    ADD COLUMN user_id bigint NOT NULL REFERENCES sm_identity.users(id) ON DELETE CASCADE,
    ADD COLUMN role_id bigint NOT NULL REFERENCES sm_identity.roles(id) ON DELETE CASCADE;
ALTER TABLE sm_identity.role_permissions
    ADD COLUMN role_id bigint NOT NULL REFERENCES sm_identity.roles(id) ON DELETE CASCADE,
    ADD COLUMN permission_id bigint NOT NULL REFERENCES sm_identity.permissions(id) ON DELETE CASCADE;

ALTER TABLE sm_core.organizations
    ADD COLUMN tenant_id bigint NOT NULL REFERENCES sm_identity.tenants(id),
    ADD COLUMN slug sm_core.slug NOT NULL;
ALTER TABLE sm_core.teams
    ADD COLUMN organization_id bigint NOT NULL REFERENCES sm_core.organizations(id);
ALTER TABLE sm_core.team_members
    ADD COLUMN team_id bigint NOT NULL REFERENCES sm_core.teams(id),
    ADD COLUMN user_id bigint NOT NULL REFERENCES sm_identity.users(id);
ALTER TABLE sm_core.projects
    ADD COLUMN organization_id bigint NOT NULL REFERENCES sm_core.organizations(id),
    ADD COLUMN slug sm_core.slug NOT NULL;
ALTER TABLE sm_core.environments
    ADD COLUMN project_id bigint NOT NULL REFERENCES sm_core.projects(id),
    ADD COLUMN kind sm_core.environment_kind NOT NULL;

ALTER TABLE sm_catalog.products
    ADD COLUMN tenant_id bigint NOT NULL REFERENCES sm_identity.tenants(id),
    ADD COLUMN brand_id bigint REFERENCES sm_catalog.brands(id),
    ADD COLUMN state sm_catalog.product_state NOT NULL DEFAULT 'draft';
ALTER TABLE sm_catalog.product_variants
    ADD COLUMN product_id bigint NOT NULL REFERENCES sm_catalog.products(id) ON DELETE CASCADE,
    ADD COLUMN sku sm_catalog.sku NOT NULL UNIQUE;
ALTER TABLE sm_catalog.inventory_items
    ADD COLUMN variant_id bigint NOT NULL REFERENCES sm_catalog.product_variants(id),
    ADD COLUMN warehouse_id bigint NOT NULL REFERENCES sm_catalog.warehouses(id);
ALTER TABLE sm_catalog.inventory_balances
    ADD COLUMN inventory_item_id bigint NOT NULL REFERENCES sm_catalog.inventory_items(id),
    ADD COLUMN available integer NOT NULL DEFAULT 0 CHECK (available >= 0);

ALTER TABLE sm_billing.customers
    ADD COLUMN tenant_id bigint NOT NULL REFERENCES sm_identity.tenants(id);
ALTER TABLE sm_billing.subscriptions
    ADD COLUMN customer_id bigint NOT NULL REFERENCES sm_billing.customers(id),
    ADD COLUMN project_id bigint REFERENCES sm_core.projects(id);
ALTER TABLE sm_billing.invoices
    ADD COLUMN customer_id bigint NOT NULL REFERENCES sm_billing.customers(id),
    ADD COLUMN state sm_billing.invoice_state NOT NULL DEFAULT 'draft',
    ADD COLUMN currency sm_billing.currency_code NOT NULL;
ALTER TABLE sm_billing.invoice_lines
    ADD COLUMN invoice_id bigint NOT NULL REFERENCES sm_billing.invoices(id) ON DELETE CASCADE,
    ADD COLUMN variant_id bigint REFERENCES sm_catalog.product_variants(id),
    ADD COLUMN amount sm_billing.money_amount NOT NULL;
ALTER TABLE sm_billing.payments
    ADD COLUMN invoice_id bigint NOT NULL REFERENCES sm_billing.invoices(id),
    ADD COLUMN state sm_billing.payment_state NOT NULL DEFAULT 'pending';

ALTER TABLE sm_fulfillment.addresses
    ADD COLUMN user_id bigint REFERENCES sm_identity.users(id),
    ADD COLUMN country sm_fulfillment.country_code NOT NULL;
ALTER TABLE sm_fulfillment.orders
    ADD COLUMN customer_id bigint NOT NULL REFERENCES sm_billing.customers(id),
    ADD COLUMN invoice_id bigint REFERENCES sm_billing.invoices(id),
    ADD COLUMN state sm_fulfillment.order_state NOT NULL DEFAULT 'pending';
ALTER TABLE sm_fulfillment.order_items
    ADD COLUMN order_id bigint NOT NULL REFERENCES sm_fulfillment.orders(id) ON DELETE CASCADE,
    ADD COLUMN variant_id bigint NOT NULL REFERENCES sm_catalog.product_variants(id);
ALTER TABLE sm_fulfillment.shipments
    ADD COLUMN order_id bigint NOT NULL REFERENCES sm_fulfillment.orders(id);
ALTER TABLE sm_fulfillment.shipment_items
    ADD COLUMN shipment_id bigint NOT NULL REFERENCES sm_fulfillment.shipments(id),
    ADD COLUMN order_item_id bigint NOT NULL REFERENCES sm_fulfillment.order_items(id);

ALTER TABLE sm_audit.audit_events
    ADD COLUMN tenant_id bigint REFERENCES sm_identity.tenants(id),
    ADD COLUMN actor_id bigint REFERENCES sm_identity.users(id),
    ADD COLUMN payload jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE sm_audit.job_runs
    ADD COLUMN state sm_audit.job_state NOT NULL DEFAULT 'queued';
ALTER TABLE sm_audit.change_requests
    ADD COLUMN test_table_id integer REFERENCES public.test_table(id),
    ADD COLUMN requested_by bigint REFERENCES sm_identity.users(id);
ALTER TABLE sm_analytics.daily_tenant_metrics
    ADD COLUMN tenant_id bigint NOT NULL REFERENCES sm_identity.tenants(id);
ALTER TABLE sm_analytics.daily_product_metrics
    ADD COLUMN product_id bigint NOT NULL REFERENCES sm_catalog.products(id);
ALTER TABLE sm_analytics.report_runs
    ADD COLUMN definition_id bigint NOT NULL REFERENCES sm_analytics.report_definitions(id),
    ADD COLUMN requested_by bigint REFERENCES sm_identity.users(id);

CREATE FUNCTION sm_audit.capture_row_change() RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    INSERT INTO sm_audit.audit_events(payload)
    VALUES (jsonb_build_object('schema', TG_TABLE_SCHEMA, 'table', TG_TABLE_NAME, 'operation', TG_OP));
    RETURN COALESCE(NEW, OLD);
END
$function$;

CREATE FUNCTION sm_core.f() RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RETURN COALESCE(NEW, OLD);
END
$function$;

CREATE FUNCTION sm_core.f(integer) RETURNS integer
LANGUAGE sql VOLATILE
AS 'SELECT $1';

CREATE FUNCTION sm_core.f(text) RETURNS text
LANGUAGE sql VOLATILE
AS 'SELECT $1';

CREATE FUNCTION sm_core.f_safe(integer, text) RETURNS integer
LANGUAGE sql
AS 'SELECT $1';

CREATE FUNCTION sm_core.f_safe(VARIADIC integer[]) RETURNS integer
LANGUAGE sql
AS 'SELECT COALESCE($1[1], 0)';

CREATE FUNCTION sm_core.f_safe(OUT result integer)
LANGUAGE sql
AS 'SELECT 1';

CREATE FUNCTION sm_core.f_safe(value integer DEFAULT 1) RETURNS SETOF integer
LANGUAGE sql
AS 'SELECT $1';

CREATE FUNCTION public.f() RETURNS integer
LANGUAGE sql VOLATILE
AS 'SELECT 1';

CREATE TRIGGER audit_public_test_table
AFTER INSERT OR UPDATE OR DELETE ON public.test_table
FOR EACH ROW EXECUTE FUNCTION sm_audit.capture_row_change();
CREATE TRIGGER check_trigger
BEFORE INSERT OR UPDATE ON public.test_table
FOR EACH ROW EXECUTE FUNCTION sm_audit.capture_row_change();
CREATE TRIGGER user_insert_trigger
BEFORE INSERT ON public.test_table
FOR EACH ROW EXECUTE FUNCTION sm_audit.capture_row_change();
CREATE TRIGGER audit_trigger
AFTER INSERT OR UPDATE OR DELETE ON public.test_table
FOR EACH ROW EXECUTE FUNCTION sm_audit.capture_row_change();
CREATE TRIGGER t
AFTER INSERT ON public.test_table
FOR EACH ROW EXECUTE FUNCTION sm_core.f();
ALTER TABLE public.test_table DISABLE TRIGGER audit_trigger;
CREATE TRIGGER audit_identity_users
AFTER INSERT OR UPDATE OR DELETE ON sm_identity.users
FOR EACH ROW EXECUTE FUNCTION sm_audit.capture_row_change();
CREATE TRIGGER audit_billing_invoices
AFTER INSERT OR UPDATE OR DELETE ON sm_billing.invoices
FOR EACH ROW EXECUTE FUNCTION sm_audit.capture_row_change();
CREATE TRIGGER audit_fulfillment_orders
AFTER INSERT OR UPDATE OR DELETE ON sm_fulfillment.orders
FOR EACH ROW EXECUTE FUNCTION sm_audit.capture_row_change();

CREATE VIEW sm_core.active_users AS
SELECT u.id, u.tenant_id, u.email
FROM sm_identity.users u
WHERE u.state = 'active';

CREATE VIEW sm_billing.open_invoices AS
SELECT i.id, i.customer_id, i.currency
FROM sm_billing.invoices i
WHERE i.state = 'open';

CREATE MATERIALIZED VIEW sm_analytics.tenant_user_counts AS
SELECT tenant_id, count(*) AS user_count
FROM sm_identity.users
GROUP BY tenant_id
WITH NO DATA;

CREATE INDEX users_tenant_idx ON sm_identity.users (tenant_id);
CREATE INDEX projects_organization_idx ON sm_core.projects (organization_id);
CREATE INDEX variants_product_idx ON sm_catalog.product_variants (product_id);
CREATE INDEX invoices_customer_idx ON sm_billing.invoices (customer_id);
CREATE INDEX orders_customer_idx ON sm_fulfillment.orders (customer_id);
CREATE INDEX audit_events_tenant_created_idx ON sm_audit.audit_events (tenant_id, created_at);

-- Deliberately non-public: unqualified fixtures must follow live PostgreSQL resolution.
SET search_path TO sm_core, public;
