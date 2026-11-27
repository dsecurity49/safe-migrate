SET lock_timeout = '2s';
SET statement_timeout = '5s';
CREATE FUNCTION sm_core.srf_diff_test() RETURNS SETOF integer
    LANGUAGE sql
    ROWS 10 COST 25 PARALLEL SAFE STRICT
    SET search_path = sm_core, public
    RESET search_path
    AS 'SELECT 1';
ALTER FUNCTION sm_core.srf_diff_test() SUPPORT pg_catalog.generate_series_int4_support;
ALTER ROUTINE sm_core.srf_diff_test() SUPPORT generate_series_int4_support;
ALTER FUNCTION sm_core.srf_diff_test() DEPENDS ON EXTENSION plpgsql;
ALTER FUNCTION sm_core.srf_diff_test() NO DEPENDS ON EXTENSION plpgsql;
ALTER ROUTINE sm_core.srf_diff_test() OWNER TO app_user;
