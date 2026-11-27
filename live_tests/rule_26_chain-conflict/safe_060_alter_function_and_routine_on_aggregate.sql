SET lock_timeout = '2s';
SET statement_timeout = '5s';
CREATE AGGREGATE sm_core.agg_diff_test(integer) (sfunc = int4pl, stype = integer);
ALTER FUNCTION sm_core.agg_diff_test(integer) RENAME TO agg_diff_renamed;
ALTER ROUTINE sm_core.agg_diff_renamed(integer) OWNER TO app_user;
ALTER FUNCTION sm_core.agg_diff_renamed(integer) SET SCHEMA public;
DROP AGGREGATE public.agg_diff_renamed(integer);
