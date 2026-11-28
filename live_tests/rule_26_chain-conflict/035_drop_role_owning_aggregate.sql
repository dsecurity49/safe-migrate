SET lock_timeout = '2s';
SET statement_timeout = '5s';
CREATE AGGREGATE sm_core.role_owned_agg(integer) (sfunc = int4pl, stype = integer);
ALTER AGGREGATE sm_core.role_owned_agg(integer) OWNER TO sm_set_member;
DROP ROLE sm_set_member;
