CREATE FUNCTION sm_core.phase5_alias(value int4)
RETURNS int4
LANGUAGE SQL
IMMUTABLE
AS $$ SELECT value $$;
ALTER FUNCTION sm_core.phase5_alias(int) STABLE;
DROP FUNCTION sm_core.phase5_alias(integer);
