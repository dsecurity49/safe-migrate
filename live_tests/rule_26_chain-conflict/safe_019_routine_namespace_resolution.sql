CREATE SCHEMA sm_routine_early;
CREATE SCHEMA sm_routine_late;
CREATE FUNCTION sm_routine_early.choose_value(value text)
RETURNS integer
LANGUAGE sql
IMMUTABLE
AS 'SELECT 1';
CREATE FUNCTION sm_routine_late.choose_value(value integer)
RETURNS integer
LANGUAGE sql
IMMUTABLE
AS 'SELECT value';
CREATE FUNCTION sm_routine_early.dropped_routine(value integer)
RETURNS integer
LANGUAGE sql
IMMUTABLE
AS 'SELECT value';
CREATE FUNCTION sm_routine_late.dropped_routine(value integer)
RETURNS integer
LANGUAGE sql
IMMUTABLE
AS 'SELECT value';
DROP FUNCTION sm_routine_early.dropped_routine(integer);
SET search_path TO sm_routine_early, sm_routine_late, public;
ALTER FUNCTION choose_value(integer) STABLE;
ALTER FUNCTION dropped_routine(integer) STABLE;
