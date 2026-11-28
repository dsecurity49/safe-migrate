SET lock_timeout = '2s';
SET statement_timeout = '5s';
CREATE FUNCTION sm_core.atomic_sum(x integer) RETURNS integer
    LANGUAGE sql
BEGIN ATOMIC
    SELECT id + x FROM sm_core.t;
END;
ALTER ROUTINE sm_core.atomic_sum(integer) STABLE;
