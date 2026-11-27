SET lock_timeout = '2s';
SET statement_timeout = '5s';
CREATE FUNCTION sm_core.bad_atomic_col() RETURNS integer
    LANGUAGE sql
BEGIN ATOMIC
    SELECT no_such_col FROM sm_core.t;
END;
