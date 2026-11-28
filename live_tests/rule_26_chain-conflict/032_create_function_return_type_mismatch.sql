SET lock_timeout = '2s';
SET statement_timeout = '5s';
CREATE FUNCTION sm_core.bad_ret_type() RETURNS integer
    LANGUAGE sql
BEGIN ATOMIC
    SELECT name FROM sm_core.t;
END;
