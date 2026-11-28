SET lock_timeout = '2s';
SET statement_timeout = '5s';
CREATE FUNCTION sm_core.stat_expr_fn(x integer) RETURNS integer
    LANGUAGE sql IMMUTABLE AS 'SELECT x';
CREATE STATISTICS sm_core.stat_on_fn ON sm_core.stat_expr_fn(id), name FROM sm_core.t;
DROP FUNCTION sm_core.stat_expr_fn(integer);
