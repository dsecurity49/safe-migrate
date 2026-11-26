-- User-defined casts across all contexts track function dependencies and drop cleanly with CASCADE.
CREATE TYPE sm_core.cast_src_t AS (v integer);
CREATE TYPE sm_core.cast_dst_t AS (v integer);
CREATE FUNCTION sm_core.fn_cast_to_dst(sm_core.cast_src_t) RETURNS sm_core.cast_dst_t
    LANGUAGE sql IMMUTABLE AS 'SELECT ROW(($1).v)::sm_core.cast_dst_t';
CREATE CAST (sm_core.cast_src_t AS sm_core.cast_dst_t)
    WITH FUNCTION sm_core.fn_cast_to_dst(sm_core.cast_src_t) AS ASSIGNMENT;
DROP FUNCTION sm_core.fn_cast_to_dst(sm_core.cast_src_t) CASCADE;
CREATE CAST (sm_core.cast_src_t AS sm_core.cast_dst_t) WITH INOUT;
DROP CAST (sm_core.cast_src_t AS sm_core.cast_dst_t);
