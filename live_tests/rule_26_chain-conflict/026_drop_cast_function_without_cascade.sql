-- PostgreSQL rejects DROP FUNCTION without CASCADE when a cast depends on the function.
CREATE TYPE sm_core.cast_dep_src AS (v integer);
CREATE TYPE sm_core.cast_dep_dst AS (v integer);
CREATE FUNCTION sm_core.fn_cast_dep(sm_core.cast_dep_src) RETURNS sm_core.cast_dep_dst
    LANGUAGE sql IMMUTABLE AS 'SELECT ROW(($1).v)::sm_core.cast_dep_dst';
CREATE CAST (sm_core.cast_dep_src AS sm_core.cast_dep_dst)
    WITH FUNCTION sm_core.fn_cast_dep(sm_core.cast_dep_src);
DROP FUNCTION sm_core.fn_cast_dep(sm_core.cast_dep_src);
