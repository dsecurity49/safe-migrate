-- PostgreSQL rejects DROP CAST without IF EXISTS when no cast exists between the source and target types.
CREATE TYPE sm_core.cast_missing_src AS (v integer);
CREATE TYPE sm_core.cast_missing_dst AS (v integer);
DROP CAST (sm_core.cast_missing_src AS sm_core.cast_missing_dst);
