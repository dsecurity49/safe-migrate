CREATE SCHEMA sm_type_early;
CREATE SCHEMA sm_type_late;
CREATE TABLE sm_type_early.shadowed_type (id integer);
CREATE DOMAIN sm_type_late.shadowed_type AS integer;
CREATE DOMAIN sm_type_early.dropped_type AS integer;
CREATE DOMAIN sm_type_late.dropped_type AS bigint;
DROP DOMAIN sm_type_early.dropped_type;
SET search_path TO sm_type_early, sm_type_late, public;
CREATE TABLE public.type_namespace_probe (
    selected_type shadowed_type,
    selected_after_tombstone dropped_type
);
