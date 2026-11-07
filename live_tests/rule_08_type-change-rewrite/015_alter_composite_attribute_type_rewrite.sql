CREATE TYPE sm_core.live_comp_rewrite AS (
    code text,
    counter integer
);
CREATE TABLE sm_core.live_comp_rewrite_table OF sm_core.live_comp_rewrite;
ALTER TYPE sm_core.live_comp_rewrite ALTER ATTRIBUTE counter TYPE bigint CASCADE;
