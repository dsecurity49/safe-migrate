CREATE TYPE sm_core.live_comp_cascade AS (
    code text,
    description text
);
CREATE TABLE sm_core.live_comp_typed OF sm_core.live_comp_cascade;
ALTER TYPE sm_core.live_comp_cascade DROP ATTRIBUTE description CASCADE;
