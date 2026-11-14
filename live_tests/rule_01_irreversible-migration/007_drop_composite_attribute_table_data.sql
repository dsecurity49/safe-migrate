CREATE TYPE sm_core.live_comp_attr AS (
    id integer,
    bio text
);
CREATE TABLE sm_core.live_comp_table (
    pk integer,
    profile sm_core.live_comp_attr
);
ALTER TYPE sm_core.live_comp_attr DROP ATTRIBUTE bio;
