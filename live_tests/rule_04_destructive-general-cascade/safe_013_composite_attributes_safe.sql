CREATE TYPE sm_core.live_comp_free AS (
    code text,
    label text
);
ALTER TYPE sm_core.live_comp_free ADD ATTRIBUTE extra_field integer;
ALTER TYPE sm_core.live_comp_free RENAME ATTRIBUTE label TO title;
