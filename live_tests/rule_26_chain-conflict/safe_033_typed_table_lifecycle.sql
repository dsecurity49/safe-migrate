CREATE TYPE sm_core.batch1_row_type AS (
    id integer,
    payload text
);
CREATE TABLE sm_core.batch1_typed_table OF sm_core.batch1_row_type;
ALTER TABLE sm_core.batch1_typed_table NOT OF;
CREATE TABLE sm_core.batch1_still_typed OF sm_core.batch1_row_type;
