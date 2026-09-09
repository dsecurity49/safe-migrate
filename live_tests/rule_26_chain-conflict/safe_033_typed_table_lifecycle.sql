CREATE TYPE sm_core.catalog_row_type AS (
    id integer,
    payload text
);
CREATE TABLE sm_core.catalog_typed_table OF sm_core.catalog_row_type;
ALTER TABLE sm_core.catalog_typed_table NOT OF;
CREATE TABLE sm_core.catalog_still_typed OF sm_core.catalog_row_type;
