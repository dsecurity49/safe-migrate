CREATE TABLE sm_core.catalog_generated_change (
    base integer,
    calculated integer GENERATED ALWAYS AS (base * 2) STORED
);
ALTER TABLE sm_core.catalog_generated_change
    ALTER COLUMN calculated SET EXPRESSION AS (base * 3);
