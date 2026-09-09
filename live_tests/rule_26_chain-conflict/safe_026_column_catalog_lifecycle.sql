CREATE TABLE sm_core.catalog_column_catalog (
    base integer NOT NULL,
    generated integer GENERATED ALWAYS AS (base * 2) STORED,
    payload text
);
ALTER TABLE sm_core.catalog_column_catalog ALTER COLUMN payload SET STORAGE MAIN;
ALTER TABLE sm_core.catalog_column_catalog ALTER COLUMN payload SET COMPRESSION pglz;
ALTER TABLE sm_core.catalog_column_catalog ALTER COLUMN payload SET STATISTICS 321;
ALTER TABLE sm_core.catalog_column_catalog ALTER COLUMN payload SET (n_distinct = 0.25);
