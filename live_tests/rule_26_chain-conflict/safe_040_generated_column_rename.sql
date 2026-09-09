CREATE TABLE sm_core.catalog_generated_rename (
    abs integer,
    negative integer GENERATED ALWAYS AS (-abs) STORED,
    calculated integer GENERATED ALWAYS AS (abs(abs) + abs) STORED
);
ALTER TABLE sm_core.catalog_generated_rename RENAME COLUMN abs TO "Renamed";
CREATE FUNCTION sm_core.catalog_absolute(integer) RETURNS integer
    LANGUAGE sql IMMUTABLE AS 'SELECT abs($1)';
CREATE TABLE sm_core.catalog_generated_qualified_rename (
    sm_core integer,
    calculated integer GENERATED ALWAYS AS (sm_core.catalog_absolute(sm_core)) STORED
);
ALTER TABLE sm_core.catalog_generated_qualified_rename
    RENAME COLUMN sm_core TO "Renamed";
-- Keep the function schema visible in PostgreSQL's deparsed catalog expression.
SET search_path = pg_catalog, public;
