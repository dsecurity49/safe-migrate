CREATE FUNCTION sm_core.generated_visible_double(integer)
RETURNS integer LANGUAGE SQL IMMUTABLE AS 'SELECT $1 * 2';
SET search_path TO sm_core, public;
CREATE TABLE sm_core.catalog_generated_visible_function (
    base integer,
    calculated integer GENERATED ALWAYS AS (sm_core.generated_visible_double(base)) STORED
);
