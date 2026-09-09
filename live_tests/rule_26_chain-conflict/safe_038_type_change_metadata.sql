CREATE TABLE sm_core.catalog_type_change (
    text_value text,
    number_value numeric(10, 2),
    optional integer DEFAULT NULL
);
ALTER TABLE sm_core.catalog_type_change ALTER COLUMN text_value SET STORAGE MAIN;
ALTER TABLE sm_core.catalog_type_change ALTER COLUMN text_value SET COMPRESSION pglz;
ALTER TABLE sm_core.catalog_type_change ALTER COLUMN text_value TYPE varchar(80);
ALTER TABLE sm_core.catalog_type_change ALTER COLUMN number_value TYPE double precision;
