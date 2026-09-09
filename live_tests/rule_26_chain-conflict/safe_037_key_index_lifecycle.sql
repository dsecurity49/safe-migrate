CREATE TABLE sm_core.catalog_keys (id integer, value text);
ALTER TABLE sm_core.catalog_keys ADD CONSTRAINT catalog_keys_unique UNIQUE (value);
ALTER TABLE sm_core.catalog_keys DROP CONSTRAINT catalog_keys_unique;
ALTER TABLE sm_core.catalog_keys ADD CONSTRAINT catalog_keys_unique UNIQUE (value);
ALTER TABLE sm_core.catalog_keys ADD CONSTRAINT catalog_keys_primary PRIMARY KEY (id);
