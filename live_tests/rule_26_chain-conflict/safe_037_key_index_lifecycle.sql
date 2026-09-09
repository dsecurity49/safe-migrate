CREATE TABLE sm_core.batch1_keys (id integer, value text);
ALTER TABLE sm_core.batch1_keys ADD CONSTRAINT batch1_keys_unique UNIQUE (value);
ALTER TABLE sm_core.batch1_keys DROP CONSTRAINT batch1_keys_unique;
ALTER TABLE sm_core.batch1_keys ADD CONSTRAINT batch1_keys_unique UNIQUE (value);
ALTER TABLE sm_core.batch1_keys ADD CONSTRAINT batch1_keys_primary PRIMARY KEY (id);
