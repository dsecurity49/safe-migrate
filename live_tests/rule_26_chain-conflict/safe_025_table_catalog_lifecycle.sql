CREATE TABLE sm_core.catalog_table_catalog (
    id bigint NOT NULL,
    payload text
);
CREATE UNIQUE INDEX catalog_table_catalog_id_key
    ON sm_core.catalog_table_catalog (id);
ALTER TABLE sm_core.catalog_table_catalog CLUSTER ON catalog_table_catalog_id_key;
ALTER TABLE sm_core.catalog_table_catalog REPLICA IDENTITY USING INDEX catalog_table_catalog_id_key;
ALTER TABLE sm_core.catalog_table_catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE sm_core.catalog_table_catalog FORCE ROW LEVEL SECURITY;
ALTER TABLE sm_core.catalog_table_catalog SET (fillfactor = 80);
ALTER TABLE sm_core.catalog_table_catalog SET UNLOGGED;
ALTER TABLE sm_core.catalog_table_catalog SET ACCESS METHOD heap;
