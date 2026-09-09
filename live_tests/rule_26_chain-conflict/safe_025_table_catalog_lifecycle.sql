CREATE TABLE sm_core.batch1_table_catalog (
    id bigint NOT NULL,
    payload text
);
CREATE UNIQUE INDEX batch1_table_catalog_id_key
    ON sm_core.batch1_table_catalog (id);
ALTER TABLE sm_core.batch1_table_catalog CLUSTER ON batch1_table_catalog_id_key;
ALTER TABLE sm_core.batch1_table_catalog REPLICA IDENTITY USING INDEX batch1_table_catalog_id_key;
ALTER TABLE sm_core.batch1_table_catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE sm_core.batch1_table_catalog FORCE ROW LEVEL SECURITY;
ALTER TABLE sm_core.batch1_table_catalog SET (fillfactor = 80);
ALTER TABLE sm_core.batch1_table_catalog SET UNLOGGED;
ALTER TABLE sm_core.batch1_table_catalog SET ACCESS METHOD heap;
