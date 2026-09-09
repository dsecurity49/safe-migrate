CREATE TABLE sm_core.batch1_metadata_reset (
    id integer,
    payload text
) WITH (fillfactor = 75);
ALTER TABLE sm_core.batch1_metadata_reset RESET (fillfactor);
ALTER TABLE sm_core.batch1_metadata_reset ALTER COLUMN payload SET (n_distinct = 0.5);
ALTER TABLE sm_core.batch1_metadata_reset ALTER COLUMN payload RESET (n_distinct);
ALTER TABLE sm_core.batch1_metadata_reset ALTER COLUMN payload SET STATISTICS 450;
ALTER TABLE sm_core.batch1_metadata_reset ALTER COLUMN payload SET STATISTICS DEFAULT;
ALTER TABLE sm_core.batch1_metadata_reset ALTER COLUMN payload SET STORAGE MAIN;
ALTER TABLE sm_core.batch1_metadata_reset ALTER COLUMN payload SET STORAGE DEFAULT;
ALTER TABLE sm_core.batch1_metadata_reset ALTER COLUMN payload SET COMPRESSION pglz;
ALTER TABLE sm_core.batch1_metadata_reset ALTER COLUMN payload SET COMPRESSION default;
