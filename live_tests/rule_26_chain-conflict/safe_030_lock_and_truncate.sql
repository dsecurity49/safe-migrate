CREATE TABLE sm_core.catalog_lock_target (id integer);
LOCK TABLE ONLY sm_core.catalog_lock_target IN SHARE ROW EXCLUSIVE MODE NOWAIT;
TRUNCATE TABLE ONLY sm_core.catalog_lock_target CONTINUE IDENTITY RESTRICT;
