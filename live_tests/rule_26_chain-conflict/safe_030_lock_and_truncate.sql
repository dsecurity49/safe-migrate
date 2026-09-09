CREATE TABLE sm_core.batch1_lock_target (id integer);
LOCK TABLE ONLY sm_core.batch1_lock_target IN SHARE ROW EXCLUSIVE MODE NOWAIT;
TRUNCATE TABLE ONLY sm_core.batch1_lock_target CONTINUE IDENTITY RESTRICT;
