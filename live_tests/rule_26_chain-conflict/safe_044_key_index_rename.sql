CREATE TABLE sm_core.rename_key_target (id integer NOT NULL);
ALTER TABLE sm_core.rename_key_target ADD CONSTRAINT original_unique_key UNIQUE (id);
ALTER TABLE sm_core.rename_key_target CLUSTER ON original_unique_key;
ALTER TABLE sm_core.rename_key_target REPLICA IDENTITY USING INDEX original_unique_key;
ALTER TABLE sm_core.rename_key_target RENAME CONSTRAINT original_unique_key TO renamed_unique_key;
ALTER INDEX sm_core.renamed_unique_key RENAME TO final_unique_key;
