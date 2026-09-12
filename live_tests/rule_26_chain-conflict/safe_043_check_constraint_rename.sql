CREATE TABLE sm_core.check_rename_target (
    id integer,
    payload integer,
    CONSTRAINT original_id_check CHECK (id > 0),
    CONSTRAINT original_payload_check CHECK (payload > 0)
);
ALTER TABLE sm_core.check_rename_target RENAME CONSTRAINT original_id_check TO renamed_id_check;
ALTER TABLE sm_core.check_rename_target RENAME CONSTRAINT original_payload_check TO renamed_payload_check;
ALTER TABLE sm_core.check_rename_target DROP CONSTRAINT renamed_payload_check;
ALTER TABLE sm_core.check_rename_target DROP COLUMN payload;
