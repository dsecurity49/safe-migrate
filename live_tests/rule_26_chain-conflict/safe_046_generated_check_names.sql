CREATE TABLE sm_core.check_name_holder (
    id integer CONSTRAINT check_name_target_id_check CHECK (id > 0)
);
CREATE TABLE sm_core.check_name_target (id integer CHECK (id > 0));
ALTER TABLE sm_core.check_name_target
    RENAME CONSTRAINT check_name_target_id_check1 TO retained_check;
ALTER TABLE sm_core.check_name_target DROP CONSTRAINT retained_check;
ALTER TABLE sm_core.check_name_target ADD CHECK (id < 100);
ALTER TABLE sm_core.check_name_target
    RENAME CONSTRAINT check_name_target_id_check1 TO upper_bound;
CREATE TABLE sm_core.table_check_names (
    id integer,
    other integer,
    CHECK (id > 0 AND id < 100),
    CHECK (id < other)
);
ALTER TABLE sm_core.table_check_names
    RENAME CONSTRAINT table_check_names_id_check TO bounded_id;
