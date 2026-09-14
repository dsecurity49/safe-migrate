CREATE TABLE sm_core.rename_parent (
    id integer CONSTRAINT rename_parent_id_check CHECK (id > 0)
);
CREATE TABLE sm_core.rename_child () INHERITS (sm_core.rename_parent);
CREATE INDEX rename_child_id_idx ON sm_core.rename_child (id);
ALTER TABLE sm_core.rename_parent RENAME COLUMN id TO renamed;
