CREATE TABLE sm_core.catalog_inherit_parent (
    id integer NOT NULL,
    payload text,
    CONSTRAINT catalog_inherit_check CHECK (id > 0)
);
CREATE TABLE sm_core.catalog_inherit_child (
    extra text
) INHERITS (sm_core.catalog_inherit_parent);
ALTER TABLE sm_core.catalog_inherit_child NO INHERIT sm_core.catalog_inherit_parent;
CREATE TABLE sm_core.catalog_inherit_attached () INHERITS (sm_core.catalog_inherit_parent);
ALTER TABLE sm_core.catalog_inherit_attached NO INHERIT sm_core.catalog_inherit_parent;
ALTER TABLE sm_core.catalog_inherit_attached INHERIT sm_core.catalog_inherit_parent;
