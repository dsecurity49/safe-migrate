CREATE TABLE sm_core.catalog_partition_parent (
    id integer NOT NULL,
    payload text,
    CONSTRAINT catalog_partition_parent_check CHECK (id >= 0),
    CONSTRAINT catalog_partition_parent_key UNIQUE (id)
) PARTITION BY RANGE (id);
CREATE TRIGGER catalog_partition_trigger
    BEFORE INSERT ON sm_core.catalog_partition_parent
    FOR EACH ROW EXECUTE FUNCTION sm_core.f();
CREATE TABLE sm_core.catalog_partition_child
    PARTITION OF sm_core.catalog_partition_parent
    FOR VALUES FROM (0) TO (100);
