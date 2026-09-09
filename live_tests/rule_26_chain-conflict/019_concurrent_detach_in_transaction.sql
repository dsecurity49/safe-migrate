CREATE TABLE sm_core.catalog_detach_parent(id integer) PARTITION BY RANGE(id);
CREATE TABLE sm_core.catalog_detach_child PARTITION OF sm_core.catalog_detach_parent
    FOR VALUES FROM (0) TO (10);
BEGIN;
ALTER TABLE sm_core.catalog_detach_parent
    DETACH PARTITION sm_core.catalog_detach_child CONCURRENTLY;
