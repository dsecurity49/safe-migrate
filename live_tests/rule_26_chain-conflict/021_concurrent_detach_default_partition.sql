CREATE TABLE sm_core.catalog_detach_default (id integer) PARTITION BY RANGE (id);
CREATE TABLE sm_core.catalog_detach_child PARTITION OF sm_core.catalog_detach_default
    FOR VALUES FROM (0) TO (10);
CREATE TABLE sm_core.catalog_detach_rest PARTITION OF sm_core.catalog_detach_default DEFAULT;
ALTER TABLE sm_core.catalog_detach_default DETACH PARTITION sm_core.catalog_detach_child CONCURRENTLY;
