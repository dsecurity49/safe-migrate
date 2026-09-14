CREATE TABLE sm_core.retained_range_parent (id integer NOT NULL) PARTITION BY RANGE (id);
CREATE TABLE sm_core.retained_range_child PARTITION OF sm_core.retained_range_parent
    FOR VALUES FROM (0) TO (100);
ALTER TABLE sm_core.retained_range_parent DETACH PARTITION sm_core.retained_range_child CONCURRENTLY;