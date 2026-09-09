CREATE TABLE sm_core.batch1_bounds (id integer) PARTITION /* typed strategy */ BY "RANGE" (id);
CREATE TABLE sm_core.batch1_bound_child PARTITION OF sm_core.batch1_bounds
    FOR VALUES FROM (0) TO (10);
CREATE TABLE sm_core.batch1_bound_default PARTITION OF sm_core.batch1_bounds DEFAULT;
ALTER TABLE sm_core.batch1_bounds DETACH PARTITION sm_core.batch1_bound_child;
ALTER TABLE sm_core.batch1_bounds ATTACH PARTITION sm_core.batch1_bound_child
    FOR VALUES FROM (10) TO (20);
