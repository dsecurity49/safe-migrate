CREATE TABLE sm_core.retained_list_parent (id integer NOT NULL) PARTITION BY LIST (id);
CREATE TABLE sm_core.retained_list_child PARTITION OF sm_core.retained_list_parent
    FOR VALUES IN (1, 2, 3);
ALTER TABLE sm_core.retained_list_parent DETACH PARTITION sm_core.retained_list_child CONCURRENTLY;