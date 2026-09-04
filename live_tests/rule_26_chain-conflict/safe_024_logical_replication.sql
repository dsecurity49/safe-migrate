-- Exercise publication and subscription cross-version semantics.
-- NOTE: a per-table WHERE (row filter) predicate is rejected by PostgreSQL for
-- partitioned tables, and row-filter parameters are not modeled by the
-- publication normalization, so publications here use column lists only.
CREATE PUBLICATION sm_pub_all FOR ALL TABLES;
CREATE PUBLICATION sm_pub_tables FOR TABLE sm_core.t (id, name), public.parent;
CREATE PUBLICATION sm_pub_schema FOR TABLES IN SCHEMA sm_core, public;
ALTER PUBLICATION sm_pub_schema ADD TABLE public.child;
