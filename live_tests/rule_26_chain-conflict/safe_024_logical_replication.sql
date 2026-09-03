-- Exercise publication and subscription cross-version semantics
CREATE PUBLICATION sm_pub_all FOR ALL TABLES;
CREATE PUBLICATION sm_pub_tables FOR TABLE sm_core.t (id, name), public.parent WHERE (id > 0);
CREATE PUBLICATION sm_pub_schema FOR TABLES IN SCHEMA sm_core, public;
ALTER PUBLICATION sm_pub_schema ADD TABLE public.child;
