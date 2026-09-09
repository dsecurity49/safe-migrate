CREATE TABLE sm_core.catalog_security_reset (id integer NOT NULL);
ALTER TABLE sm_core.catalog_security_reset ENABLE ROW LEVEL SECURITY;
ALTER TABLE sm_core.catalog_security_reset FORCE ROW LEVEL SECURITY;
ALTER TABLE sm_core.catalog_security_reset NO FORCE ROW LEVEL SECURITY;
ALTER TABLE sm_core.catalog_security_reset DISABLE ROW LEVEL SECURITY;
ALTER TABLE sm_core.catalog_security_reset REPLICA IDENTITY FULL;
ALTER TABLE sm_core.catalog_security_reset REPLICA IDENTITY NOTHING;
ALTER TABLE sm_core.catalog_security_reset REPLICA IDENTITY DEFAULT;
