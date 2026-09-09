CREATE TABLE sm_core.catalog_hash_parent (id integer PRIMARY KEY) PARTITION BY HASH (id);
CREATE TRIGGER catalog_hash_trigger BEFORE INSERT ON sm_core.catalog_hash_parent
    FOR EACH ROW EXECUTE FUNCTION sm_core.f();
CREATE TABLE sm_core.catalog_hash_child PARTITION OF sm_core.catalog_hash_parent
    FOR VALUES WITH (MODULUS 2, REMAINDER 0);
ALTER TABLE sm_core.catalog_hash_parent DETACH PARTITION sm_core.catalog_hash_child CONCURRENTLY;
