CREATE TABLE reindex_test (id int);
CREATE INDEX reindex_test_idx ON reindex_test(id);
REINDEX TABLE reindex_test;
REINDEX INDEX reindex_test_idx;
REINDEX (CONCURRENTLY) TABLE reindex_test;
REINDEX TABLE CONCURRENTLY reindex_test;
