CREATE TABLE new_ctas_tbl AS SELECT * FROM (SELECT id, name FROM test_table) sub;
