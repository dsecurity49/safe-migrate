CREATE TABLE new_ctas_tbl AS SELECT category, COUNT(*) AS cnt FROM test_table GROUP BY category;
