-- PostgreSQL records DEPENDENCY_AUTO on extended statistics columns and drops the statistics on DROP COLUMN RESTRICT.
CREATE TABLE sm_core.stats_drop_col_probe (a integer, b integer, c integer);
CREATE STATISTICS sm_core.stats_drop_col_ab ON a, b FROM sm_core.stats_drop_col_probe;
CREATE STATISTICS sm_core.stats_drop_col_expr ON ((b + 1)), c FROM sm_core.stats_drop_col_probe;
ALTER TABLE sm_core.stats_drop_col_probe DROP COLUMN a RESTRICT;
ALTER TABLE sm_core.stats_drop_col_probe DROP COLUMN b RESTRICT;
