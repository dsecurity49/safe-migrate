-- PostgreSQL rejects CREATE STATISTICS when an expression references a nonexistent column.
CREATE TABLE sm_core.stats_expr_missing_probe (a integer, b integer);
CREATE STATISTICS sm_core.stats_missing_expr
    ON ((missing_col + 1)), a
    FROM sm_core.stats_expr_missing_probe;
