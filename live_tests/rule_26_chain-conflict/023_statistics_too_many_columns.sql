-- PostgreSQL rejects CREATE STATISTICS with more than STATS_MAX_DIMENSIONS (8) columns/expressions.
CREATE TABLE sm_core.stats_max_dim_probe (
    c1 integer, c2 integer, c3 integer, c4 integer, c5 integer,
    c6 integer, c7 integer, c8 integer, c9 integer
);
CREATE STATISTICS sm_core.stats_too_many
    ON c1, c2, c3, c4, c5, c6, c7, c8, c9
    FROM sm_core.stats_max_dim_probe;
