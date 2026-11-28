-- PostgreSQL rejects CREATE STATISTICS on a column whose type lacks a default btree operator class.
CREATE TABLE sm_core.stats_point_probe (pt point, id integer);
CREATE STATISTICS sm_core.stats_on_point ON pt, id FROM sm_core.stats_point_probe;
