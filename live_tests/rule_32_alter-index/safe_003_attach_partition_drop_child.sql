CREATE TABLE parent_tbl (a int) PARTITION BY RANGE (a);
CREATE TABLE child_tbl (a int);
CREATE INDEX child_idx ON child_tbl (a);
CREATE INDEX parent_idx ON parent_tbl (a);
ALTER TABLE parent_tbl ATTACH PARTITION child_tbl FOR VALUES FROM (0) TO (10);
ALTER INDEX parent_idx ATTACH PARTITION child_idx;
DROP INDEX parent_idx;
DROP INDEX child_idx;
