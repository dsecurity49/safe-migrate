CREATE TABLE parent (a character varying(32), b integer) PARTITION BY RANGE (a, b);
CREATE TABLE child PARTITION OF parent FOR VALUES FROM ('a', 0) TO ('m', 10);
ALTER TABLE parent DETACH PARTITION child CONCURRENTLY;