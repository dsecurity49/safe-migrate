ALTER TABLE t_large ADD CONSTRAINT t_large_id_positive CHECK (id > 0) NOT VALID;
