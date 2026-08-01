ALTER TABLE t_large ADD CONSTRAINT temporary_check CHECK (id > 0) NOT VALID;
ALTER TABLE t_large DROP CONSTRAINT temporary_check;
