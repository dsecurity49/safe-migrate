ALTER TABLE sm_core.t_large
    ADD CONSTRAINT t_large_col1_not_valid_check CHECK (col1 > 0) NOT VALID;
