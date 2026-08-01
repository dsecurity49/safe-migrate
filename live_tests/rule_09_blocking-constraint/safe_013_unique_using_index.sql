ALTER TABLE t_large
    ADD CONSTRAINT t_large_col1_prebuilt_key
    UNIQUE USING INDEX t_large_col1_prebuilt_key;
