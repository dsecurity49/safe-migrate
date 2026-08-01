ALTER TABLE child_table
    ADD CONSTRAINT child_table_missing_column_fk
    FOREIGN KEY (missing_parent_id) REFERENCES test_table(id)
    NOT VALID;
