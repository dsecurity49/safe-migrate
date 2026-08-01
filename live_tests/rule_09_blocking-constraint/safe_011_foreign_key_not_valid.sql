ALTER TABLE child_table
    ADD CONSTRAINT child_table_test_table_not_valid_fk
    FOREIGN KEY (test_table_id) REFERENCES test_table(id)
    NOT VALID;
