ALTER TABLE child_table
    ADD CONSTRAINT child_table_test_table_validate_later_fk
    FOREIGN KEY (test_table_id) REFERENCES test_table(id)
    NOT VALID;

ALTER TABLE child_table
    VALIDATE CONSTRAINT child_table_test_table_validate_later_fk;
