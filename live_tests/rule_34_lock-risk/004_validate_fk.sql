ALTER TABLE public.child_table
    ADD CONSTRAINT child_table_test_table_validate_lock_fk
    FOREIGN KEY (test_table_id) REFERENCES public.test_table(id)
    NOT VALID;

ALTER TABLE public.child_table
    VALIDATE CONSTRAINT child_table_test_table_validate_lock_fk;
