CREATE TABLE sm_core.batch1_invalid_strategy (id integer)
    PARTITION BY imaginary (id);
