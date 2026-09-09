CREATE UNLOGGED SEQUENCE sm_core.catalog_sequence
    AS integer
    INCREMENT BY -3
    MINVALUE -99
    MAXVALUE -3
    START WITH -3
    CACHE 7
    CYCLE;
ALTER SEQUENCE sm_core.catalog_sequence RESTART WITH -12;
