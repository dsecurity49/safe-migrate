ALTER TABLE t_large
    ADD CONSTRAINT t_large_id_excl
    EXCLUDE USING gist (int4range(id, id, '[]') WITH &&);
