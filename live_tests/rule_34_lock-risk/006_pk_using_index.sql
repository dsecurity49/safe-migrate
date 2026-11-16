CREATE TABLE public.lock_pk (id integer);
CREATE UNIQUE INDEX lock_pk_id_key ON public.lock_pk (id);
ALTER TABLE public.lock_pk
    ADD CONSTRAINT lock_pk_id_key PRIMARY KEY USING INDEX lock_pk_id_key;
