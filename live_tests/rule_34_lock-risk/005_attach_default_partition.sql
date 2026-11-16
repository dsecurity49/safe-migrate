CREATE TABLE public.lock_attach_parent (id integer) PARTITION BY RANGE (id);
CREATE TABLE public.lock_attach_default
    PARTITION OF public.lock_attach_parent DEFAULT;
CREATE TABLE public.lock_attach_child (id integer);
ALTER TABLE public.lock_attach_parent
    ATTACH PARTITION public.lock_attach_child FOR VALUES FROM (10) TO (20);
