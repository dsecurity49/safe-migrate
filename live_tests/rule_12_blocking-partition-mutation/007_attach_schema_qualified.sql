ALTER TABLE public.parent ATTACH PARTITION public.child FOR VALUES IN (1, 2);
