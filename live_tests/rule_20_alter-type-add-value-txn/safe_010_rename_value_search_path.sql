CREATE TYPE public.my_enum AS ENUM ('old', 'public_only');
SET search_path TO public, sm_core;
ALTER TYPE my_enum RENAME VALUE 'old' TO 'public_new';
