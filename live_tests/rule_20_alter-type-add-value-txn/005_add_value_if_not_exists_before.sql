BEGIN;
ALTER TYPE my_enum ADD VALUE IF NOT EXISTS 'new_val' BEFORE 'existing_val';
COMMIT;
