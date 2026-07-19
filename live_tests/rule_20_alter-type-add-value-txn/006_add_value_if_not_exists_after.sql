BEGIN;
ALTER TYPE my_enum ADD VALUE IF NOT EXISTS 'new_val' AFTER 'existing_val';
COMMIT;
