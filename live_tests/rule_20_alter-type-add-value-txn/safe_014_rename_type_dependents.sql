CREATE TYPE sm_core.type_refs_mood AS ENUM ('sad');
CREATE TABLE sm_core.type_refs_entries (status sm_core.type_refs_mood, statuses sm_core.type_refs_mood[]);
CREATE DOMAIN sm_core.type_refs_mood_alias AS sm_core.type_refs_mood;
CREATE FUNCTION sm_core.accepts_type_refs_mood(value sm_core.type_refs_mood) RETURNS sm_core.type_refs_mood LANGUAGE sql AS $$ SELECT value $$;
ALTER TYPE sm_core.type_refs_mood RENAME TO type_refs_emotion;
