CREATE TYPE sm_core.release_stage_probe AS ENUM ('planned', 'ready', 'shipped');
ALTER TYPE sm_core.release_stage_probe RENAME VALUE 'ready' TO 'approved';
