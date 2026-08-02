BEGIN;
SET SESSION AUTHORIZATION app_user;
ROLLBACK;
CREATE TABLE sm_core.after_session_rollback (id integer);
