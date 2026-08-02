BEGIN;
SET LOCAL SESSION AUTHORIZATION app_user;
CREATE TABLE app_user.local_session_owned (id integer);
COMMIT;
CREATE TABLE sm_core.after_local_session (id integer);
