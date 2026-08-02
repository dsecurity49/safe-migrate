SET SESSION AUTHORIZATION app_user;
CREATE TABLE app_user.session_owned (id integer);
SET SESSION AUTHORIZATION DEFAULT;
CREATE TABLE sm_core.after_session_default (id integer);
