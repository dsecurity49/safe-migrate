SET SESSION AUTHORIZATION sm_set_member;
SET ROLE sm_set_target;
CREATE TABLE sm_core.transitive_role_owned (id integer);
RESET ROLE;
SET SESSION AUTHORIZATION DEFAULT;
