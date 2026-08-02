BEGIN;
SET LOCAL ROLE app_user;
CREATE TABLE app_user.local_role_owned (id integer);
COMMIT;

CREATE TABLE sm_core.after_local_role (id integer);

BEGIN;
SET ROLE app_user;
CREATE TABLE app_user.persistent_role_inside (id integer);
COMMIT;
CREATE TABLE app_user.persistent_role_after_commit (id integer);
RESET ROLE;
