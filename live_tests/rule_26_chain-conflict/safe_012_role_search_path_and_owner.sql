SET search_path TO "$user", public;
SET ROLE app_user;
CREATE TABLE role_path_probe (id integer);
GRANT SELECT ON app_user.role_path_probe TO SESSION_USER;
RESET ROLE;
CREATE TABLE sm_core.owner_probe (id integer);
ALTER TABLE sm_core.owner_probe OWNER TO app_user;
