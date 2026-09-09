SELECT id, name AS copied_name
INTO UNLOGGED TABLE sm_core.catalog_select_into
FROM sm_core.t;
