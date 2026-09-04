-- Exercise mutation authorization and option changes on role edges
GRANT sm_option_parent TO sm_inherit_member WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
GRANT sm_option_parent TO sm_option_member WITH INHERIT TRUE, SET TRUE;
REVOKE ADMIN OPTION FOR sm_option_parent FROM sm_inherit_member;
REVOKE INHERIT OPTION FOR sm_option_parent FROM sm_option_member;
