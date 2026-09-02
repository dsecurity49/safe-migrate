-- PostgreSQL 16+ tracks dependent role grants by their membership grantor.
GRANT sm_option_parent TO sm_inherit_member WITH ADMIN TRUE;
GRANT sm_option_parent TO sm_inherit_member GRANTED BY sm_option_member;
REVOKE sm_option_parent FROM sm_option_member CASCADE;
