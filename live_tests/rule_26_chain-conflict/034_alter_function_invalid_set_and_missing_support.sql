SET lock_timeout = '2s';
SET statement_timeout = '5s';
ALTER FUNCTION sm_core.f(integer) SET statement_timeout = 'abc';
