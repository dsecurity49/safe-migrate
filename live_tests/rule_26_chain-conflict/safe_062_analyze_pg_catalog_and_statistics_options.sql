SET lock_timeout = '2s';
SET statement_timeout = '5s';
ANALYZE pg_class;
ANALYZE pg_catalog.pg_class;
ANALYZE (VERBOSE, SKIP_LOCKED true, BUFFER_USAGE_LIMIT '256kB') sm_core.t (id);
ALTER STATISTICS sm_core.catalog_like_source_stats OWNER TO app_user;
ALTER STATISTICS sm_core.catalog_like_source_stats SET STATISTICS 20000;
