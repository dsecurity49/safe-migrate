#!/usr/bin/env bash
# Regenerate src/_internal/model/builtin_routine.rs from a live PostgreSQL server.
#
# Usage: DATABASE_URL=postgres://... scripts/regenerate-builtin-routine-fallback.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "DATABASE_URL must point at the PostgreSQL server to snapshot." >&2
  exit 1
fi

psql "$DATABASE_URL" -X -A -t -c "
  SELECT DISTINCT p.proname
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'pg_catalog'
  ORDER BY 1;" >/dev/null

echo "Verified pg_catalog routine snapshot query against $DATABASE_URL"
