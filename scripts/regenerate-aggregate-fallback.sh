#!/usr/bin/env bash
# Regenerate the offline built-in aggregate fallback from a live PostgreSQL server.
#
# Usage:  DATABASE_URL=postgres://... scripts/regenerate-aggregate-fallback.sh
#
# Every aggregate records its `pg_aggregate.aggkind` and direct-argument count,
# so ordered-set and hypothetical calls can be matched against the same input
# list PostgreSQL uses. A polymorphic parameter becomes `*`. The generated file
# is committed, so review the diff when the supported PostgreSQL range changes.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "DATABASE_URL must point at the PostgreSQL server to snapshot." >&2
  exit 1
fi

server_version="$(psql "$DATABASE_URL" -X -A -t -c 'SHOW server_version;')"
rows="$(psql "$DATABASE_URL" -X -A -t -F '|' -c "
  SELECT p.proname,
         g.aggkind,
         CASE WHEN g.aggkind = 'n' THEN p.pronargs::int
              ELSE g.aggnumdirectargs::int END,
         COALESCE(string_agg(
             CASE WHEN t.typcategory = 'P' THEN '*'
                  ELSE pg_catalog.format_type(a.argtype, NULL) END,
             ',' ORDER BY a.ord), '')
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
  JOIN pg_catalog.pg_aggregate g ON g.aggfnoid = p.oid
  LEFT JOIN LATERAL unnest(p.proargtypes) WITH ORDINALITY AS a(argtype, ord) ON true
  LEFT JOIN pg_catalog.pg_type t ON t.oid = a.argtype
  WHERE n.nspname = 'pg_catalog'
  GROUP BY p.oid, p.proname, g.aggkind, g.aggnumdirectargs, p.pronargs
  ORDER BY p.oid, 4;")"
entry_count="$(printf '%s\n' "$rows" | grep -c . || true)"

{
  cat <<HEADER
//! Offline fallback for the built-in aggregate signatures.
//!
//! GENERATED FILE — do not edit. Regenerate with
//! \`scripts/regenerate-aggregate-fallback.sh\`.
//!
//! Snapshot of PostgreSQL ${server_version} (${entry_count} signatures), used only on
//! the \`--no-cache\` path. A synced baseline supersedes it.

use super::aggregate::{AggregateArg, AggregateCatalogue, AggregateKind, AggregateSignature};

/// \`(name, kind, direct arguments, all parameters)\`; \`*\` marks a polymorphic
/// parameter.
const SIGNATURES: &[(&str, AggregateKind, usize, &[&str])] = &[
HEADER

  while IFS='|' read -r name kind direct args; do
    [ -n "$name" ] || continue
    case "$kind" in
      n) kind_name=AggregateKind::Normal ;;
      o) kind_name=AggregateKind::OrderedSet ;;
      h) kind_name=AggregateKind::Hypothetical ;;
      *) echo "unknown aggkind '$kind' for $name" >&2; exit 1 ;;
    esac
    if [ -z "$args" ]; then
      printf '    ("%s", %s, %s, &[]),\n' "$name" "$kind_name" "$direct"
      continue
    fi
    IFS=',' read -ra parts <<<"$args"
    printf '    ("%s", %s, %s, &[' "$name" "$kind_name" "$direct"
    for part in "${parts[@]}"; do
      printf '"%s", ' "$part"
    done
    printf ']),\n'
  done <<<"$rows"

  cat <<'FOOTER'
];

pub(crate) fn catalogue() -> AggregateCatalogue {
    AggregateCatalogue::new(
        SIGNATURES
            .iter()
            .map(|(name, kind, direct_count, parameters)| {
                let arguments = parameters
                    .iter()
                    .map(|parameter| {
                        if *parameter == "*" {
                            AggregateArg::Any
                        } else {
                            AggregateArg::Type((*parameter).to_string())
                        }
                    })
                    .collect();
                (
                    (*name).to_string(),
                    AggregateSignature::new(*kind, *direct_count, arguments),
                )
            })
            .collect(),
    )
}
FOOTER
} >src/_internal/model/aggregate_fallback.rs

echo "regenerated from PostgreSQL ${server_version}: ${entry_count} signatures"
