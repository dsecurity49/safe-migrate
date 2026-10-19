#!/usr/bin/env bash
# Regenerate the offline implicit-cast fallback from a live PostgreSQL server.
#
# Usage:  DATABASE_URL=postgres://... scripts/regenerate-cast-fallback.sh
#
# The generated file is committed; re-run when the supported PostgreSQL range
# changes and review the diff.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "DATABASE_URL must point at the PostgreSQL server to snapshot." >&2
  exit 1
fi

server_version="$(psql "$DATABASE_URL" -X -A -t -c 'SHOW server_version;')"
entry_count="$(psql "$DATABASE_URL" -X -A -t -c "
  SELECT count(*)
  FROM pg_catalog.pg_cast c
  JOIN pg_catalog.pg_type s ON s.oid = c.castsource
  JOIN pg_catalog.pg_namespace sn ON sn.oid = s.typnamespace
  JOIN pg_catalog.pg_type t ON t.oid = c.casttarget
  JOIN pg_catalog.pg_namespace tn ON tn.oid = t.typnamespace
  WHERE c.castcontext = 'i'
    AND sn.nspname = 'pg_catalog' AND tn.nspname = 'pg_catalog';")"

{
  cat <<HEADER
//! Offline fallback for the implicit-cast catalogue.
//!
//! GENERATED FILE — do not edit. Regenerate with
//! \`scripts/regenerate-cast-fallback.sh\`.
//!
//! Snapshot of PostgreSQL ${server_version} (${entry_count} casts), used only on
//! the \`--no-cache\` path. A synced baseline supersedes it.

use super::cast::CastCatalogue;

/// \`(source, target)\`, each a \`format_type\` spelling.
const EDGES: &[(&str, &str)] = &[
HEADER

  # Pin the path at the connection level so `format_type` does not schema-
  # qualify, without emitting a command tag into the output.
  PGOPTIONS='-c search_path=pg_catalog' psql "$DATABASE_URL" -X -A -t -F'|' -c "
    SELECT pg_catalog.format_type(c.castsource, NULL),
           pg_catalog.format_type(c.casttarget, NULL)
    FROM pg_catalog.pg_cast c
    JOIN pg_catalog.pg_type s ON s.oid = c.castsource
    JOIN pg_catalog.pg_namespace sn ON sn.oid = s.typnamespace
    JOIN pg_catalog.pg_type t ON t.oid = c.casttarget
    JOIN pg_catalog.pg_namespace tn ON tn.oid = t.typnamespace
    WHERE c.castcontext = 'i'
      AND sn.nspname = 'pg_catalog' AND tn.nspname = 'pg_catalog'
    ORDER BY 1, 2;" |
    python3 -c '
import sys


def rust_string(value: str) -> str:
    return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""


for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    source, target = line.split("|")
    print(f"    ({rust_string(source)}, {rust_string(target)}),")
'

  cat <<'FOOTER'
];

pub(crate) fn catalogue() -> CastCatalogue {
    CastCatalogue::new(
        EDGES
            .iter()
            .map(|(source, target)| ((*source).to_string(), (*target).to_string())),
    )
}

#[cfg(test)]
mod tests {
    use super::EDGES;
    use crate::_internal::model::cast::CastCatalogue;

    #[test]
    fn the_snapshot_is_sorted_and_free_of_duplicates() {
        assert!(!EDGES.is_empty(), "the fallback must not be empty");
        assert!(
            EDGES.windows(2).all(|pair| pair[0] < pair[1]),
            "entries must be sorted and unique by (source, target)"
        );
    }

    #[test]
    fn a_widening_cast_is_present_and_a_narrowing_one_is_absent() {
        let catalogue = CastCatalogue::fallback();
        assert!(catalogue.coerces_implicitly("integer", "bigint"));
        assert!(!catalogue.coerces_implicitly("bigint", "integer"));
    }
}
FOOTER
} > src/_internal/model/cast_fallback.rs

cargo fmt
echo "regenerated from PostgreSQL ${server_version}: ${entry_count} casts"
