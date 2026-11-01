#!/usr/bin/env bash
# Regenerate the offline built-in type fallback from a live PostgreSQL server.
#
# The fallback exists only for `--no-cache`, where no server supplied a
# catalogue. It is deliberately a subset: it carries names and derived
# attributes, never OIDs, and any type it does not cover stays unresolved
# rather than being guessed at.
#
# Usage:  DATABASE_URL=postgres://... scripts/regenerate-builtin-type-fallback.sh
#
# The generated file is committed. Re-run this whenever the supported range of
# PostgreSQL versions changes, and review the diff: a new type appearing here
# means the server gained it, not that the analyzer learned new semantics.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "DATABASE_URL must point at the PostgreSQL server to snapshot." >&2
  exit 1
fi

server_version="$(psql "$DATABASE_URL" -X -A -t -c 'SHOW server_version;')"
entry_count="$(psql "$DATABASE_URL" -X -A -t -c "
  SELECT count(*) FROM pg_catalog.pg_type t
  JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
  WHERE n.nspname = 'pg_catalog' AND t.typtype IN ('b','r','m') AND t.typcategory <> 'A';")"

{
  cat <<HEADER
//! Offline fallback for the built-in type catalogue.
//!
//! GENERATED FILE — do not edit. Regenerate with
//! \`scripts/regenerate-builtin-type-fallback.sh\`.
//!
//! Snapshot of PostgreSQL ${server_version} (${entry_count} types). This is the
//! \`--no-cache\` path only: it is a subset of one server's catalog, carries no
//! OIDs, and resolves nothing it does not cover. A synced baseline always
//! supersedes it.

use super::builtin_type::{BuiltinType, BuiltinTypeCatalogue, TypeCategory};

/// \`(typname, canonical, category, preferred, fixed_bits, accepts_typmod, collatable)\`.
#[allow(clippy::type_complexity)]
const TYPES: &[(&str, &str, TypeCategory, bool, Option<i32>, bool, bool)] = &[
HEADER

  # Pin the path at the connection level so `format_type` does not schema-
  # qualify, without emitting a command tag into the output.
  PGOPTIONS='-c search_path=pg_catalog' psql "$DATABASE_URL" -X -A -t -F'|' -c "
    SELECT
      t.typname,
      pg_catalog.format_type(t.oid, NULL),
      t.typcategory::text,
      t.typispreferred::text,
      CASE WHEN t.typlen > 0 THEN (t.typlen * 8)::text ELSE '' END,
      (t.typmodout <> 0)::text,
      (t.typcollation <> 0)::text
    FROM pg_catalog.pg_type t
    JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname = 'pg_catalog' AND t.typtype IN ('b','r','m') AND t.typcategory <> 'A'
    ORDER BY t.typname;" |
    python3 -c '
import sys

CATEGORY = {
    "A": "Array", "B": "Boolean", "C": "Composite", "D": "DateTime",
    "E": "Enum", "G": "Geometric", "I": "Network", "N": "Numeric",
    "P": "Pseudo", "R": "Range", "S": "String", "T": "Timespan",
    "U": "User", "V": "BitString", "Z": "Internal",
}


def rust_string(value: str) -> str:
    return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""


for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    typname, canonical, category, preferred, typlen, typmod, collatable = line.split("|")
    preferred = "true" if preferred in ("t", "true") else "false"
    fixed = "None" if not typlen else f"Some({typlen})"
    typmod = "true" if typmod in ("t", "true") else "false"
    collatable = "true" if collatable in ("t", "true") else "false"
    print(
        f"    ({rust_string(typname)}, {rust_string(canonical)}, "
        f"TypeCategory::{CATEGORY.get(category, chr(85)+chr(110)+chr(107)+chr(110)+chr(111)+chr(119)+chr(110))}, "
        f"{preferred}, {fixed}, {typmod}, {collatable}),"
    )
'

  cat <<'FOOTER'
];

pub(crate) fn catalogue() -> BuiltinTypeCatalogue {
    BuiltinTypeCatalogue::new(
        TYPES
            .iter()
            .map(
                |(typname, canonical, category, preferred, fixed_bits, accepts_typmod, collatable)| {
                    BuiltinType {
                        oid: None,
                        typname: (*typname).to_string(),
                        canonical: (*canonical).to_string(),
                        category: *category,
                        preferred: *preferred,
                        fixed_bits: *fixed_bits,
                        array_oid: None,
                        accepts_typmod: *accepts_typmod,
                        collatable: *collatable,
                    }
                },
            )
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::TYPES;
    use crate::_internal::model::builtin_type::BuiltinTypeCatalogue;

    #[test]
    fn the_snapshot_is_sorted_and_free_of_duplicates() {
        assert!(!TYPES.is_empty(), "the fallback must not be empty");
        assert!(
            TYPES.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "entries must be sorted and unique by typname"
        );
    }

    #[test]
    fn every_snapshot_spelling_resolves_back_to_its_type() {
        let catalogue = BuiltinTypeCatalogue::fallback();
        for entry in catalogue.types() {
            for spelling in catalogue.spellings(entry) {
                let resolved = catalogue
                    .resolve(spelling)
                    .unwrap_or_else(|| panic!("{spelling} did not resolve"));
                assert_eq!(
                    resolved.typname, entry.typname,
                    "{spelling} resolved to the wrong type"
                );
            }
        }
    }

    #[test]
    fn the_snapshot_records_collatability_and_typmod_support() {
        let text = TYPES
            .iter()
            .find(|entry| entry.0 == "text")
            .expect("text must be present");
        assert!(text.6, "text carries a collation");
        let varchar = TYPES
            .iter()
            .find(|entry| entry.0 == "varchar")
            .expect("varchar must be present");
        assert!(varchar.5, "varchar accepts a typmod");
        assert!(varchar.6, "varchar carries a collation");
        let int4 = TYPES
            .iter()
            .find(|entry| entry.0 == "int4")
            .expect("int4 must be present");
        assert!(!int4.6, "int4 is not collatable");
    }

    #[test]
    fn the_snapshot_covers_the_types_identity_depends_on() {
        for typname in [
            "int2", "int4", "int8", "float4", "float8", "numeric", "bpchar",
            "varchar", "text", "bit", "varbit", "time", "timetz", "timestamp",
            "timestamptz", "interval", "bool", "bytea", "json", "uuid",
        ] {
            assert!(
                TYPES.iter().any(|(name, ..)| *name == typname),
                "{typname} must survive into the fallback snapshot"
            );
        }
    }
}
FOOTER
} > src/_internal/model/builtin_type_fallback.rs

cargo fmt
echo "regenerated from PostgreSQL ${server_version}: ${entry_count} types"
