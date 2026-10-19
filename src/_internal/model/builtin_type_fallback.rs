//! Offline fallback for the built-in type catalogue.
//!
//! GENERATED FILE — do not edit. Regenerate with
//! `scripts/regenerate-builtin-type-fallback.sh`.
//!
//! Snapshot of PostgreSQL 18.6 (80 types). This is the
//! `--no-cache` path only: it is a subset of one server's catalog, carries no
//! OIDs, and resolves nothing it does not cover. A synced baseline always
//! supersedes it.

use super::builtin_type::{BuiltinType, BuiltinTypeCatalogue, TypeCategory};

/// `(typname, canonical, category, fixed_bits, accepts_typmod)`.
const TYPES: &[(&str, &str, TypeCategory, Option<i32>, bool)] = &[
    ("aclitem", "aclitem", TypeCategory::User, Some(128), false),
    ("bit", "bit", TypeCategory::BitString, None, false),
    ("bool", "boolean", TypeCategory::Boolean, Some(8), false),
    ("box", "box", TypeCategory::Geometric, Some(256), false),
    ("bpchar", "character", TypeCategory::String, None, false),
    ("bytea", "bytea", TypeCategory::User, None, false),
    ("char", "\"char\"", TypeCategory::Internal, Some(8), false),
    ("cid", "cid", TypeCategory::User, Some(32), false),
    ("cidr", "cidr", TypeCategory::Network, None, false),
    (
        "circle",
        "circle",
        TypeCategory::Geometric,
        Some(192),
        false,
    ),
    ("date", "date", TypeCategory::DateTime, Some(32), false),
    (
        "datemultirange",
        "datemultirange",
        TypeCategory::Range,
        None,
        false,
    ),
    ("daterange", "daterange", TypeCategory::Range, None, false),
    ("float4", "real", TypeCategory::Numeric, Some(32), false),
    (
        "float8",
        "double precision",
        TypeCategory::Numeric,
        Some(64),
        false,
    ),
    ("gtsvector", "gtsvector", TypeCategory::User, None, false),
    ("inet", "inet", TypeCategory::Network, None, false),
    ("int2", "smallint", TypeCategory::Numeric, Some(16), false),
    ("int4", "integer", TypeCategory::Numeric, Some(32), false),
    (
        "int4multirange",
        "int4multirange",
        TypeCategory::Range,
        None,
        false,
    ),
    ("int4range", "int4range", TypeCategory::Range, None, false),
    ("int8", "bigint", TypeCategory::Numeric, Some(64), false),
    (
        "int8multirange",
        "int8multirange",
        TypeCategory::Range,
        None,
        false,
    ),
    ("int8range", "int8range", TypeCategory::Range, None, false),
    (
        "interval",
        "interval",
        TypeCategory::Timespan,
        Some(128),
        false,
    ),
    ("json", "json", TypeCategory::User, None, false),
    ("jsonb", "jsonb", TypeCategory::User, None, false),
    ("jsonpath", "jsonpath", TypeCategory::User, None, false),
    ("line", "line", TypeCategory::Geometric, Some(192), false),
    ("lseg", "lseg", TypeCategory::Geometric, Some(256), false),
    ("macaddr", "macaddr", TypeCategory::User, Some(48), false),
    ("macaddr8", "macaddr8", TypeCategory::User, Some(64), false),
    ("money", "money", TypeCategory::Numeric, Some(64), false),
    ("name", "name", TypeCategory::String, Some(512), false),
    ("numeric", "numeric", TypeCategory::Numeric, None, false),
    (
        "nummultirange",
        "nummultirange",
        TypeCategory::Range,
        None,
        false,
    ),
    ("numrange", "numrange", TypeCategory::Range, None, false),
    ("oid", "oid", TypeCategory::Numeric, Some(32), false),
    ("path", "path", TypeCategory::Geometric, None, false),
    (
        "pg_brin_bloom_summary",
        "pg_brin_bloom_summary",
        TypeCategory::Internal,
        None,
        false,
    ),
    (
        "pg_brin_minmax_multi_summary",
        "pg_brin_minmax_multi_summary",
        TypeCategory::Internal,
        None,
        false,
    ),
    (
        "pg_dependencies",
        "pg_dependencies",
        TypeCategory::Internal,
        None,
        false,
    ),
    ("pg_lsn", "pg_lsn", TypeCategory::User, Some(64), false),
    (
        "pg_mcv_list",
        "pg_mcv_list",
        TypeCategory::Internal,
        None,
        false,
    ),
    (
        "pg_ndistinct",
        "pg_ndistinct",
        TypeCategory::Internal,
        None,
        false,
    ),
    (
        "pg_node_tree",
        "pg_node_tree",
        TypeCategory::Internal,
        None,
        false,
    ),
    (
        "pg_snapshot",
        "pg_snapshot",
        TypeCategory::User,
        None,
        false,
    ),
    ("point", "point", TypeCategory::Geometric, Some(128), false),
    ("polygon", "polygon", TypeCategory::Geometric, None, false),
    ("refcursor", "refcursor", TypeCategory::User, None, false),
    (
        "regclass",
        "regclass",
        TypeCategory::Numeric,
        Some(32),
        false,
    ),
    (
        "regcollation",
        "regcollation",
        TypeCategory::Numeric,
        Some(32),
        false,
    ),
    (
        "regconfig",
        "regconfig",
        TypeCategory::Numeric,
        Some(32),
        false,
    ),
    (
        "regdictionary",
        "regdictionary",
        TypeCategory::Numeric,
        Some(32),
        false,
    ),
    (
        "regnamespace",
        "regnamespace",
        TypeCategory::Numeric,
        Some(32),
        false,
    ),
    ("regoper", "regoper", TypeCategory::Numeric, Some(32), false),
    (
        "regoperator",
        "regoperator",
        TypeCategory::Numeric,
        Some(32),
        false,
    ),
    ("regproc", "regproc", TypeCategory::Numeric, Some(32), false),
    (
        "regprocedure",
        "regprocedure",
        TypeCategory::Numeric,
        Some(32),
        false,
    ),
    ("regrole", "regrole", TypeCategory::Numeric, Some(32), false),
    ("regtype", "regtype", TypeCategory::Numeric, Some(32), false),
    ("text", "text", TypeCategory::String, None, false),
    ("tid", "tid", TypeCategory::User, Some(48), false),
    (
        "time",
        "time without time zone",
        TypeCategory::DateTime,
        Some(64),
        false,
    ),
    (
        "timestamp",
        "timestamp without time zone",
        TypeCategory::DateTime,
        Some(64),
        false,
    ),
    (
        "timestamptz",
        "timestamp with time zone",
        TypeCategory::DateTime,
        Some(64),
        false,
    ),
    (
        "timetz",
        "time with time zone",
        TypeCategory::DateTime,
        Some(96),
        false,
    ),
    (
        "tsmultirange",
        "tsmultirange",
        TypeCategory::Range,
        None,
        false,
    ),
    ("tsquery", "tsquery", TypeCategory::User, None, false),
    ("tsrange", "tsrange", TypeCategory::Range, None, false),
    (
        "tstzmultirange",
        "tstzmultirange",
        TypeCategory::Range,
        None,
        false,
    ),
    ("tstzrange", "tstzrange", TypeCategory::Range, None, false),
    ("tsvector", "tsvector", TypeCategory::User, None, false),
    (
        "txid_snapshot",
        "txid_snapshot",
        TypeCategory::User,
        None,
        false,
    ),
    ("uuid", "uuid", TypeCategory::User, Some(128), false),
    (
        "varbit",
        "bit varying",
        TypeCategory::BitString,
        None,
        false,
    ),
    (
        "varchar",
        "character varying",
        TypeCategory::String,
        None,
        false,
    ),
    ("xid", "xid", TypeCategory::User, Some(32), false),
    ("xid8", "xid8", TypeCategory::User, Some(64), false),
    ("xml", "xml", TypeCategory::User, None, false),
];

pub(crate) fn catalogue() -> BuiltinTypeCatalogue {
    BuiltinTypeCatalogue::new(
        TYPES
            .iter()
            .map(
                |(typname, canonical, category, fixed_bits, accepts_typmod)| BuiltinType {
                    oid: None,
                    typname: (*typname).to_string(),
                    canonical: (*canonical).to_string(),
                    category: *category,
                    fixed_bits: *fixed_bits,
                    array_oid: None,
                    accepts_typmod: *accepts_typmod,
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
    fn the_snapshot_covers_the_types_identity_depends_on() {
        for typname in [
            "int2",
            "int4",
            "int8",
            "float4",
            "float8",
            "numeric",
            "bpchar",
            "varchar",
            "text",
            "bit",
            "varbit",
            "time",
            "timetz",
            "timestamp",
            "timestamptz",
            "interval",
            "bool",
            "bytea",
            "json",
            "uuid",
        ] {
            assert!(
                TYPES.iter().any(|(name, _, _, _, _)| *name == typname),
                "{typname} must survive into the fallback snapshot"
            );
        }
    }
}
