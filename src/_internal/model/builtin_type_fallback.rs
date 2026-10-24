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

/// `(typname, canonical, category, preferred, fixed_bits, accepts_typmod)`.
#[allow(clippy::type_complexity)]
const TYPES: &[(&str, &str, TypeCategory, bool, Option<i32>, bool)] = &[
    (
        "aclitem",
        "aclitem",
        TypeCategory::User,
        false,
        Some(128),
        false,
    ),
    ("bit", "bit", TypeCategory::BitString, false, None, false),
    (
        "bool",
        "boolean",
        TypeCategory::Boolean,
        true,
        Some(8),
        false,
    ),
    (
        "box",
        "box",
        TypeCategory::Geometric,
        false,
        Some(256),
        false,
    ),
    (
        "bpchar",
        "character",
        TypeCategory::String,
        false,
        None,
        false,
    ),
    ("bytea", "bytea", TypeCategory::User, false, None, false),
    (
        "char",
        "\"char\"",
        TypeCategory::Internal,
        false,
        Some(8),
        false,
    ),
    ("cid", "cid", TypeCategory::User, false, Some(32), false),
    ("cidr", "cidr", TypeCategory::Network, false, None, false),
    (
        "circle",
        "circle",
        TypeCategory::Geometric,
        false,
        Some(192),
        false,
    ),
    (
        "date",
        "date",
        TypeCategory::DateTime,
        false,
        Some(32),
        false,
    ),
    (
        "datemultirange",
        "datemultirange",
        TypeCategory::Range,
        false,
        None,
        false,
    ),
    (
        "daterange",
        "daterange",
        TypeCategory::Range,
        false,
        None,
        false,
    ),
    (
        "float4",
        "real",
        TypeCategory::Numeric,
        false,
        Some(32),
        false,
    ),
    (
        "float8",
        "double precision",
        TypeCategory::Numeric,
        true,
        Some(64),
        false,
    ),
    (
        "gtsvector",
        "gtsvector",
        TypeCategory::User,
        false,
        None,
        false,
    ),
    ("inet", "inet", TypeCategory::Network, true, None, false),
    (
        "int2",
        "smallint",
        TypeCategory::Numeric,
        false,
        Some(16),
        false,
    ),
    (
        "int4",
        "integer",
        TypeCategory::Numeric,
        false,
        Some(32),
        false,
    ),
    (
        "int4multirange",
        "int4multirange",
        TypeCategory::Range,
        false,
        None,
        false,
    ),
    (
        "int4range",
        "int4range",
        TypeCategory::Range,
        false,
        None,
        false,
    ),
    (
        "int8",
        "bigint",
        TypeCategory::Numeric,
        false,
        Some(64),
        false,
    ),
    (
        "int8multirange",
        "int8multirange",
        TypeCategory::Range,
        false,
        None,
        false,
    ),
    (
        "int8range",
        "int8range",
        TypeCategory::Range,
        false,
        None,
        false,
    ),
    (
        "interval",
        "interval",
        TypeCategory::Timespan,
        true,
        Some(128),
        false,
    ),
    ("json", "json", TypeCategory::User, false, None, false),
    ("jsonb", "jsonb", TypeCategory::User, false, None, false),
    (
        "jsonpath",
        "jsonpath",
        TypeCategory::User,
        false,
        None,
        false,
    ),
    (
        "line",
        "line",
        TypeCategory::Geometric,
        false,
        Some(192),
        false,
    ),
    (
        "lseg",
        "lseg",
        TypeCategory::Geometric,
        false,
        Some(256),
        false,
    ),
    (
        "macaddr",
        "macaddr",
        TypeCategory::User,
        false,
        Some(48),
        false,
    ),
    (
        "macaddr8",
        "macaddr8",
        TypeCategory::User,
        false,
        Some(64),
        false,
    ),
    (
        "money",
        "money",
        TypeCategory::Numeric,
        false,
        Some(64),
        false,
    ),
    (
        "name",
        "name",
        TypeCategory::String,
        false,
        Some(512),
        false,
    ),
    (
        "numeric",
        "numeric",
        TypeCategory::Numeric,
        false,
        None,
        false,
    ),
    (
        "nummultirange",
        "nummultirange",
        TypeCategory::Range,
        false,
        None,
        false,
    ),
    (
        "numrange",
        "numrange",
        TypeCategory::Range,
        false,
        None,
        false,
    ),
    ("oid", "oid", TypeCategory::Numeric, true, Some(32), false),
    ("path", "path", TypeCategory::Geometric, false, None, false),
    (
        "pg_brin_bloom_summary",
        "pg_brin_bloom_summary",
        TypeCategory::Internal,
        false,
        None,
        false,
    ),
    (
        "pg_brin_minmax_multi_summary",
        "pg_brin_minmax_multi_summary",
        TypeCategory::Internal,
        false,
        None,
        false,
    ),
    (
        "pg_dependencies",
        "pg_dependencies",
        TypeCategory::Internal,
        false,
        None,
        false,
    ),
    (
        "pg_lsn",
        "pg_lsn",
        TypeCategory::User,
        false,
        Some(64),
        false,
    ),
    (
        "pg_mcv_list",
        "pg_mcv_list",
        TypeCategory::Internal,
        false,
        None,
        false,
    ),
    (
        "pg_ndistinct",
        "pg_ndistinct",
        TypeCategory::Internal,
        false,
        None,
        false,
    ),
    (
        "pg_node_tree",
        "pg_node_tree",
        TypeCategory::Internal,
        false,
        None,
        false,
    ),
    (
        "pg_snapshot",
        "pg_snapshot",
        TypeCategory::User,
        false,
        None,
        false,
    ),
    (
        "point",
        "point",
        TypeCategory::Geometric,
        false,
        Some(128),
        false,
    ),
    (
        "polygon",
        "polygon",
        TypeCategory::Geometric,
        false,
        None,
        false,
    ),
    (
        "refcursor",
        "refcursor",
        TypeCategory::User,
        false,
        None,
        false,
    ),
    (
        "regclass",
        "regclass",
        TypeCategory::Numeric,
        false,
        Some(32),
        false,
    ),
    (
        "regcollation",
        "regcollation",
        TypeCategory::Numeric,
        false,
        Some(32),
        false,
    ),
    (
        "regconfig",
        "regconfig",
        TypeCategory::Numeric,
        false,
        Some(32),
        false,
    ),
    (
        "regdictionary",
        "regdictionary",
        TypeCategory::Numeric,
        false,
        Some(32),
        false,
    ),
    (
        "regnamespace",
        "regnamespace",
        TypeCategory::Numeric,
        false,
        Some(32),
        false,
    ),
    (
        "regoper",
        "regoper",
        TypeCategory::Numeric,
        false,
        Some(32),
        false,
    ),
    (
        "regoperator",
        "regoperator",
        TypeCategory::Numeric,
        false,
        Some(32),
        false,
    ),
    (
        "regproc",
        "regproc",
        TypeCategory::Numeric,
        false,
        Some(32),
        false,
    ),
    (
        "regprocedure",
        "regprocedure",
        TypeCategory::Numeric,
        false,
        Some(32),
        false,
    ),
    (
        "regrole",
        "regrole",
        TypeCategory::Numeric,
        false,
        Some(32),
        false,
    ),
    (
        "regtype",
        "regtype",
        TypeCategory::Numeric,
        false,
        Some(32),
        false,
    ),
    ("text", "text", TypeCategory::String, true, None, false),
    ("tid", "tid", TypeCategory::User, false, Some(48), false),
    (
        "time",
        "time without time zone",
        TypeCategory::DateTime,
        false,
        Some(64),
        false,
    ),
    (
        "timestamp",
        "timestamp without time zone",
        TypeCategory::DateTime,
        false,
        Some(64),
        false,
    ),
    (
        "timestamptz",
        "timestamp with time zone",
        TypeCategory::DateTime,
        true,
        Some(64),
        false,
    ),
    (
        "timetz",
        "time with time zone",
        TypeCategory::DateTime,
        false,
        Some(96),
        false,
    ),
    (
        "tsmultirange",
        "tsmultirange",
        TypeCategory::Range,
        false,
        None,
        false,
    ),
    ("tsquery", "tsquery", TypeCategory::User, false, None, false),
    (
        "tsrange",
        "tsrange",
        TypeCategory::Range,
        false,
        None,
        false,
    ),
    (
        "tstzmultirange",
        "tstzmultirange",
        TypeCategory::Range,
        false,
        None,
        false,
    ),
    (
        "tstzrange",
        "tstzrange",
        TypeCategory::Range,
        false,
        None,
        false,
    ),
    (
        "tsvector",
        "tsvector",
        TypeCategory::User,
        false,
        None,
        false,
    ),
    (
        "txid_snapshot",
        "txid_snapshot",
        TypeCategory::User,
        false,
        None,
        false,
    ),
    ("uuid", "uuid", TypeCategory::User, false, Some(128), false),
    (
        "varbit",
        "bit varying",
        TypeCategory::BitString,
        true,
        None,
        false,
    ),
    (
        "varchar",
        "character varying",
        TypeCategory::String,
        false,
        None,
        false,
    ),
    ("xid", "xid", TypeCategory::User, false, Some(32), false),
    ("xid8", "xid8", TypeCategory::User, false, Some(64), false),
    ("xml", "xml", TypeCategory::User, false, None, false),
];

pub(crate) fn catalogue() -> BuiltinTypeCatalogue {
    BuiltinTypeCatalogue::new(
        TYPES
            .iter()
            .map(
                |(typname, canonical, category, preferred, fixed_bits, accepts_typmod)| {
                    BuiltinType {
                        oid: None,
                        typname: (*typname).to_string(),
                        canonical: (*canonical).to_string(),
                        category: *category,
                        preferred: *preferred,
                        fixed_bits: *fixed_bits,
                        array_oid: None,
                        accepts_typmod: *accepts_typmod,
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
                TYPES.iter().any(|(name, ..)| *name == typname),
                "{typname} must survive into the fallback snapshot"
            );
        }
    }
}
