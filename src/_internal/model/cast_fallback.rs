//! Offline fallback for the implicit-cast catalogue.
//!
//! GENERATED FILE — do not edit. Regenerate with
//! `scripts/regenerate-cast-fallback.sh`.
//!
//! Snapshot of PostgreSQL 18.6 (117 casts), used only on
//! the `--no-cache` path. A synced baseline supersedes it.

use super::cast::CastCatalogue;

/// `(source, target)`, each a `format_type` spelling.
const EDGES: &[(&str, &str)] = &[
    ("\"char\"", "text"),
    ("bigint", "double precision"),
    ("bigint", "numeric"),
    ("bigint", "oid"),
    ("bigint", "real"),
    ("bigint", "regclass"),
    ("bigint", "regcollation"),
    ("bigint", "regconfig"),
    ("bigint", "regdictionary"),
    ("bigint", "regnamespace"),
    ("bigint", "regoper"),
    ("bigint", "regoperator"),
    ("bigint", "regproc"),
    ("bigint", "regprocedure"),
    ("bigint", "regrole"),
    ("bigint", "regtype"),
    ("bit", "bit"),
    ("bit", "bit varying"),
    ("bit varying", "bit"),
    ("bit varying", "bit varying"),
    ("character", "character"),
    ("character", "character varying"),
    ("character", "name"),
    ("character", "text"),
    ("character varying", "character"),
    ("character varying", "character varying"),
    ("character varying", "name"),
    ("character varying", "regclass"),
    ("character varying", "text"),
    ("cidr", "inet"),
    ("date", "timestamp with time zone"),
    ("date", "timestamp without time zone"),
    ("integer", "bigint"),
    ("integer", "double precision"),
    ("integer", "numeric"),
    ("integer", "oid"),
    ("integer", "real"),
    ("integer", "regclass"),
    ("integer", "regcollation"),
    ("integer", "regconfig"),
    ("integer", "regdictionary"),
    ("integer", "regnamespace"),
    ("integer", "regoper"),
    ("integer", "regoperator"),
    ("integer", "regproc"),
    ("integer", "regprocedure"),
    ("integer", "regrole"),
    ("integer", "regtype"),
    ("interval", "interval"),
    ("macaddr", "macaddr8"),
    ("macaddr8", "macaddr"),
    ("name", "text"),
    ("numeric", "double precision"),
    ("numeric", "numeric"),
    ("numeric", "real"),
    ("oid", "regclass"),
    ("oid", "regcollation"),
    ("oid", "regconfig"),
    ("oid", "regdictionary"),
    ("oid", "regnamespace"),
    ("oid", "regoper"),
    ("oid", "regoperator"),
    ("oid", "regproc"),
    ("oid", "regprocedure"),
    ("oid", "regrole"),
    ("oid", "regtype"),
    ("pg_dependencies", "bytea"),
    ("pg_dependencies", "text"),
    ("pg_mcv_list", "bytea"),
    ("pg_mcv_list", "text"),
    ("pg_ndistinct", "bytea"),
    ("pg_ndistinct", "text"),
    ("pg_node_tree", "text"),
    ("real", "double precision"),
    ("regclass", "oid"),
    ("regcollation", "oid"),
    ("regconfig", "oid"),
    ("regdictionary", "oid"),
    ("regnamespace", "oid"),
    ("regoper", "oid"),
    ("regoper", "regoperator"),
    ("regoperator", "oid"),
    ("regoperator", "regoper"),
    ("regproc", "oid"),
    ("regproc", "regprocedure"),
    ("regprocedure", "oid"),
    ("regprocedure", "regproc"),
    ("regrole", "oid"),
    ("regtype", "oid"),
    ("smallint", "bigint"),
    ("smallint", "double precision"),
    ("smallint", "integer"),
    ("smallint", "numeric"),
    ("smallint", "oid"),
    ("smallint", "real"),
    ("smallint", "regclass"),
    ("smallint", "regcollation"),
    ("smallint", "regconfig"),
    ("smallint", "regdictionary"),
    ("smallint", "regnamespace"),
    ("smallint", "regoper"),
    ("smallint", "regoperator"),
    ("smallint", "regproc"),
    ("smallint", "regprocedure"),
    ("smallint", "regrole"),
    ("smallint", "regtype"),
    ("text", "character"),
    ("text", "character varying"),
    ("text", "name"),
    ("text", "regclass"),
    ("time with time zone", "time with time zone"),
    ("time without time zone", "interval"),
    ("time without time zone", "time with time zone"),
    ("time without time zone", "time without time zone"),
    ("timestamp with time zone", "timestamp with time zone"),
    ("timestamp without time zone", "timestamp with time zone"),
    ("timestamp without time zone", "timestamp without time zone"),
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
