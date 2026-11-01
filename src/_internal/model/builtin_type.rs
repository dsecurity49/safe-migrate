//! Built-in type catalogue, derived from `pg_catalog.pg_type` at sync time.
//!
//! Every attribute here comes from the catalog rather than from a hand-written
//! table, so a type added by a PostgreSQL release is correct by construction.
//! The only names this module hard-codes are the grammar aliases in
//! [`TYPE_ALIASES`], which are productions in `gram.y` and therefore part of
//! PostgreSQL's parser rather than of its catalog.

use serde::{Deserialize, Serialize};

/// `pg_type.typcategory`, the catalog's own classification of a type.
///
/// Categories describe the type's *purpose*, not its storage, so `jsonb` is
/// `User` while `inet` is `Network` and `bool` is `Boolean`. Built-in-ness
/// never comes from here; it comes from `typtype` plus `typnamespace`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TypeCategory {
    Array,
    Boolean,
    Composite,
    DateTime,
    Enum,
    Geometric,
    Network,
    Numeric,
    Pseudo,
    Range,
    String,
    Timespan,
    User,
    BitString,
    Internal,
    Unknown,
}

impl TypeCategory {
    pub(crate) fn from_catalog(code: &str) -> Self {
        match code {
            "A" => Self::Array,
            "B" => Self::Boolean,
            "C" => Self::Composite,
            "D" => Self::DateTime,
            "E" => Self::Enum,
            "G" => Self::Geometric,
            "I" => Self::Network,
            "N" => Self::Numeric,
            "P" => Self::Pseudo,
            "R" => Self::Range,
            "S" => Self::String,
            "T" => Self::Timespan,
            "U" => Self::User,
            "V" => Self::BitString,
            "Z" => Self::Internal,
            _ => Self::Unknown,
        }
    }
}

/// One built-in type, carrying only what the analyzer actually consults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BuiltinType {
    /// `pg_type.oid`, absent in the offline fallback where no server assigned
    /// one. Modeled as optional rather than zero so "unknown" cannot be
    /// confused with a real identity.
    pub oid: Option<u32>,
    /// `pg_type.typname`, the catalog's own name (`int4`).
    pub typname: String,
    /// `format_type(oid, NULL)`, the canonical SQL spelling (`integer`).
    ///
    /// `NULL` rather than `-1` deliberately: the two differ, and identity wants
    /// the form that names the type rather than one that round-trips a typmod.
    pub canonical: String,
    pub category: TypeCategory,
    /// `pg_type.typispreferred`: the preferred type in its category.
    pub preferred: bool,
    /// `pg_type.typlen` in bits, for fixed-width types only.
    pub fixed_bits: Option<i32>,
    /// `pg_type.typarray`, absent when the type has no array or when the
    /// catalogue came from the offline fallback.
    pub array_oid: Option<u32>,
    /// Whether `pg_type.typmodout` exists, i.e. the type accepts a modifier.
    pub accepts_typmod: bool,
    /// `pg_type.typcollation <> 0`: a value of this type carries a collation.
    pub collatable: bool,
}

impl BuiltinType {}

/// Spellings PostgreSQL's parser accepts in place of a `pg_type.typname`.
///
/// These are the `SystemTypeName` productions in `gram.y`, cross-checked
/// against the special cases in `format_type.c`. They are grammar, so they do
/// not drift with catalog contents; everything else is derived.
///
/// Only spellings that are neither a `typname` nor a canonical spelling appear
/// here; [`BuiltinTypeCatalogue::resolve`] also matches those two.
///
/// `char` is the unquoted `CHAR_P opt_varying` production, which names `bpchar`.
/// The quoted `"char"` is a separate type (OID 18) that keeps its own
/// `typname`, so it stays reachable through [`BuiltinTypeCatalogue::by_oid`]
/// rather than through this table.
const TYPE_ALIASES: &[(&str, &str)] = &[
    ("int", "int4"),
    ("integer", "int4"),
    ("smallint", "int2"),
    ("bigint", "int8"),
    ("real", "float4"),
    ("float", "float8"),
    ("double precision", "float8"),
    ("decimal", "numeric"),
    ("dec", "numeric"),
    ("bit varying", "varbit"),
    ("char", "bpchar"),
    ("character", "bpchar"),
    ("character varying", "varchar"),
    ("national character", "bpchar"),
    ("national char", "bpchar"),
    ("nchar", "bpchar"),
    ("nchar varying", "varchar"),
    ("national character varying", "varchar"),
    ("national char varying", "varchar"),
    ("timestamp without time zone", "timestamp"),
    ("timestamp with time zone", "timestamptz"),
    ("time without time zone", "time"),
    ("time with time zone", "timetz"),
];

/// Map an already case-folded, unquoted type name onto its `pg_type.typname`.
fn grammar_alias(name: &str) -> &str {
    TYPE_ALIASES
        .iter()
        .find(|(alias, _)| *alias == name)
        .map_or(name, |(_, typname)| *typname)
}

/// The derived built-in types of the synchronized database.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BuiltinTypeCatalogue {
    /// Sorted by `typname` so serialization is deterministic and lookup is a
    /// binary search rather than a hash map whose iteration order would vary.
    types: Vec<BuiltinType>,
}

impl BuiltinTypeCatalogue {
    pub(crate) fn new(mut types: Vec<BuiltinType>) -> Self {
        types.sort_by(|a, b| a.typname.cmp(&b.typname));
        types.dedup_by(|a, b| a.typname == b.typname);
        Self { types }
    }

    #[cfg(test)]
    pub(crate) fn types(&self) -> &[BuiltinType] {
        &self.types
    }

    /// Resolve a written type name to the built-in it denotes.
    ///
    /// A name matches when it is a `pg_type.typname`, the canonical spelling
    /// `format_type` produces, or a grammar alias. Matching the canonical form
    /// too is what lets `boolean`, `integer` and `character varying` resolve
    /// without each being enumerated here.
    ///
    /// `name` must already be case-folded and unquoted; the quoted `"char"`
    /// type is looked up by its own `typname` and never by an alias.
    pub(crate) fn resolve(&self, name: &str) -> Option<&BuiltinType> {
        let typname = grammar_alias(name);
        if let Ok(index) = self
            .types
            .binary_search_by(|candidate| candidate.typname.as_str().cmp(typname))
        {
            return Some(&self.types[index]);
        }
        self.types
            .iter()
            .find(|candidate| candidate.canonical == name)
    }

    /// Every spelling [`Self::resolve`] accepts for this type, so a catalogue
    /// gap shows up as a test failure rather than as a silently unresolved name.
    #[cfg(test)]
    pub(crate) fn spellings<'a>(&self, entry: &'a BuiltinType) -> Vec<&'a str> {
        // A typname that a grammar alias claims belongs to another type is not
        // reachable by name: unquoted `char` is the bpchar production, so the
        // catalog's own `char` type is reachable only through its OID.
        let shadowed = TYPE_ALIASES
            .iter()
            .any(|(alias, typname)| *alias == entry.typname && *typname != entry.typname);
        let mut spellings = vec![entry.canonical.as_str()];
        if !shadowed {
            spellings.insert(0, entry.typname.as_str());
        }
        spellings.extend(
            TYPE_ALIASES
                .iter()
                .filter(|(_, typname)| *typname == entry.typname)
                .map(|(alias, _)| *alias),
        );
        spellings
    }

    /// The catalogue used when no baseline supplied one.
    ///
    /// Falls back to the generated static table, which is explicitly a subset
    /// of a real server: anything it does not cover stays unresolved rather than
    /// being guessed at. Built once, since it is immutable.
    pub(crate) fn fallback() -> Self {
        static FALLBACK: std::sync::OnceLock<BuiltinTypeCatalogue> = std::sync::OnceLock::new();
        FALLBACK
            .get_or_init(super::builtin_type_fallback::catalogue)
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builtin(typname: &str, canonical: &str, category: TypeCategory) -> BuiltinType {
        BuiltinType {
            oid: Some(1),
            array_oid: None,
            typname: typname.to_string(),
            canonical: canonical.to_string(),
            category,
            preferred: false,
            fixed_bits: None,
            accepts_typmod: false,
            collatable: false,
        }
    }

    fn sample() -> BuiltinTypeCatalogue {
        BuiltinTypeCatalogue::new(vec![
            builtin("bpchar", "character", TypeCategory::String),
            builtin("float4", "real", TypeCategory::Numeric),
            builtin("float8", "double precision", TypeCategory::Numeric),
            builtin("int2", "smallint", TypeCategory::Numeric),
            builtin("int4", "integer", TypeCategory::Numeric),
            builtin("int8", "bigint", TypeCategory::Numeric),
            builtin("varchar", "character varying", TypeCategory::String),
        ])
    }

    #[test]
    fn grammar_aliases_reach_the_same_canonical_spelling() {
        let catalogue = sample();
        for alias in ["int", "integer", "int4"] {
            assert_eq!(
                catalogue.resolve(alias).map(|t| t.canonical.as_str()),
                Some("integer"),
                "{alias} must name int4"
            );
        }
        assert_eq!(
            catalogue.resolve("float").map(|t| t.canonical.as_str()),
            Some("double precision"),
            "bare float is float8, not float4"
        );
        assert_eq!(
            catalogue
                .resolve("double precision")
                .map(|t| t.typname.as_str()),
            Some("float8")
        );
        for alias in ["char", "character", "bpchar"] {
            assert_eq!(
                catalogue.resolve(alias).map(|t| t.typname.as_str()),
                Some("bpchar"),
                "{alias} must name bpchar"
            );
        }
        for alias in [
            "varchar",
            "character varying",
            "national character varying",
            "nchar varying",
        ] {
            assert_eq!(
                catalogue.resolve(alias).map(|t| t.typname.as_str()),
                Some("varchar"),
                "{alias} must name varchar"
            );
        }
    }

    #[test]
    fn an_unrecognised_name_resolves_to_nothing() {
        assert!(sample().resolve("bytea_missing").is_none());
        assert!(sample().resolve("citext").is_none());
    }

    #[test]
    fn unquoted_char_names_bpchar_not_the_catalogs_own_char_type() {
        let catalogue = BuiltinTypeCatalogue::new(vec![
            builtin("bpchar", "character", TypeCategory::String),
            {
                let mut quoted = builtin("char", "\"char\"", TypeCategory::Internal);
                quoted.oid = Some(18);
                quoted
            },
        ]);
        assert_eq!(
            catalogue.resolve("char").map(|t| t.typname.as_str()),
            Some("bpchar"),
            "unquoted char is the bpchar production"
        );
        assert_eq!(
            catalogue.types()[1].canonical,
            "\"char\"",
            "the catalog's own char type keeps its quoted spelling"
        );
    }

    #[test]
    fn construction_is_order_independent_and_deduplicated() {
        let shuffled = BuiltinTypeCatalogue::new(vec![
            builtin("int4", "integer", TypeCategory::Numeric),
            builtin("bpchar", "character", TypeCategory::String),
            builtin("int4", "integer", TypeCategory::Numeric),
        ]);
        assert_eq!(shuffled.types().len(), 2);
        assert_eq!(shuffled.types()[0].typname, "bpchar");
        assert_eq!(shuffled.types()[1].typname, "int4");
    }
}
