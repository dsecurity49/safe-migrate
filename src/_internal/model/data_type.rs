use std::fmt;

use super::builtin_type::{BuiltinType, BuiltinTypeCatalogue, TypeCategory};

/// A built-in type as the analyzer resolved it.
///
/// Owned rather than borrowed so a parsed type stays valid without the
/// catalogue it came from, which matters because parsing happens deep inside
/// rule evaluation where the catalogue is not in scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ResolvedBuiltinType {
    pub typname: String,
    /// `format_type(oid, NULL)`, the spelling `TypeIdentity` renders.
    pub canonical: String,
    pub category: TypeCategory,
    pub fixed_bits: Option<i32>,
    pub accepts_typmod: bool,
}

impl ResolvedBuiltinType {
    fn from(entry: &BuiltinType) -> Self {
        Self {
            typname: entry.typname.clone(),
            canonical: entry.canonical.clone(),
            category: entry.category,
            fixed_bits: entry.fixed_bits,
            accepts_typmod: entry.accepts_typmod,
        }
    }

    pub(crate) fn is_named(&self, typname: &str) -> bool {
        self.typname == typname
    }

    /// Types whose length limits compare the same way, so a widening between
    /// two of them is metadata-only. `typcategory` cannot answer this: it also
    /// admits `name`, which takes no length at all.
    pub(crate) fn is_text_like(&self) -> bool {
        self.category == TypeCategory::String && self.typname != "name"
    }

    /// The `numeric` type specifically, not PostgreSQL's wider numeric
    /// category: the precision/scale widening rules are about it alone, since
    /// integers and floats widen by an entirely different route.
    pub(crate) fn is_exact_numeric(&self) -> bool {
        self.typname == "numeric"
    }

    /// The one type whose values need an explicit `::text` cast to compare
    /// byte-for-byte when a partition key is synthesized.
    pub(crate) fn requires_text_cast_for_comparison(&self) -> bool {
        self.typname == "varchar"
    }
}

/// What a modifier on a built-in type means.
///
/// This is *not* in the catalog: PostgreSQL encodes each type's modifier in a
/// `typmodout` function, and the accepted ranges live in `typtmod.c`. The
/// catalogue says which types accept a modifier at all; this says what it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypmodKind {
    None,
    CharacterLength,
    BitLength,
    Numeric,
    FractionalSeconds,
    IntervalFields,
}

/// The ten PostgreSQL types that accept a modifier, matching `pg_type.typmodout`.
const TYPMOD_RULES: &[(&str, TypmodKind)] = &[
    ("bit", TypmodKind::BitLength),
    ("bpchar", TypmodKind::CharacterLength),
    ("interval", TypmodKind::IntervalFields),
    ("numeric", TypmodKind::Numeric),
    ("time", TypmodKind::FractionalSeconds),
    ("timestamp", TypmodKind::FractionalSeconds),
    ("timestamptz", TypmodKind::FractionalSeconds),
    ("timetz", TypmodKind::FractionalSeconds),
    ("varbit", TypmodKind::BitLength),
    ("varchar", TypmodKind::CharacterLength),
];

/// Spellings whose grammar production defaults the length to one.
///
/// `CharacterWithoutLength` sets typmod 1 only when it reduced to `bpchar`, and
/// `BitWithoutLength` only when it did not take `VARYING`. So bare `char`,
/// `character` and `bit` are `(1)`, while `character varying`, `varchar`,
/// `varbit` and the catalog's own `bpchar` establish no limit.
const IMPLICIT_LENGTH_ONE: &[&str] = &["char", "character", "bit"];

fn typmod_kind(typname: &str) -> TypmodKind {
    TYPMOD_RULES
        .iter()
        .find(|(name, _)| *name == typname)
        .map_or(TypmodKind::None, |(_, kind)| *kind)
}

// PostgreSQL's accepted ranges for built-in type modifiers, verified against
// PostgreSQL 18.2 and stable across 14-18. A declaration outside them is SQL
// the database rejects.
mod pg_typmod {
    // "length for type varchar must be at least 1" / "cannot exceed 10485760"
    pub(crate) const CHAR_LENGTH: std::ops::RangeInclusive<i32> = 1..=10_485_760;
    // A bounded character column stores its length in atttypmod as length + VARHDRSZ.
    pub(crate) const VARHDRSZ: i32 = 4;
    pub(crate) const NUMERIC_PRECISION: std::ops::RangeInclusive<i32> = 1..=1_000;
    pub(crate) const NUMERIC_SCALE: std::ops::RangeInclusive<i32> = -1_000..=1_000;
}

/// A character length PostgreSQL has accepted. Holding the bound here is what
/// makes `atttypmod` total, so no declaration can overflow it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CharLength(u32);

impl CharLength {
    // Bare char/character is character(1) in both the SQL standard and PostgreSQL.
    pub(crate) const IMPLICIT: Self = Self(1);

    fn new(raw: i32) -> Option<Self> {
        pg_typmod::CHAR_LENGTH
            .contains(&raw)
            .then_some(Self(raw as u32))
    }

    pub(crate) fn get(self) -> i32 {
        self.0 as i32
    }

    pub(crate) fn atttypmod(self) -> i32 {
        self.get() + pg_typmod::VARHDRSZ
    }
}

/// A `numeric` precision PostgreSQL has accepted (1..=1000).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct NumericPrecision(u16);

impl NumericPrecision {
    fn new(raw: i32) -> Option<Self> {
        pg_typmod::NUMERIC_PRECISION
            .contains(&raw)
            .then_some(Self(raw as u16))
    }

    pub(crate) fn get(self) -> i32 {
        self.0 as i32
    }
}

/// A `numeric` scale PostgreSQL has accepted (-1000..=1000). This value decides
/// how many zeros are appended when rendering a scale-padded partition bound, so
/// the bound belongs here rather than in a clamp at each use site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct NumericScale(i32);

impl NumericScale {
    fn new(raw: i32) -> Option<Self> {
        pg_typmod::NUMERIC_SCALE.contains(&raw).then_some(Self(raw))
    }

    pub(crate) fn get(self) -> i32 {
        self.0
    }

    // A negative scale shifts digits left of the point, so it needs no padding.
    pub(crate) fn zero_padding(self) -> usize {
        self.0.max(0) as usize
    }
}

/// How PostgreSQL interprets a declared type modifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypeTypmod {
    /// The family takes no modifier (`integer`, `text`, `uuid`).
    NotApplicable,
    /// None declared, so no limit is established (atttypmod -1).
    Unbounded,
    /// `char(n)`, `varchar(n)`, or bare `char`.
    CharacterLength(CharLength),
    /// `numeric(p, s)`. `scale` is None for `numeric(p)`.
    Numeric {
        precision: NumericPrecision,
        scale: Option<NumericScale>,
    },
    /// Declared but rejected by the server. Kept distinct from `Unbounded` so an
    /// out-of-range value can never be read as a valid limit or as "no limit".
    OutOfRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedDataType {
    /// `None` when the written name is not a built-in; a user-defined type is
    /// resolved by OID elsewhere and keeps only its written name here.
    pub builtin: Option<ResolvedBuiltinType>,
    pub original_base: String,
    // Kept verbatim so rendering and signature identity reproduce the exact
    // declaration, including ones the server would reject. Private so it cannot
    // drift from `typmod`; only `parse` sets it.
    raw_typmods: Option<String>,
    pub array_dimensions: usize,
    typmod: TypeTypmod,
}

/// First `server_version_num` accepting a widened `numeric` scale.
pub(crate) const WIDENED_NUMERIC_SCALE_VERSION: u32 = 150_000;

impl ParsedDataType {
    pub(crate) fn parse(raw: &str, catalogue: &BuiltinTypeCatalogue) -> Self {
        let mut text = Self::fold_unquoted_identifier_case(raw.trim());

        let mut array_dimensions = 0;
        while text.ends_with("[]") {
            array_dimensions += 1;
            text = text.strip_suffix("[]").unwrap().trim().to_string();
        }

        // rfind so nested parens in unusual type expressions don't truncate the typmod.
        // A timezone qualifier can trail the closing paren, so re-join it before
        // the family lookup or it is silently discarded.
        let mut typmods = None;
        let original_base;
        if let Some(open) = text.find('(')
            && let Some(close) = text.rfind(')')
            && close > open
        {
            typmods = Some(text[open + 1..close].trim().to_string());
            let pre = text[..open].trim();
            let post = text[close + 1..].trim();
            original_base = pre.to_string();
            text = if post.is_empty() {
                pre.to_string()
            } else {
                format!("{pre} {post}")
            };
        } else {
            original_base = text.clone();
        }

        // A built-in type is the same whether or not it is written
        // `pg_catalog.text`. Any other qualifier names a distinct user type.
        let text = Self::strip_pg_catalog_qualifier(&text).to_string();
        let original_base = Self::strip_pg_catalog_qualifier(&original_base).to_string();

        let builtin = catalogue.resolve(&text).map(ResolvedBuiltinType::from);
        let typmod = Self::classify_typmod(builtin.as_ref(), &text, typmods.as_deref());
        Self {
            builtin,
            original_base,
            raw_typmods: typmods,
            array_dimensions,
            typmod,
        }
    }

    /// Whether the written name named a built-in type.
    pub(crate) fn is_builtin(&self) -> bool {
        self.builtin.is_some()
    }

    pub(crate) fn builtin(&self) -> Option<&ResolvedBuiltinType> {
        self.builtin.as_ref()
    }

    /// The canonical SQL spelling, or the written name when unresolved.
    pub(crate) fn canonical_name(&self) -> &str {
        self.builtin
            .as_ref()
            .map_or(self.original_base.as_str(), |b| b.canonical.as_str())
    }

    /// The canonical spelling split so a modifier renders before any timezone
    /// qualifier: `timestamptz` gives `("timestamp", " with time zone")`.
    fn canonical_and_tz_suffix(&self) -> (&str, &str) {
        let canonical = self.canonical_name();
        for suffix in [" without time zone", " with time zone"] {
            if let Some(base) = canonical.strip_suffix(suffix) {
                return (base, suffix);
            }
        }
        (canonical, "")
    }

    pub(crate) fn is_named(&self, typname: &str) -> bool {
        self.builtin.as_ref().is_some_and(|b| b.is_named(typname))
    }

    pub(crate) fn is_text_like(&self) -> bool {
        self.builtin.as_ref().is_some_and(|b| b.is_text_like())
    }

    pub(crate) fn is_exact_numeric(&self) -> bool {
        self.builtin.as_ref().is_some_and(|b| b.is_exact_numeric())
    }

    pub(crate) fn fixed_bits(&self) -> Option<i32> {
        self.builtin.as_ref().and_then(|b| b.fixed_bits)
    }

    pub(crate) fn requires_text_cast_for_comparison(&self) -> bool {
        self.builtin
            .as_ref()
            .is_some_and(|b| b.requires_text_cast_for_comparison())
    }

    fn strip_pg_catalog_qualifier(name: &str) -> &str {
        name.strip_prefix("pg_catalog.")
            .or_else(|| name.strip_prefix("\"pg_catalog\"."))
            .unwrap_or(name)
    }

    // Anything the server would reject becomes OutOfRange rather than a value.
    fn classify_typmod(
        builtin: Option<&ResolvedBuiltinType>,
        written: &str,
        raw: Option<&str>,
    ) -> TypeTypmod {
        let Some(builtin) = builtin else {
            // Nothing is known about the type, so a modifier cannot be called
            // acceptable; failing closed keeps an unverified declaration visible.
            return match raw {
                None => TypeTypmod::NotApplicable,
                Some(_) => TypeTypmod::OutOfRange,
            };
        };

        match typmod_kind(&builtin.typname) {
            TypmodKind::CharacterLength | TypmodKind::BitLength => {
                let implicit = if matches!(builtin.typname.as_str(), "bpchar" | "bit")
                    && IMPLICIT_LENGTH_ONE.contains(&written)
                {
                    TypeTypmod::CharacterLength(CharLength::IMPLICIT)
                } else {
                    // `bpchar` is only ever the catalog's spelling, so an absent
                    // modifier there means no length was carried.
                    TypeTypmod::Unbounded
                };
                let Some(raw) = raw else {
                    return implicit;
                };
                raw.trim()
                    .parse::<i32>()
                    .ok()
                    .and_then(CharLength::new)
                    .map_or(TypeTypmod::OutOfRange, TypeTypmod::CharacterLength)
            }
            TypmodKind::Numeric => {
                let Some(raw) = raw else {
                    return TypeTypmod::Unbounded;
                };
                let mut parts = raw.splitn(2, ',');
                let Some(precision) = parts.next().map(str::trim).and_then(|p| p.parse().ok())
                else {
                    return TypeTypmod::OutOfRange;
                };
                let Some(precision) = NumericPrecision::new(precision) else {
                    return TypeTypmod::OutOfRange;
                };
                // `numeric(p)` declares a precision but no scale.
                let scale = match parts.next() {
                    None => None,
                    Some(s) => match s.trim().parse().ok().and_then(NumericScale::new) {
                        Some(scale) => Some(scale),
                        None => return TypeTypmod::OutOfRange,
                    },
                };
                TypeTypmod::Numeric { precision, scale }
            }
            // Fractional-second precision and interval fields take a bare
            // integer or a field list, neither of which narrows a value.
            // Fractional-second precision and interval fields take a bare
            // integer or a field list; neither constrains a stored value, so the
            // modifier is recorded without being interpreted.
            TypmodKind::FractionalSeconds | TypmodKind::IntervalFields => match raw {
                None => TypeTypmod::NotApplicable,
                Some(_) => TypeTypmod::Unbounded,
            },
            // The server rejects a modifier on a type that takes none. A type
            // the catalog reports as accepting one but this table has no rule
            // for is a modelling gap, and fails closed rather than claiming the
            // modifier was accepted.
            TypmodKind::None => match raw {
                None => TypeTypmod::NotApplicable,
                Some(_) => TypeTypmod::OutOfRange,
            },
        }
    }

    fn fold_unquoted_identifier_case(raw: &str) -> String {
        let mut folded = String::with_capacity(raw.len());
        let mut in_quotes = false;
        let mut chars = raw.chars().peekable();
        while let Some(ch) = chars.next() {
            match ch {
                '"' if in_quotes && chars.peek() == Some(&'"') => {
                    folded.push('"');
                    folded.push('"');
                    chars.next();
                }
                '"' => {
                    in_quotes = !in_quotes;
                    folded.push(ch);
                }
                ch if in_quotes => folded.push(ch),
                ch => folded.extend(ch.to_lowercase()),
            }
        }
        folded
    }

    /// The modifier exactly as declared, for rendering and signature identity.
    pub(crate) fn raw_typmods(&self) -> Option<&str> {
        self.raw_typmods.as_deref()
    }

    /// Whether a modifier was declared at all.
    pub(crate) fn has_typmod(&self) -> bool {
        self.raw_typmods.is_some()
    }

    /// Character limit, or None when no limit is established: an unbounded
    /// column, another family, or a declaration the server rejects.
    pub(crate) fn character_limit(&self) -> Option<i32> {
        match self.typmod {
            TypeTypmod::CharacterLength(length) => Some(length.get()),
            _ => None,
        }
    }

    /// atttypmod as PostgreSQL stores it for a bounded character column.
    pub(crate) fn atttypmod_offset(&self) -> Option<i32> {
        match self.typmod {
            TypeTypmod::CharacterLength(length) => Some(length.atttypmod()),
            _ => None,
        }
    }

    /// Precision and scale. numeric(p) is Some((p, 0)), the scale PostgreSQL applies.
    pub(crate) fn numeric_params(&self) -> Option<(i32, i32)> {
        match self.typmod {
            TypeTypmod::Numeric { precision, scale } => {
                Some((precision.get(), scale.map_or(0, NumericScale::get)))
            }
            _ => None,
        }
    }

    /// True when the declared scale is only legal from
    /// `WIDENED_NUMERIC_SCALE_VERSION` onward.
    pub(crate) fn needs_widened_numeric_scale(&self) -> bool {
        match self.typmod {
            TypeTypmod::Numeric {
                precision,
                scale: Some(scale),
            } => {
                let scale = scale.get();
                scale < 0 || scale > precision.get()
            }
            _ => false,
        }
    }

    /// The scale numeric(p, s) declares, if any.
    pub(crate) fn numeric_scale(&self) -> Option<NumericScale> {
        match self.typmod {
            TypeTypmod::Numeric { scale, .. } => scale,
            _ => None,
        }
    }

    pub(crate) fn is_lossy_narrowing_to(&self, new_type: &ParsedDataType) -> bool {
        // Two spellings of one built-in (`int` and `integer`) are the same
        // type; two unresolved names are never assumed to be.
        if self.is_builtin()
            && new_type.is_builtin()
            && self.canonical_name() == new_type.canonical_name()
            && self.raw_typmods == new_type.raw_typmods
            && self.array_dimensions == new_type.array_dimensions
        {
            return false;
        }

        // Any change in array dimensionality is structurally incompatible.
        if self.array_dimensions != new_type.array_dimensions {
            return true;
        }

        // A narrower fixed-width representation cannot hold every value of a
        // wider one, whatever the type.
        if let (Some(old_bits), Some(new_bits)) = (self.fixed_bits(), new_type.fixed_bits()) {
            return new_bits < old_bits;
        }

        let old_is_string = self.is_text_like();
        let new_is_string = new_type.is_text_like();

        if old_is_string && new_is_string {
            return match (self.character_limit(), new_type.character_limit()) {
                (Some(old_lim), Some(new_lim)) => new_lim < old_lim,
                (None, Some(_)) => true,
                (Some(_), None) => false,
                (None, None) => false,
            };
        }

        // String to a non-string family: lossy when the source had an explicit upper bound.
        if old_is_string {
            return self.character_limit().is_some();
        }

        false
    }
}

/// A type's catalog identity, as PostgreSQL compares it. `ParsedDataType` records
/// what the user wrote; this discards parenthesized modifiers, so it has no typmod.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct TypeIdentity {
    /// `format_type(oid, NULL)` for a built-in, or the written name for a type
    /// PostgreSQL did not resolve to one.
    canonical: String,
    array_dimensions: usize,
    /// Whether `canonical` came from the catalog rather than from the written
    /// name. Two unresolved types that share a spelling are still distinct, so
    /// this cannot be inferred from the string.
    resolved: bool,
}

impl TypeIdentity {
    pub(crate) fn from_syntax(syntax: &ParsedDataType) -> Self {
        Self {
            canonical: syntax.canonical_name().to_string(),
            // PostgreSQL has one array type per element however many `[]` a
            // declaration carried, so the identity cannot keep the count.
            array_dimensions: usize::from(syntax.array_dimensions > 0),
            resolved: syntax.is_builtin(),
        }
    }

    /// A type PostgreSQL did not resolve to a built-in, such as a user-defined
    /// type. Its written name is all that distinguishes it.
    pub(crate) fn is_unknown(&self) -> bool {
        !self.resolved
    }

    /// Renders exactly as `pg_catalog.format_type(oid, NULL)` does, so bare
    /// `character` is not expanded to `character(1)`.
    pub(crate) fn render(&self) -> String {
        let mut out = self.canonical.clone();
        for _ in 0..self.array_dimensions {
            out.push_str("[]");
        }
        out
    }
}

impl fmt::Display for ParsedDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The catalog's own spelling renders as itself; a DDL declaration
        // renders as the canonical SQL spelling it was written with.
        // `bpchar` keeps its catalog spelling: `character` on its own means
        // character(1), so rendering it canonically would change the
        // declaration. PostgreSQL draws the same line in format_type.c.
        let (base, tz_suffix) = if self.is_named("bpchar") && self.typmod == TypeTypmod::Unbounded {
            ("bpchar", "")
        } else {
            self.canonical_and_tz_suffix()
        };
        let mut out = base.to_string();

        if let Some(mods) = self.raw_typmods() {
            out.push_str(&format!("({mods})"));
        } else if matches!(self.typmod, TypeTypmod::CharacterLength(length) if length == CharLength::IMPLICIT)
        {
            out.push_str("(1)");
        }

        // The qualifier trails the modifier, as PostgreSQL renders it.
        out.push_str(tz_suffix);

        for _ in 0..self.array_dimensions {
            out.push_str("[]");
        }

        write!(f, "{out}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The offline snapshot; a synced baseline supersedes it.
    fn catalogue() -> &'static BuiltinTypeCatalogue {
        static CATALOGUE: std::sync::OnceLock<BuiltinTypeCatalogue> = std::sync::OnceLock::new();
        CATALOGUE.get_or_init(BuiltinTypeCatalogue::fallback)
    }

    #[test]
    fn canonical_alias_round_trip() {
        let cases = [
            ("int", "integer"),
            ("int4", "integer"),
            ("int8", "bigint"),
            ("int2", "smallint"),
            ("float8", "double precision"),
            ("float4", "real"),
            ("bool", "boolean"),
            ("varchar", "character varying"),
            ("varchar(255)", "character varying(255)"),
            ("char", "character(1)"),
            ("char(10)", "character(10)"),
            ("bpchar(5)", "character(5)"),
            ("time", "time without time zone"),
            ("timestamp", "timestamp without time zone"),
            ("timestamptz", "timestamp with time zone"),
            ("decimal", "numeric"),
            ("int[]", "integer[]"),
            ("varchar(50)[][]", "character varying(50)[][]"),
            ("unknown_type", "unknown_type"),
            // Precision modifier combined with timezone qualifier (F7 regression).
            // The qualifier trails the closing paren and must not be discarded.
            // PostgreSQL renders the precision before the timezone qualifier.
            ("timestamp(6) with time zone", "timestamp(6) with time zone"),
            ("timestamp(0) with time zone", "timestamp(0) with time zone"),
            (
                "timestamp(3) without time zone",
                "timestamp(3) without time zone",
            ),
            ("time(3) with time zone", "time(3) with time zone"),
            ("time(0) without time zone", "time(0) without time zone"),
        ];
        for (input, expected) in cases {
            let parsed = ParsedDataType::parse(input, catalogue());
            assert_eq!(parsed.to_string(), expected, "failed for '{input}'");
        }
    }

    #[test]
    fn type_identity_discards_typmods_like_postgres() {
        let identity = |raw: &str| {
            TypeIdentity::from_syntax(&ParsedDataType::parse(raw, catalogue()))
                .render()
                .to_string()
        };

        // CREATE FUNCTION discards parenthesized modifiers, and
        // pg_catalog.format_type(oid, NULL) is bare for bpchar/char.
        assert_eq!(identity("char"), "character");
        assert_eq!(identity("character"), "character");
        assert_eq!(identity("char(10)"), "character");
        assert_eq!(identity("bpchar"), "character");
        assert_eq!(identity("int"), "integer");
        assert_eq!(identity("varchar(50)"), "character varying");
        assert_eq!(identity("numeric(10,2)"), "numeric");
        assert_eq!(
            identity("timestamp(6) with time zone"),
            "timestamp with time zone"
        );
        assert_eq!(identity("varchar(50)[]"), "character varying[]");

        assert_eq!(identity("varchar(10)"), identity("varchar"));
        assert_eq!(identity("numeric(3,5)"), identity("numeric"));
    }

    #[test]
    fn lossy_narrowing_integer() {
        let s = ParsedDataType::parse("smallint", catalogue());
        let i = ParsedDataType::parse("integer", catalogue());
        let b = ParsedDataType::parse("bigint", catalogue());
        assert!(!s.is_lossy_narrowing_to(&i));
        assert!(!i.is_lossy_narrowing_to(&b));
        assert!(b.is_lossy_narrowing_to(&i));
        assert!(i.is_lossy_narrowing_to(&s));
    }

    #[test]
    fn lossy_narrowing_character() {
        let text = ParsedDataType::parse("text", catalogue());
        let vc_unb = ParsedDataType::parse("character varying", catalogue());
        let vc255 = ParsedDataType::parse("varchar(255)", catalogue());
        let vc50 = ParsedDataType::parse("varchar(50)", catalogue());
        assert!(!vc50.is_lossy_narrowing_to(&vc255));
        assert!(!vc50.is_lossy_narrowing_to(&text));
        assert!(vc255.is_lossy_narrowing_to(&vc50));
        assert!(text.is_lossy_narrowing_to(&vc255));
        assert!(vc_unb.is_lossy_narrowing_to(&vc255));
    }

    #[test]
    fn lossy_narrowing_array_dimension_change() {
        let i = ParsedDataType::parse("integer", catalogue());
        let ia = ParsedDataType::parse("integer[]", catalogue());
        assert!(i.is_lossy_narrowing_to(&ia));
        assert!(ia.is_lossy_narrowing_to(&i));
    }

    #[test]
    fn numeric_params_extraction() {
        assert_eq!(
            ParsedDataType::parse("numeric", catalogue()).numeric_params(),
            None
        );
        assert_eq!(
            ParsedDataType::parse("numeric(10)", catalogue()).numeric_params(),
            Some((10, 0))
        );
        assert_eq!(
            ParsedDataType::parse("numeric(10, 2)", catalogue()).numeric_params(),
            Some((10, 2))
        );
        assert_eq!(
            ParsedDataType::parse("decimal(5,3)", catalogue()).numeric_params(),
            Some((5, 3))
        );
        assert_eq!(
            ParsedDataType::parse("integer", catalogue()).numeric_params(),
            None
        );
    }

    #[test]
    fn numeric_scale_extraction() {
        assert_eq!(
            ParsedDataType::parse("numeric", catalogue())
                .numeric_scale()
                .map(NumericScale::get),
            None
        );
        assert_eq!(
            ParsedDataType::parse("numeric(10)", catalogue())
                .numeric_scale()
                .map(NumericScale::get),
            None
        );
        assert_eq!(
            ParsedDataType::parse("numeric(10,2)", catalogue())
                .numeric_scale()
                .map(NumericScale::get),
            Some(2)
        );
        assert_eq!(
            ParsedDataType::parse("numeric(10,-3)", catalogue())
                .numeric_scale()
                .map(NumericScale::get),
            Some(-3)
        );
    }

    #[test]
    fn character_limit_and_atttypmod() {
        let v50 = ParsedDataType::parse("varchar(50)", catalogue());
        assert_eq!(v50.character_limit(), Some(50));
        assert_eq!(v50.atttypmod_offset(), Some(54));
        assert_eq!(
            ParsedDataType::parse("text", catalogue()).character_limit(),
            None
        );

        // PostgreSQL records these exact atttypmod values; see the 18.2 probe in
        // temp/ and docs. char(7) is 11, bare char is 5.
        assert_eq!(
            ParsedDataType::parse("char(7)", catalogue()).atttypmod_offset(),
            Some(11)
        );
        assert_eq!(
            ParsedDataType::parse("char", catalogue()).atttypmod_offset(),
            Some(5)
        );
        assert_eq!(
            ParsedDataType::parse("character", catalogue()).character_limit(),
            Some(1)
        );
    }

    // The accepted range is the server's, so the largest accepted length plus
    // VARHDRSZ is the largest atttypmod that can be built.
    #[test]
    fn character_length_bounds_match_postgres() {
        assert_eq!(
            ParsedDataType::parse("varchar(0)", catalogue()).typmod,
            TypeTypmod::OutOfRange
        );
        assert_eq!(
            ParsedDataType::parse("char(0)", catalogue()).typmod,
            TypeTypmod::OutOfRange
        );
        assert_eq!(
            ParsedDataType::parse("varchar(-1)", catalogue()).typmod,
            TypeTypmod::OutOfRange
        );
        assert_eq!(
            ParsedDataType::parse("varchar(10485760)", catalogue()).character_limit(),
            Some(10485760)
        );
        assert_eq!(
            ParsedDataType::parse("varchar(10485761)", catalogue()).typmod,
            TypeTypmod::OutOfRange
        );
        assert_eq!(
            ParsedDataType::parse("varchar(10485760)", catalogue()).atttypmod_offset(),
            Some(10485764)
        );
    }

    // Regression: varchar(2147483647) used to reach `limit + 4`, which wraps to a
    // negative atttypmod in release and makes a partition-key incompatibility
    // compare as compatible. The server rejects this declaration outright.
    #[test]
    fn atttypmod_cannot_overflow() {
        for decl in [
            "varchar(2147483643)",
            "varchar(2147483644)",
            "varchar(2147483647)",
            "varchar(99999999999999)",
        ] {
            let parsed = ParsedDataType::parse(decl, catalogue());
            assert_eq!(parsed.typmod, TypeTypmod::OutOfRange, "{decl}");
            assert_eq!(parsed.character_limit(), None, "{decl}");
            assert_eq!(parsed.atttypmod_offset(), None, "{decl}");
        }
    }

    // Regression: numeric(10, 4000000000) reached "0".repeat(4_000_000_000) and
    // aborted the process on a ~4 GiB allocation. The server rejects the scale
    // as out of range for type integer.
    #[test]
    fn hostile_numeric_scale_never_reaches_repeat() {
        for decl in ["numeric(10,4000000000)", "numeric(4000000000,0)"] {
            let parsed = ParsedDataType::parse(decl, catalogue());
            assert_eq!(parsed.typmod, TypeTypmod::OutOfRange, "{decl}");
            assert_eq!(parsed.numeric_scale(), None, "{decl}");
            assert_eq!(parsed.numeric_params(), None, "{decl}");
        }
    }

    #[test]
    fn numeric_precision_and_scale_bounds_match_postgres() {
        for bad in [
            "numeric(0)",
            "numeric(1001)",
            "numeric(-1)",
            "numeric(10,1001)",
        ] {
            assert_eq!(
                ParsedDataType::parse(bad, catalogue()).typmod,
                TypeTypmod::OutOfRange,
                "{bad}"
            );
        }
        assert_eq!(
            ParsedDataType::parse("numeric(1000,1000)", catalogue()).numeric_params(),
            Some((1000, 1000))
        );
        assert_eq!(
            ParsedDataType::parse("numeric(10,-1000)", catalogue()).numeric_params(),
            Some((10, -1000))
        );
    }

    // The padding count is what sizes the allocation, so its bound is the
    // invariant that keeps a scale-padded literal cheap to render.
    #[test]
    fn zero_padding_is_bounded_by_server_scale_limit() {
        let mut widest = 0;
        for scale in -1000..=1000 {
            let padding = NumericScale::new(scale).map_or(0, NumericScale::zero_padding);
            assert!(padding <= 1000, "scale {scale} produced {padding} zeros");
            widest = widest.max(padding);
        }
        assert_eq!(widest, 1000);
        assert_eq!(
            NumericScale::new(-3).map(NumericScale::zero_padding),
            Some(0)
        );
    }

    // A modifier on a family that takes none is rejected by the server
    // ("type modifier is not allowed"), so it is not a valid modifier here either.
    #[test]
    fn typmod_on_family_that_takes_none_is_out_of_range() {
        for decl in [
            "text(50)",
            "integer(5)",
            "name(300)",
            "numeric()",
            "varchar()",
        ] {
            assert_eq!(
                ParsedDataType::parse(decl, catalogue()).typmod,
                TypeTypmod::OutOfRange,
                "{decl}"
            );
        }
        assert_eq!(
            ParsedDataType::parse("text", catalogue()).typmod,
            TypeTypmod::NotApplicable
        );
        assert_eq!(
            ParsedDataType::parse("integer", catalogue()).typmod,
            TypeTypmod::NotApplicable
        );
    }

    #[test]
    fn not_applicable_and_unbounded_are_distinct() {
        assert_eq!(
            ParsedDataType::parse("varchar", catalogue()).typmod,
            TypeTypmod::Unbounded
        );
        assert_eq!(
            ParsedDataType::parse("numeric", catalogue()).typmod,
            TypeTypmod::Unbounded
        );
        assert_eq!(
            ParsedDataType::parse("text", catalogue()).typmod,
            TypeTypmod::NotApplicable
        );
    }

    // `bpchar` is the catalog's internal spelling and never appears in DDL, so a
    // missing modifier means the length was not carried. It must not be guessed
    // as 1, because that would turn an unknown length into a false "safe".
    #[test]
    fn bare_bpchar_establishes_no_limit() {
        assert_eq!(
            ParsedDataType::parse("bpchar", catalogue()).typmod,
            TypeTypmod::Unbounded
        );
        assert_eq!(
            ParsedDataType::parse("bpchar", catalogue()).character_limit(),
            None
        );
        assert_eq!(
            ParsedDataType::parse("bpchar", catalogue()).to_string(),
            "bpchar"
        );
    }

    // A bare `char` is exactly character(1), so widening it to varchar(50) is
    // safe. It used to be modelled as unbounded, which reported a safe change
    // as a lossy narrowing.
    #[test]
    fn bare_char_widening_is_not_reported_as_lossy() {
        let bare = ParsedDataType::parse("char", catalogue());
        assert!(!bare.is_lossy_narrowing_to(&ParsedDataType::parse("varchar(50)", catalogue())));
        assert!(!bare.is_lossy_narrowing_to(&ParsedDataType::parse("text", catalogue())));
        assert!(!ParsedDataType::parse("char(1)", catalogue()).is_lossy_narrowing_to(&bare));
        // Narrowing it really is lossy.
        assert!(ParsedDataType::parse("char(10)", catalogue()).is_lossy_narrowing_to(&bare));
    }

    // An unknown length must still fail closed.
    #[test]
    fn unknown_bpchar_length_still_fails_closed() {
        let unknown = ParsedDataType::parse("bpchar", catalogue());
        assert!(unknown.is_lossy_narrowing_to(&ParsedDataType::parse("char(5)", catalogue())));
    }

    // Rendering must reproduce the declaration verbatim, including one the server
    // would reject: rewriting it would hide the error from the reader.
    #[test]
    fn rejected_declarations_render_verbatim() {
        assert_eq!(
            ParsedDataType::parse("numeric(10,4000000000)", catalogue()).to_string(),
            "numeric(10,4000000000)"
        );
        assert_eq!(
            ParsedDataType::parse("varchar(2147483647)", catalogue()).to_string(),
            "character varying(2147483647)"
        );
        assert_eq!(
            ParsedDataType::parse("text(50)", catalogue()).to_string(),
            "text(50)"
        );
        assert_eq!(
            TypeIdentity::from_syntax(&ParsedDataType::parse(
                "numeric(10,4000000000)",
                catalogue()
            ))
            .render(),
            "numeric"
        );
    }

    #[test]
    fn has_typmod_distinguishes_declared_from_established() {
        assert!(ParsedDataType::parse("varchar(50)", catalogue()).has_typmod());
        assert!(!ParsedDataType::parse("varchar", catalogue()).has_typmod());
        // A rejected declaration is still a declaration.
        assert!(ParsedDataType::parse("varchar(2147483647)", catalogue()).has_typmod());
        assert!(
            ParsedDataType::parse("varchar(2147483647)", catalogue())
                .raw_typmods()
                .is_some()
        );
    }

    #[test]
    fn pg_catalog_qualifier_does_not_change_a_builtin_identity() {
        // PostgreSQL resolves both spellings to the same type OID.
        for (qualified, bare) in [
            ("pg_catalog.text", "text"),
            ("pg_catalog.int4", "int"),
            ("pg_catalog.varchar(10)", "varchar(10)"),
            ("pg_catalog.timestamptz", "timestamptz"),
            ("pg_catalog.text[]", "text[]"),
            ("\"pg_catalog\".numeric", "numeric"),
        ] {
            assert_eq!(
                TypeIdentity::from_syntax(&ParsedDataType::parse(qualified, catalogue())),
                TypeIdentity::from_syntax(&ParsedDataType::parse(bare, catalogue())),
                "{qualified} must be the same identity as {bare}"
            );
        }
    }

    #[test]
    fn a_custom_type_has_no_catalog_rendering_of_its_own() {
        // Callers must key an unresolved custom type on its written name;
        // `render` alone cannot tell two of them apart.
        let identity =
            |raw: &str| TypeIdentity::from_syntax(&ParsedDataType::parse(raw, catalogue()));
        assert!(identity("sm_core.text").is_unknown());
        assert!(identity("sm_core.text[]").is_unknown());
        assert!(!identity("text").is_unknown());
        assert!(!identity("pg_catalog.text").is_unknown());

        // The built-in renders canonically once the qualifier is dropped.
        assert_eq!(identity("pg_catalog.text").render(), "text");
        assert_eq!(identity("pg_catalog.int").render(), "integer");

        // Distinct custom types keep distinct written forms.
        let written = |raw: &str| ParsedDataType::parse(raw, catalogue()).to_string();
        assert_ne!(written("sm_core.text"), written("other.text"));
        assert_ne!(written("sm_core.text"), written("text"));
        assert_ne!(written("sm_core.mood"), written("sm_core.mood[]"));
    }
}
