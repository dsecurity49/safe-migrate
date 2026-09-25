use std::fmt;

/// Represents the canonical base families of PostgreSQL data types.
/// This enum normalizes away spelling differences (e.g., `int4` vs `integer`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum DataTypeFamily {
    Boolean,
    SmallInt,
    Integer,
    BigInt,
    Numeric,
    Real,
    DoublePrecision,
    Date,
    Time,
    TimeTz,
    Timestamp,
    TimestampTz,
    Interval,
    Uuid,
    Text,
    Name,
    CiText,
    CharacterVarying,
    Character,
    BpChar,
    /// Fallback for types not strictly modeled (e.g., user-defined types, geometric types).
    Unknown,
}

impl DataTypeFamily {
    /// Resolves a raw PostgreSQL type name (without modifiers or array dimensions)
    /// into its canonical family.
    pub(crate) fn from_base_name(name: &str) -> Self {
        match name {
            "bool" | "boolean" => Self::Boolean,
            "int2" | "smallint" => Self::SmallInt,
            "int" | "int4" | "integer" => Self::Integer,
            "int8" | "bigint" => Self::BigInt,
            "decimal" | "numeric" => Self::Numeric,
            "float4" | "real" => Self::Real,
            "float8" | "double precision" => Self::DoublePrecision,
            "date" => Self::Date,
            "time" | "time without time zone" => Self::Time,
            "timetz" | "time with time zone" => Self::TimeTz,
            "timestamp" | "timestamp without time zone" => Self::Timestamp,
            "timestamptz" | "timestamp with time zone" => Self::TimestampTz,
            "interval" => Self::Interval,
            "uuid" => Self::Uuid,
            "text" => Self::Text,
            "name" => Self::Name,
            "citext" => Self::CiText,
            "varchar" | "character varying" => Self::CharacterVarying,
            "char" | "character" => Self::Character,
            "bpchar" => Self::BpChar,
            _ => Self::Unknown,
        }
    }

    /// Returns the canonical PostgreSQL spelling for this type family.
    pub(crate) fn to_canonical_string(self, original_fallback: &str) -> String {
        match self {
            Self::Boolean => "boolean".to_string(),
            Self::SmallInt => "smallint".to_string(),
            Self::Integer => "integer".to_string(),
            Self::BigInt => "bigint".to_string(),
            Self::Numeric => "numeric".to_string(),
            Self::Real => "real".to_string(),
            Self::DoublePrecision => "double precision".to_string(),
            Self::Date => "date".to_string(),
            Self::Time => "time without time zone".to_string(),
            Self::TimeTz => "time with time zone".to_string(),
            Self::Timestamp => "timestamp without time zone".to_string(),
            Self::TimestampTz => "timestamp with time zone".to_string(),
            Self::Interval => "interval".to_string(),
            Self::Uuid => "uuid".to_string(),
            Self::Text => "text".to_string(),
            Self::Name => "name".to_string(),
            Self::CiText => "citext".to_string(),
            Self::CharacterVarying => "character varying".to_string(),
            Self::Character => "character".to_string(),
            // bpchar without typmod stays as-is, otherwise it renders as character(N)
            Self::BpChar => "character".to_string(),
            Self::Unknown => original_fallback.to_string(),
        }
    }

    /// Returns the fixed size of the type in bits, if applicable.
    pub(crate) fn size_bits(&self) -> Option<i32> {
        match self {
            Self::SmallInt => Some(16),
            Self::Integer => Some(32),
            Self::BigInt => Some(64),
            _ => None,
        }
    }

    /// True if the partition strategy synthesis requires casting via text.
    pub(crate) fn requires_text_cast_for_comparison(&self) -> bool {
        matches!(self, Self::CharacterVarying)
    }

    /// Legacy shim for existing calls in apply_relation.rs
    pub(crate) fn from_type_name(name: &str) -> Option<Self> {
        let parsed = ParsedDataType::parse(name);
        if parsed.family == Self::Unknown {
            None
        } else {
            Some(parsed.family)
        }
    }

    /// Legacy shim for existing calls in apply_relation.rs
    pub(crate) fn to_canonical_type_string(self, original: &str) -> String {
        let parsed = ParsedDataType::parse(original);
        parsed.to_string()
    }
}

/// A fully parsed representation of a PostgreSQL data type signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedDataType {
    pub family: DataTypeFamily,
    pub original_base: String,
    pub typmods: Option<String>,
    pub array_dimensions: usize,
}

impl ParsedDataType {
    /// Parses a raw string representation of a type (e.g., `varchar(255)[]`) into its structural components.
    pub(crate) fn parse(raw: &str) -> Self {
        let mut text = Self::fold_unquoted_identifier_case(raw.trim());

        // 1. Extract array dimensions
        let mut array_dimensions = 0;
        while text.ends_with("[]") {
            array_dimensions += 1;
            text = text.strip_suffix("[]").unwrap().trim().to_string();
        }

        // 2. Extract typmods (e.g., (255) or (10, 2))
        let mut typmods = None;
        if let Some(paren_start) = text.find('(')
            && let Some(paren_end) = text.rfind(')')
            && paren_end > paren_start
        {
            // Extract exactly what is between the parentheses
            typmods = Some(text[paren_start + 1..paren_end].trim().to_string());
            text = text[..paren_start].trim().to_string();
        }

        // 3. Resolve the base family
        let family = DataTypeFamily::from_base_name(&text);

        Self {
            family,
            original_base: text,
            typmods,
            array_dimensions,
        }
    }

    fn fold_unquoted_identifier_case(raw: &str) -> String {
        let mut folded = String::with_capacity(raw.len());
        let mut quoted = false;
        let mut chars = raw.chars().peekable();
        while let Some(character) = chars.next() {
            match character {
                '"' if quoted && chars.peek() == Some(&'"') => {
                    folded.push('"');
                    folded.push('"');
                    chars.next();
                }
                '"' => {
                    quoted = !quoted;
                    folded.push(character);
                }
                character if quoted => folded.push(character),
                character => folded.extend(character.to_lowercase()),
            }
        }
        folded
    }

    /// Returns the character limit if this is a bounded character type.
    pub(crate) fn character_limit(&self) -> Option<i32> {
        match self.family {
            DataTypeFamily::CharacterVarying
            | DataTypeFamily::Character
            | DataTypeFamily::BpChar => self.typmods.as_ref().and_then(|mods| mods.parse().ok()),
            _ => None,
        }
    }

    /// Calculates the `atttypmod` offset as represented in PostgreSQL catalogs.
    /// For character types, PostgreSQL adds VARHDRSZ (4) to the declared limit.
    pub(crate) fn atttypmod_offset(&self) -> Option<i32> {
        self.character_limit().map(|limit| limit + 4)
    }

    /// Safely evaluates if migrating from `self` to `new_type` results in irreversible data truncation.
    pub(crate) fn is_lossy_narrowing_to(&self, new_type: &ParsedDataType) -> bool {
        if self.family == new_type.family
            && self.typmods == new_type.typmods
            && self.array_dimensions == new_type.array_dimensions
        {
            return false;
        }

        // Arrays must match dimensions to be compared safely for base narrowing here,
        // though full structural migration handles arrays differently.
        if self.array_dimensions != new_type.array_dimensions {
            return true; // dimension change is inherently destructive/complex
        }

        // 1. Integer Narrowing (e.g., bigint -> int)
        if let (Some(old_sz), Some(new_sz)) = (self.family.size_bits(), new_type.family.size_bits())
        {
            return new_sz < old_sz;
        }

        // 2. Varchar/Text Narrowing
        let old_is_char = matches!(
            self.family,
            DataTypeFamily::CharacterVarying | DataTypeFamily::Text
        );
        let new_is_char = matches!(
            new_type.family,
            DataTypeFamily::CharacterVarying | DataTypeFamily::Text
        );

        if old_is_char && new_is_char {
            match (self.character_limit(), new_type.character_limit()) {
                // Both bounded: lossy if the new limit is strictly smaller
                (Some(old_lim), Some(new_lim)) => return new_lim < old_lim,
                // Unbounded to bounded (text -> varchar(50)) is lossy
                (None, Some(_)) => return true,
                // Bounded to unbounded (varchar(50) -> text) is safe widening
                (Some(_), None) => return false,
                // Unbounded to unbounded (text -> text) is safe
                (None, None) => return false,
            }
        } else if old_is_char {
            // Changing from string to a different type family entirely.
            // If the old string type was bounded, it's definitively lossy to blindly cast
            // to an unrelated type without explicit data assertions.
            if self.character_limit().is_some() {
                return true;
            }
        }

        // Fallback matching legacy safety: Assume other transitions (e.g., timestamp -> date)
        // are handled by specific rules, but do not blanket-flag them as "varchar narrowing".
        false
    }
}

impl fmt::Display for ParsedDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = self.family.to_canonical_string(&self.original_base);

        // PostgreSQL quirk: `char` without limits renders as `character(1)`.
        if self.typmods.is_none() && self.family == DataTypeFamily::Character {
            out.push_str("(1)");
        } else if let Some(ref mods) = self.typmods {
            out.push_str(&format!("({})", mods));
        }

        for _ in 0..self.array_dimensions {
            out.push_str("[]");
        }

        write!(f, "{}", out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_alias_probe_gate() {
        // Assert that every alias maps identically to its PostgreSQL catalog canonical form.
        let cases = vec![
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
        ];

        for (input, expected) in cases {
            let parsed = ParsedDataType::parse(input);
            assert_eq!(
                parsed.to_string(),
                expected,
                "Alias probe failed for input '{}'",
                input
            );
        }
    }

    #[test]
    fn test_lossy_narrowing_detection() {
        let text = ParsedDataType::parse("text");
        let varchar_unbounded = ParsedDataType::parse("character varying");
        let varchar_255 = ParsedDataType::parse("varchar(255)");
        let varchar_50 = ParsedDataType::parse("varchar(50)");

        let int = ParsedDataType::parse("int");
        let bigint = ParsedDataType::parse("bigint");

        // Safe widenings
        assert!(!varchar_50.is_lossy_narrowing_to(&varchar_255));
        assert!(!varchar_50.is_lossy_narrowing_to(&text));
        assert!(!int.is_lossy_narrowing_to(&bigint));

        // Lossy narrowings
        assert!(varchar_255.is_lossy_narrowing_to(&varchar_50));
        assert!(text.is_lossy_narrowing_to(&varchar_255));
        assert!(varchar_unbounded.is_lossy_narrowing_to(&varchar_255));
        assert!(bigint.is_lossy_narrowing_to(&int));
    }
}
