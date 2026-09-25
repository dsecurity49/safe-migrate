use std::fmt;

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
    // Unrecognised type — callers must taint or diagnose rather than assume safe.
    Unknown,
}

impl DataTypeFamily {
    // Single alias table. All PostgreSQL spellings for a built-in type map here.
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

    // Returns the canonical catalog spelling; Unknown round-trips through original_fallback.
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
            Self::BpChar => "character".to_string(),
            Self::Unknown => original_fallback.to_string(),
        }
    }

    // Fixed storage size in bits for integer families; None for everything else.
    pub(crate) fn size_bits(self) -> Option<i32> {
        match self {
            Self::SmallInt => Some(16),
            Self::Integer => Some(32),
            Self::BigInt => Some(64),
            _ => None,
        }
    }

    pub(crate) fn is_text_like(self) -> bool {
        matches!(
            self,
            Self::CharacterVarying | Self::Character | Self::BpChar | Self::Text
        )
    }

    pub(crate) fn is_numeric(self) -> bool {
        matches!(self, Self::Numeric)
    }

    // Partition synthesiser must cast varchar keys through ::text for byte-identical comparison.
    pub(crate) fn requires_text_cast_for_comparison(self) -> bool {
        matches!(self, Self::CharacterVarying)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedDataType {
    pub family: DataTypeFamily,
    pub original_base: String,
    pub typmods: Option<String>,
    pub array_dimensions: usize,
}

impl ParsedDataType {
    pub(crate) fn parse(raw: &str) -> Self {
        let mut text = Self::fold_unquoted_identifier_case(raw.trim());

        let mut array_dimensions = 0;
        while text.ends_with("[]") {
            array_dimensions += 1;
            text = text.strip_suffix("[]").unwrap().trim().to_string();
        }

        // rfind so nested parens in unusual type expressions don't truncate the typmod.
        let mut typmods = None;
        if let Some(open) = text.find('(')
            && let Some(close) = text.rfind(')')
            && close > open
        {
            typmods = Some(text[open + 1..close].trim().to_string());
            text = text[..open].trim().to_string();
        }

        let family = DataTypeFamily::from_base_name(&text);
        Self { family, original_base: text, typmods, array_dimensions }
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

    // Character limit for bounded character types. None for unbounded and non-character families.
    pub(crate) fn character_limit(&self) -> Option<i32> {
        match self.family {
            DataTypeFamily::CharacterVarying
            | DataTypeFamily::Character
            | DataTypeFamily::BpChar => self.typmods.as_ref().and_then(|m| m.parse().ok()),
            _ => None,
        }
    }

    // PostgreSQL stores atttypmod as character_limit + VARHDRSZ (4) for bounded char types.
    pub(crate) fn atttypmod_offset(&self) -> Option<i32> {
        self.character_limit().map(|limit| limit + 4)
    }

    // Precision and scale for numeric(p, s). numeric(p) returns Some((p, 0)); bare numeric returns None.
    pub(crate) fn numeric_params(&self) -> Option<(i32, i32)> {
        if self.family != DataTypeFamily::Numeric {
            return None;
        }
        let mods = self.typmods.as_deref()?;
        let mut parts = mods.splitn(2, ',');
        let precision: i32 = parts.next()?.trim().parse().ok()?;
        let scale: i32 = parts
            .next()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        Some((precision, scale))
    }

    // Scale from numeric(p, s). None when scale is not explicitly declared.
    pub(crate) fn numeric_scale(&self) -> Option<u32> {
        if self.family != DataTypeFamily::Numeric {
            return None;
        }
        let mods = self.typmods.as_deref()?;
        let scale_str = mods.split(',').nth(1)?.trim();
        scale_str.parse().ok()
    }

    // Renders as pg_catalog.format_type(oid, NULL) for function-signature identity keys.
    // Unlike Display, does NOT add the implicit (1) for bare character/char.
    pub(crate) fn to_function_signature_string(&self) -> String {
        let mut out = self.family.to_canonical_string(&self.original_base);
        if let Some(ref mods) = self.typmods {
            out.push_str(&format!("({})", mods));
        }
        for _ in 0..self.array_dimensions {
            out.push_str("[]");
        }
        out
    }

    pub(crate) fn is_lossy_narrowing_to(&self, new_type: &ParsedDataType) -> bool {
        if self.family == new_type.family
            && self.typmods == new_type.typmods
            && self.array_dimensions == new_type.array_dimensions
        {
            return false;
        }

        // Any change in array dimensionality is structurally incompatible.
        if self.array_dimensions != new_type.array_dimensions {
            return true;
        }

        if let (Some(old_bits), Some(new_bits)) =
            (self.family.size_bits(), new_type.family.size_bits())
        {
            return new_bits < old_bits;
        }

        let old_is_string = self.family.is_text_like();
        let new_is_string = new_type.family.is_text_like();

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

impl fmt::Display for ParsedDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = self.family.to_canonical_string(&self.original_base);

        // Bare char/character in DDL means character(1) per the SQL standard.
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
        ];
        for (input, expected) in cases {
            let parsed = ParsedDataType::parse(input);
            assert_eq!(parsed.to_string(), expected, "failed for '{input}'");
        }
    }

    #[test]
    fn function_signature_string_no_implicit_char_width() {
        // pg_catalog.format_type returns "character" bare (no typmod) for bpchar/char.
        // Function identity keys must match that; Display must not be used here.
        assert_eq!(ParsedDataType::parse("char").to_function_signature_string(), "character");
        assert_eq!(ParsedDataType::parse("character").to_function_signature_string(), "character");
        assert_eq!(ParsedDataType::parse("char(10)").to_function_signature_string(), "character(10)");
        assert_eq!(ParsedDataType::parse("bpchar").to_function_signature_string(), "character");
        assert_eq!(ParsedDataType::parse("int").to_function_signature_string(), "integer");
        assert_eq!(ParsedDataType::parse("varchar(50)").to_function_signature_string(), "character varying(50)");
    }

    #[test]
    fn lossy_narrowing_integer() {
        let s = ParsedDataType::parse("smallint");
        let i = ParsedDataType::parse("integer");
        let b = ParsedDataType::parse("bigint");
        assert!(!s.is_lossy_narrowing_to(&i));
        assert!(!i.is_lossy_narrowing_to(&b));
        assert!(b.is_lossy_narrowing_to(&i));
        assert!(i.is_lossy_narrowing_to(&s));
    }

    #[test]
    fn lossy_narrowing_character() {
        let text = ParsedDataType::parse("text");
        let vc_unb = ParsedDataType::parse("character varying");
        let vc255 = ParsedDataType::parse("varchar(255)");
        let vc50 = ParsedDataType::parse("varchar(50)");
        assert!(!vc50.is_lossy_narrowing_to(&vc255));
        assert!(!vc50.is_lossy_narrowing_to(&text));
        assert!(vc255.is_lossy_narrowing_to(&vc50));
        assert!(text.is_lossy_narrowing_to(&vc255));
        assert!(vc_unb.is_lossy_narrowing_to(&vc255));
    }

    #[test]
    fn lossy_narrowing_array_dimension_change() {
        let i = ParsedDataType::parse("integer");
        let ia = ParsedDataType::parse("integer[]");
        assert!(i.is_lossy_narrowing_to(&ia));
        assert!(ia.is_lossy_narrowing_to(&i));
    }

    #[test]
    fn numeric_params_extraction() {
        assert_eq!(ParsedDataType::parse("numeric").numeric_params(), None);
        assert_eq!(ParsedDataType::parse("numeric(10)").numeric_params(), Some((10, 0)));
        assert_eq!(ParsedDataType::parse("numeric(10, 2)").numeric_params(), Some((10, 2)));
        assert_eq!(ParsedDataType::parse("decimal(5,3)").numeric_params(), Some((5, 3)));
        assert_eq!(ParsedDataType::parse("integer").numeric_params(), None);
    }

    #[test]
    fn numeric_scale_extraction() {
        assert_eq!(ParsedDataType::parse("numeric").numeric_scale(), None);
        assert_eq!(ParsedDataType::parse("numeric(10)").numeric_scale(), None);
        assert_eq!(ParsedDataType::parse("numeric(10,2)").numeric_scale(), Some(2));
    }

    #[test]
    fn character_limit_and_atttypmod() {
        let v50 = ParsedDataType::parse("varchar(50)");
        assert_eq!(v50.character_limit(), Some(50));
        assert_eq!(v50.atttypmod_offset(), Some(54));
        assert_eq!(ParsedDataType::parse("text").character_limit(), None);
    }
}
