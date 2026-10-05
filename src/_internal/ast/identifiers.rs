use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct Ident {
    pub text: String,
    pub quoted: bool,
}

impl Ident {
    pub(crate) fn new(text: impl Into<String>, quoted: bool) -> Self {
        Self {
            text: text.into(),
            quoted,
        }
    }

    /// Returns the lookup spelling used by PostgreSQL and the analyzer. Quoted
    /// identifiers preserve case, unquoted identifiers are folded, and both are
    /// clipped to PostgreSQL's default `NAMEDATALEN - 1` byte limit without
    /// splitting a UTF-8 code point.
    pub(crate) fn resolve(&self) -> String {
        let resolved = if self.quoted {
            self.text.clone()
        } else {
            self.text.to_ascii_lowercase()
        };
        truncate_postgres_identifier(&resolved).to_string()
    }
}

fn truncate_postgres_identifier(value: &str) -> &str {
    const MAX_IDENTIFIER_BYTES: usize = 63;

    let mut end = value.len().min(MAX_IDENTIFIER_BYTES);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct QualifiedName {
    pub schema: Option<Ident>,
    pub name: Ident,
}

impl QualifiedName {
    pub(crate) fn new(schema: Option<Ident>, name: Ident) -> Self {
        Self { schema, name }
    }
}

#[cfg(test)]
mod tests {
    use super::Ident;

    #[test]
    fn identifiers_follow_postgresql_byte_truncation() {
        let ascii = "A".repeat(70);
        assert_eq!(Ident::new(ascii, false).resolve(), "a".repeat(63));

        let quoted = format!("{}suffix", "é".repeat(32));
        let resolved = Ident::new(quoted, true).resolve();
        assert_eq!(resolved.len(), 62);
        assert_eq!(resolved, "é".repeat(31));
    }

    #[test]
    fn object_id_requires_explicit_inference_marker_when_deserialized() {
        let payload = serde_json::json!({"schema": "public", "name": "items"});
        assert!(serde_json::from_value::<super::ObjectId>(payload).is_err());
    }
}

/// ObjectId represents a fully resolved, state-machine tracked database object.
/// Its schema and name must already use their resolved lookup spelling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ObjectId {
    pub schema: String,
    pub name: String,
    pub inferred_schema: bool,
}

impl PartialEq for ObjectId {
    fn eq(&self, other: &Self) -> bool {
        self.schema == other.schema && self.name == other.name
    }
}

impl Eq for ObjectId {}

impl ObjectId {
    /// Total order over identity, for use inside ordered collections.
    pub(crate) fn cmp_identity(&self, other: &Self) -> std::cmp::Ordering {
        self.schema
            .cmp(&other.schema)
            .then_with(|| self.name.cmp(&other.name))
    }
}

impl std::hash::Hash for ObjectId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.schema.hash(state);
        self.name.hash(state);
    }
}

impl ObjectId {
    pub(crate) fn new(schema: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            schema: schema.into(),
            name: name.into(),
            inferred_schema: false,
        }
    }

    /// A column of this relation, as `schema.relation.column`.
    ///
    /// The inferred-schema annotation belongs to the relation and stays at the
    /// end, so it never lands inside the qualified name.
    ///
    /// TODO: `Violation::object_name` is still a `String`, so callers assemble
    /// identities by interpolation. Replace it with a structured object
    /// reference (relation plus optional column) and let the renderers format
    /// it, which removes this whole class of mis-rendered identifier.
    pub(crate) fn column_name(&self, column: &str) -> String {
        if self.inferred_schema {
            format!("{}.{}.{} (inferred)", self.schema, self.name, column)
        } else {
            format!("{}.{}.{}", self.schema, self.name, column)
        }
    }
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.inferred_schema {
            write!(f, "{}.{} (inferred)", self.schema, self.name)
        } else {
            write!(f, "{}.{}", self.schema, self.name)
        }
    }
}
