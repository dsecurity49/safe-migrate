// FILE: ./src/ast/identifiers.rs

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ident {
    pub text: String,
    pub quoted: bool,
}

impl Ident {
    pub fn new(text: impl Into<String>, quoted: bool) -> Self {
        Self {
            text: text.into(),
            quoted,
        }
    }

    /// Resolves the identifier exactly as PostgreSQL would:
    /// Quoted identifiers preserve exact casing; unquoted identifiers are case-folded to lowercase.
    pub fn resolve(&self) -> String {
        if self.quoted {
            self.text.clone()
        } else {
            self.text.to_lowercase()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QualifiedName {
    pub schema: Option<Ident>,
    pub name: Ident,
}

impl QualifiedName {
    pub fn new(schema: Option<Ident>, name: Ident) -> Self {
        Self { schema, name }
    }
}

/// ObjectId represents a fully resolved, state-machine tracked database object.
/// By the time an ObjectId is constructed, its schema and name must already be properly case-folded.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectId {
    pub schema: String,
    pub name: String,
}

impl ObjectId {
    pub fn new(schema: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            schema: schema.into(),
            name: name.into(),
        }
    }
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.schema, self.name)
    }
}

