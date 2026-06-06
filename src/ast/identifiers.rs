/// Represents a raw identifier directly from the AST.
/// This is strictly syntactic and should NEVER be used for state lookups.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QualifiedName {
    pub schema: Option<String>,
    pub name: String,
}

impl QualifiedName {
    pub fn new(schema: Option<impl Into<String>>, name: impl Into<String>) -> Self {
        Self {
            schema: schema.map(|s| s.into()),
            name: name.into(),
        }
    }
}
