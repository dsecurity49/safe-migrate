// src/report/violation.rs

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub severity: Severity,
    pub message: String,
    // Future: pub span: TextRange (to map back to the SQL text)
}

impl Violation {
    pub fn new(severity: Severity, message: impl Into<String>) -> Self {
        Self {
            severity,
            message: message.into(),
        }
    }
}
