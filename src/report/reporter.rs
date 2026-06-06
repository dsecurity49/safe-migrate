// src/report/reporter.rs
use crate::report::violations::{Severity, Violation};

#[derive(Debug, Default)]
pub struct Reporter {
    pub violations: Vec<Violation>,
}

impl Reporter {
    pub fn new() -> Self {
        Self {
            violations: Vec::new(),
        }
    }

    /// Emits a new violation
    pub fn report(&mut self, violation: Violation) {
        self.violations.push(violation);
    }

    pub fn has_errors(&self) -> bool {
        self.violations.iter().any(|v| v.severity == Severity::Error)
    }

    /// Flushes all collected violations to standard output.
    pub fn flush(&self) {
        for v in &self.violations {
            let prefix = match v.severity {
                Severity::Error => "[ERROR]",
                Severity::Warning => "[WARN] ",
            };
            println!("{} {}", prefix, v.message);
        }
    }
}
