// FILE: src/engine/mod.rs
#![allow(clippy::module_inception)]

pub mod config;
pub mod engine;

#[cfg(test)]
mod tests;

use squawk_syntax::ast::SourceFile;
use squawk_syntax::ast::Stmt;

/// Represents a parsed SQL migration file.
/// Retained for backward compatibility with CLI wrappers.
pub struct MigrationFile {
    source: SourceFile,
}

impl MigrationFile {
    pub fn parse(sql: &str) -> Result<Self, Vec<String>> {
        let parsed = SourceFile::parse(sql);
        let errors: Vec<String> = parsed.errors().iter().map(|e| e.to_string()).collect();

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(Self {
            source: parsed.tree(),
        })
    }

    pub fn statements(&self) -> impl Iterator<Item = Stmt> + '_ {
        self.source.stmts()
    }
}
