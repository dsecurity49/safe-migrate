pub mod engine;

#[cfg(test)]
mod tests;

// MigrationFile — the entry point type for the
// engine. Wraps a parsed squawk SourceFile and
// exposes a sequential statement iterator.
//
// INVARIANT: statements() yields Stmt nodes in
// source order. The engine loop MUST process
// them sequentially — no batching, no reordering.

use squawk_syntax::ast::SourceFile;
use squawk_syntax::ast::Stmt;

pub struct MigrationFile {
    source: SourceFile,
}

impl MigrationFile {
    /// Parse raw SQL text into a MigrationFile.
    ///
    /// Bug 1 fix: returns Err if the parser found syntax errors.
    ///
    /// The squawk parser is resilient — SourceFile::parse() always returns
    /// a tree and never panics, even for broken input. Without this check,
    /// the engine would silently analyse a partial/corrupt tree, producing
    /// spurious violations or missing real ones entirely.
    ///
    /// errors() returns a slice of SyntaxError. We convert each to String
    /// for a stable, displayable error type that doesn't carry AST lifetimes.
    pub fn parse(sql: &str) -> Result<Self, Vec<String>> {
        let parsed = SourceFile::parse(sql);

        let errors: Vec<String> = parsed
            .errors()
            .iter()
            .map(|e| e.to_string())
            .collect();

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(Self {
            source: parsed.tree(),
        })
    }

    /// Yields each top-level Stmt in source order.
    /// squawk's SourceFile exposes stmts(), not statements().
    pub fn statements(&self) -> impl Iterator<Item = Stmt> + '_ {
        self.source.stmts()
    }
}
