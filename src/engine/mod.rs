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
    pub fn parse(sql: &str) -> Option<Self> {
        let parsed = SourceFile::parse(sql);
        Some(Self {
            source: parsed.tree(),
        })
    }

    /// Yields each top-level Stmt in source order.
    /// squawk's SourceFile exposes stmts(), not statements().
    pub fn statements(&self) -> impl Iterator<Item = Stmt> + '_ {
        self.source.stmts()
    }
}
