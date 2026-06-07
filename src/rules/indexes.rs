// src/rules/indexes.rs
//
// Index safety rules — not yet implemented.
//
// Planned checks:
//   - CONCURRENTLY flag missing on CREATE INDEX in a live migration
//   - Dropping an index that is still referenced by a constraint
//   - Duplicate index detection
