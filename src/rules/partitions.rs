// src/rules/partitions.rs
//
// Partition safety rules — not yet implemented.
//
// Planned checks:
//   - ATTACH PARTITION without prior constraint validation
//   - DETACH PARTITION leaving orphaned child tables
//   - Partition key type mismatch on ALTER TABLE
