# Changelog

All notable changes to safe-migrate are documented here.

## v0.3.2

Official support for `squawk-syntax` v2.58.0. 

- Unpinned the `squawk-syntax` dependency from `=2.56.0` and updated the expression visitor to handle upstream breaking AST changes. 
- `CallExpr` argument lists are now correctly mapped through the newly introduced `Arg` struct wrapper, and the `BinOp::Escape` variant is now exhaustively handled.
- This ensures `cargo install safe-migrate` works natively with the latest parser ecosystem out-of-the-box without requiring the `--locked` flag.

## v0.3.1

Hotfix for a broken `cargo install` on v0.3.0.

- Pinned `squawk-syntax` to `=2.56.0`. v0.3.0 was published with a loose version requirement that allowed `squawk-syntax 2.58.0` to be pulled in on fresh installs, which introduced a new `BinOp::Escape` variant and a changed `Arg`/`Expr` relationship in `CallExpr` argument lists that the v0.3.0 source didn't account for. This broke compilation for anyone running `cargo install safe-migrate` after `2.58.0` was published, even though the code in the v0.3.0 tag itself was correct against `2.56.0`.
- No functional or rule changes. If you built v0.3.0 from source before `squawk-syntax 2.58.0` was published, your binary is unaffected.

## v0.3.0

Complete internal rewrite of the analysis engine. safe-migrate no longer just parses migrations — it runs a full state machine simulation of the migration against a model of the schema, including transactions, cascading drops, and partition hierarchies.

**Architectural fixes:**

- Transaction rollback (`BEGIN ... ROLLBACK`) now fully restores prior schema state, including internal counters and pending-validation tracking that previously leaked across rollback boundaries
- `DROP TABLE ... CASCADE` is now evaluated against the actual dependency graph (foreign keys, views, partitions) instead of just the named table
- Partition parent/child relationships are now correctly walked in both directions, so dropping a partitioned parent table correctly accounts for its children
- Table renames are now tracked so foreign key and index references resolve correctly later in the same migration, instead of pointing at stale names
- `search_path` resolution now checks that a schema actually exists before using it, instead of silently assuming the first entry is valid
- Non-cascading drops now correctly detect and block on dependent objects instead of allowing a drop that would fail at runtime

**Other fixes:**

- Dozens of smaller fixes across AST extraction (edge cases in constraint, sequence, and partition parsing), identifier normalization (quoting and case-folding), and rule threshold logic (stale-statistics handling no longer suppresses real violations on small/empty tables)
- Version-gating corrected for PG11+ constant `DEFAULT` clauses on `ADD COLUMN`

**New:**

- Live database statistics sync (`safe-migrate sync`) pulling table sizes, column widths, foreign keys, indexes, triggers, and policies from PostgreSQL catalogs
- Confidence reporting (`Exact` vs `Tainted`) when dynamic/opaque SQL is detected
- Per-rule configuration overrides via `safe-migrate.toml`
- Inline ignore directives (`-- safe-migrate: ignore(...)`, `-- safe-migrate: ignore-file(...)`)
- 78-test suite covering the simulator, rule engine, and CLI
- Multi-platform binary releases (Linux x86_64/ARM64 incl. musl, macOS Intel/Apple Silicon, Windows x86_64/ARM64)

## v0.2.0

Rewrote SQL parsing to use a typed AST instead of string matching.

- Replaced regex/substring-based table extraction with `squawk_syntax`, fixing breakage on quoted identifiers (`"WeirdTable"`), schema-qualified names (`public.users`), and other non-trivial SQL
- Split the codebase from a single `main.rs` into proper modules (`ast`, `rules`, `config`, `sync`, `resolve`, `model`)
- `sync` now maps indexes to their parent tables, so `DROP INDEX` correctly looks up the row count of the table it belongs to instead of failing closed on an unknown table
- Unanalyzed tables (`reltuples = -1`) are now treated as maximally large rather than silently passing
- Cache corruption and missing cache are now handled as distinct cases — a corrupted stats file no longer silently falls back to an empty cache and lets everything through
- Added per-rule threshold overrides in `safe-migrate.toml`

## v0.1.0

Initial release.

- CLI that compares migration SQL against synced row counts from `pg_class` to flag potentially blocking locks
- Basic rule set for common dangerous patterns (adding columns with defaults, non-concurrent index operations, type changes)
- String/substring-based SQL parsing
