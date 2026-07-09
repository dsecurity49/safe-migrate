# Changelog

All notable changes to safe-migrate are documented here.

## v0.4.0

Major correctness release. 14 bugs fixed across the rule engine, state machine, AST extraction, and output layer. Test suite expanded from 185 to 227 tests. Output format redesigned to be unambiguous and readable.

**Bug fixes:**

- `VacuumFullRule` showed `<vacuum>` as the object name instead of the actual table being vacuumed. Now correctly resolves and displays the table ObjectId.
- `now()` and `current_timestamp` were incorrectly classified as VOLATILE. They are STABLE — they return the transaction start time, the same value for every row within one statement. This caused false positive table-rewrite warnings on `ALTER TABLE ... ADD COLUMN ... DEFAULT NOW()` on PG11+.
- `BrokenComputeRule` was completely silent. The function_id constructed at drop time never matched the one stored at trigger-creation time, so the lookup always returned empty. Fixed by normalizing function_id construction to use a consistent signature format at both sites.
- `ConcurrentInsideTransactionRule` fired on `CREATE INDEX IF NOT EXISTS CONCURRENTLY` when the index already existed and the mutation was skipped. Added `MutationResult::Skipped` guard.
- `CreateTableAsSelectRule` fired on `CREATE TABLE IF NOT EXISTS t AS SELECT ...` when the table already existed and the mutation was skipped. Added `MutationResult::Skipped` guard.
- Missing `MutationResult::Skipped` guards added to `OverbroadGrantRule`, `BrokenComputeRule`, `RestrictivePolicyRule`, `DisableTriggerRule`, `FunctionVolatilityRule`.
- `PendingValidationSnapshot` `StateChange` variant existed but `snapshot_pending_validation()` was never implemented. Implemented defensively.
- `AlterColumnOption::SetStorage` was detected via fragile string matching before the main match statement. Replaced with a proper enum arm.
- Confidence was not restored on `ROLLBACK`. `Mutation::Opaque` set confidence to `Tainted` without snapshotting the previous value. After `ROLLBACK`, confidence stayed `Tainted` permanently, causing all subsequent Tier 1 violations in the same run to be silently downgraded to Tier 2. Fixed by adding `StateChange::ConfidenceSnapshot` to the undo-log and restoring in `rollback_frame()`.
- `DROP SCHEMA CASCADE` cleaned FK, view, index, partition, sequence, and rename edges but not trigger and publication edges. Stale trigger edges caused `BrokenComputeRule` to produce false positive violations after schema drops. Fixed by adding the missing `retain` calls and snapshot functions for both edge types.

**Output redesign:**

- New structured header box (filename, verdict, confidence, counts) before findings
- Per-finding blocks with consistent `object :`, `reason :`, `recipe :`, `sql :` field alignment
- `object :` shows object type (`table`, `index`, `view`, `function`) separately from the name
- Four-way verdict system: `HALT`, `CAUTIOUS`, `SAFE WITH RISK`, `SAFE`
- Same-source-range grouping — multiple violations on the same SQL grouped under one block with `also :` secondary lines
- Proportional separator between findings (≈77% of terminal width), narrower than full-width header/summary boxes
- Color on tier labels only via `owo-colors`. `NO_COLOR` environment variable respected
- `[DOWNGRADED]` tag removed from reason fields — header confidence level carries this information
- Deterministic violation ordering: `tier → source_range → object → rule_id`

**New rules:**

- `overbroad-grant` — flags `GRANT ... TO PUBLIC` and `GRANT ALL PRIVILEGES` to non-owner roles
- `broken-compute` — flags dropping a function that backs a trigger
- `drop-database` — flags `DROP DATABASE` in migration files
- `schema-drift` — flags migrations referencing tables absent from the production baseline
- `irreversible-migration` — classifies DROP COLUMN, DROP TABLE, lossy type changes as irreversible with row-count gating
- `restrictive-policy` — flags RLS policies that could unexpectedly restrict access
- `disable-trigger` — flags `ALTER TABLE ... DISABLE TRIGGER ALL` in migrations
- `chain-conflict` — flags same-chain migrations adding the same column with different types

**New capabilities:**

- Multi-file chain execution (`lint-chain --dir`) with state persisting across files
- Same-chain conflict detection via `MutationResult::Conflict`
- Ecosystem coverage: roles, ACLs, functions, triggers, policies, publications, subscriptions all tracked in state machine

**Test suite:** 185 → 227 tests (223 unit + 4 CLI integration). All 14 bug regression tests named `test_bugNNN_*`.

## v0.3.2

Properly upgraded to `squawk_syntax` 2.58.0 and fixed the two compile errors introduced by the upgrade:

- `BinOp::Escape(SyntaxToken)` — new variant added to `BinOp` enum, now handled in `expr_visitor.rs`
- `CallExpr` argument list changed from `AstChildren<Expr>` to `AstChildren<Arg>`, requiring `.filter_map(|arg| arg.expr())`

Also pinned `squawk-syntax = "=2.58.0"` to prevent future silent upgrades from breaking the build.

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

- Dozens of smaller fixes across AST extraction, identifier normalization, and rule threshold logic

**New:**

- Live database statistics sync (`safe-migrate sync`) pulling table sizes, column widths, foreign keys, indexes, triggers, and policies from PostgreSQL catalogs
- Confidence reporting (`Exact` vs `Tainted`) when dynamic/opaque SQL is detected
- Per-rule configuration overrides via `safe-migrate.toml`
- Inline ignore directives (`-- safe-migrate: ignore(...)`, `-- safe-migrate: ignore-file(...)`)
- 78-test suite covering the simulator, rule engine, and CLI
- Multi-platform binary releases (Linux x86_64/ARM64 incl. musl, macOS Intel/Apple Silicon, Windows x86_64/ARM64)

## v0.2.0

Rewrote SQL parsing to use a typed AST instead of string matching.

- Replaced regex/substring-based table extraction with `squawk_syntax`, fixing breakage on quoted identifiers, schema-qualified names, and other non-trivial SQL
- Split the codebase from a single `main.rs` into proper modules (`ast`, `rules`, `config`, `sync`, `resolve`, `model`)
- `sync` now maps indexes to their parent tables, so `DROP INDEX` correctly looks up the row count of the table it belongs to instead of failing closed on an unknown table
- Unanalyzed tables (`reltuples = -1`) are now treated as maximally large rather than silently passing
- Cache corruption and missing cache are now handled as distinct cases
- Added per-rule threshold overrides in `safe-migrate.toml`

## v0.1.0

Initial release.

- CLI that compares migration SQL against synced row counts from `pg_class` to flag potentially blocking locks
- Basic rule set for common dangerous patterns
- String/substring-based SQL parsing
