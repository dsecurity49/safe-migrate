# Changelog

All notable changes to safe-migrate are documented here.

## Unreleased

**CLI contract:**

- `lint --json` and `lint-chain --json` now emit exactly one versioned JSON
  report on standard output (`schema_version: 1`); diagnostics are written to
  standard error.
- A completed analysis with one or more Tier 1 findings now exits with status
  `2`. Operational, parser, cache, and configuration failures continue to use
  status `1`.
- `--json` and `--interactive` are now rejected when supplied together.
- Runs without a cache now report `Tainted` confidence while preserving
  conservative worst-case rule evaluation.
- `auto_sync = true` refreshes the cache before `lint` and `lint-chain`.
  Refresh failures now report their cause, retain the prior cache, and continue
  without crashing or deleting the baseline. A retained fresh cache keeps its
  confidence while the JSON baseline records the failed refresh.
- Cache replacement is atomic: a failed sync leaves the previous cache intact.
- Cache provenance (creation time, source database, and selected schemas) is
  stored in new cache files and exposed in the additive JSON `baseline` object.
  `stale_stats_days` now evaluates that recorded creation time.
- `cache_encryption = true` encrypts newly synced cache files using
  XChaCha20-Poly1305 and the environment-only `SAFE_MIGRATE_CACHE_KEY`.
- Schema filters for `sync --schemas` are bound query parameters rather than
  interpolated SQL.
- Remote sync is rejected by this build; use an SSH tunnel and a localhost or
  Unix-socket `DATABASE_URL`. This avoids unsafe transport and keeps the CLI
  portable on Android/Termux.
- Added `scripts/live-differential` and a PostgreSQL 16 CI job that executes
  the previously ignored simulator-vs-PostgreSQL differential harness.

**Documentation:**

- Removed the stale Squawk 2.58.0 AST reference snapshot. AST contributors now
  verify behavior against the exact pinned Squawk source and executable tests.
- Added a documentation index, a v0.4.3 CLI/report contract, and focused
  maintainer guides for architecture invariants and AST development.
- Reworked `CONTRIBUTING.md` to avoid copied file counts, rule inventories, and
  dependency accessor catalogs that become stale.

## v0.4.2

Internal correctness and infrastructure release. Upgraded squawk-parser 2.58.0 → 2.61.0, added `pg_depend`-based dependency tracking, and built a differential test harness that compares simulator output against real PostgreSQL dry-runs across all 26 rules.

**Parser upgrade:**

- squawk-{syntax,lexer,parser} pinned to 2.61.0; squawk-linter removed from dependencies
- Full AST extraction migration to new API: `PathRef`/`NameRef`/`descendants_with_tokens()` replacing direct `Path`/`Name` casts
- `Collate` expression moved from `BinOp::Collate` to `Expr::Collate` variant

**Dependency tracking:**

- `safe-migrate sync` now queries `pg_depend` and builds a `DependencyCache` in the model
- Consolidated 9 ad-hoc graph edge types into unified `DependencyEdge`/`DependencyKind`

**Differential test harness:**

- `tests/live_differential_harness.rs`: compares simulator `MutationResult` against PostgreSQL's actual dry-run outcome
- `live_tests/` expanded with `differential_manifest.json`, `differential_baseline.sql`, and `scripts/live-differential` runner
- Covers all 26 rules with per-rule scope/schema configuration; 0 mismatches in cached mode

**Bug fixes:**

- `DropSchema` without `CASCADE` now returns `MutationResult::Conflict` when the schema still contains relations, types, sequences, functions, or triggers — matching PostgreSQL runtime behavior
- Cache format version (`CACHE_FORMAT_VERSION`) now validated at decode time instead of being a dead constant
- Grant/Revoke role extraction: keyword tokens (`PUBLIC_KW`, `GROUP_KW`) handled via `descendants_with_tokens()` fallback with proper PostgreSQL case-folding (unquoted → lowercase, quoted → preserve case)
- Orphaned `003_drop_func_cascade.sql` fixture removed; restored as `safe_` pattern since `CASCADE` correctly resolves trigger dependencies

**Test suite:**

- 344 unit tests (up from 302); 510 live_tests SQL fixtures pass across all 26 rule directories

## v0.4.1

Correctness and stability release. 5 bugs fixed across the state machine, cache layer, and test suite. Test suite expanded from 235 to 302 tests via a comprehensive integration test modularization (13 new test files under `tests/`). Adds interactive TUI mode, schema-scoped sync, typed operation taxonomy, binary+compressed cache, and FK-dependency violation markers.

**Bug fixes:**

- `CreateType` and `CreateDomain` in the state machine incorrectly used `contains_key` to detect conflicts. After a `DROP TYPE` or `DROP DOMAIN`, the entry remained as `TypeOverlay::Dropped` — `contains_key` still returned `true`, blocking valid re-creation of the same type name. Fixed by checking specifically for `TypeOverlay::Present`.
- `AttachPartition` in the state machine did not call `check_partition_cycle`. Creating a partition cycle (table A is a partition of B, B is attached as a partition of A) would silently corrupt the partition graph instead of being detected. `check_partition_cycle` now runs before each edge is inserted; cycles taint confidence and skip the bad edge.
- `drop(encoder)` in `sync.rs` silently swallowed I/O errors from `zstd::Encoder::auto_finish()` — a disk-full condition could leave a truncated cache file on disk while the atomic rename still succeeded. Replaced with `encoder.finish()?` to propagate write errors.
- `is_lossy_varchar_narrowing` in `destructive.rs` did not handle Postgres's unbounded `atttypmod = -1`. Narrowing from an unbounded `varchar` to a bounded one was incorrectly skipped, missing a class of lossy type changes. Now correctly identifies `atttypmod = -1` as unbounded and fires the violation.
- `fuzz_txn_010_multi_savepoint_chain` test had an incorrect assertion (`!v.is_empty()`) on SQL containing only transaction-control statements and no DDL. No rules fire on pure `BEGIN/SAVEPOINT/ROLLBACK TO/RELEASE/COMMIT` sequences. Corrected to `v.is_empty()` with an explanatory comment.

**New capabilities:**

- `--interactive` / `-i` flag: launches a full-screen TUI (via `crossterm` with `EnterAlternateScreen`/`LeaveAlternateScreen`) showing violations interactively. SQL previews are capped at 5 lines. `TerminalGuard` RAII drop guard ensures terminal state is always restored on early return or panic.
- `--schemas` flag: restricts `safe-migrate sync` to a named set of schemas. Cross-schema FK dependencies are pulled automatically and marked `is_fk_dependency = true` so downstream rules can annotate findings with cross-team impact notes.
- `Violation.fk_dependency_related: bool`: violations on FK-pulled baseline tables now carry this field. Reason strings include a cross-team impact annotation.
- Binary+compressed cache: the on-disk cache is now a `bincode`-serialized `DbCacheVersioned::V1` payload compressed with `zstd` streaming. Replaced the previous JSON format. The JSON `vectorize` module has been removed.
- `OperationKind` and `ObjectKind` enums now have fully typed variants replacing generic `Other`/`Unknown` arms. All 26 rules have been audited and updated to use the correct typed variants.
- `DropType` pipeline: `DROP TYPE` is now fully tracked end-to-end through the AST visitor, fact extractor, mutation resolver, state machine, and drift detection rule.
- `Rename` and `DropType` drift detection arms added to `DriftDetectionRule`.
- `StateCollision(String)` variant in `OpaqueMutation` emits a `schema-drift` Tier 1 violation via the `OpaqueDynamicSqlRule` path when the state machine detects a creation conflict.

**Test suite:**

- 235 → 302 tests. The 5055-line `src/engine/tests.rs` monolith was split into 13 focused integration test files under `tests/` plus `tests/common/mod.rs` for shared helpers.
- New test files: `tests/architectural_gaps.rs` (37 tests), `tests/bug_fixes.rs`, `tests/chain_execution.rs`, `tests/destructive_rules.rs`, `tests/exhaustive_fuzz.rs` (63 tests), and others.
- `live_tests/` integration suite: 532 SQL fixtures with frozen `.safe-migrate.cache`; `run.sh` uses `lint-chain -d` for `chain-conflict` directories and `lint -f` per-file for all others.

**Performance:**

- Column sync loop in `sync.rs` now sorts by schema/table and reuses a cached `*mut RelationState` pointer across columns of the same table, eliminating per-column `ObjectId` heap allocations.
- Violation deduplication in `reporter.rs` replaced an O(N²) nested-loop + string-comparison approach with a zero-copy `HashMap` grouping pass — O(N) with no extra allocations.



## v0.4.0

Major correctness release. 16 bugs fixed across the rule engine, state machine, AST extraction, and output layer. Test suite expanded from 185 to 235 tests. Output format redesigned to be unambiguous and readable.

**Bug fixes:**

- `DropColumn` with `IF EXISTS` on an absent column now correctly returns `MutationResult::Skipped` instead of performing a full drop evaluation. This prevents false-positive `irreversible-migration` violations for no-op DROP COLUMN IF EXISTS. `DropColumn` without `IF EXISTS` on a nonexistent column now marks confidence as `Tainted`.
- Config parsing (`safe-migrate.toml`) now returns an error on invalid or unparseable files, exiting with code 1 instead of silently falling back to defaults.
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
- `PartitionLockRule` (`partition-lock`): Escalated locking severity thresholds (halving the Tier 1 and Tier 2 row count limits) for operations affecting `HASH` partitioned tables since they require more aggressive locking. Appends `[HASH partitioning escalates lock severity]` to the finding reason.
- `DriftDetectionRule` (`schema-drift`): Expanded checks to detect and warn when creating a partition (`CREATE TABLE ... PARTITION OF parent`) if the parent table does not exist in the production baseline.

**Other improvements:**

- `install.sh`: Fixed `detect_linux_flavor()` to correctly identify Termux/Android environments (was broken by a `*:*)` wildcard that matched everything).
- `install.sh`: Added SHA256 checksum download and verification step for release artifacts.
- Release workflow: Added `checksum: sha256` to release artifact generation. Removed `aarch64-pc-windows-msvc` target (no native GitHub Actions runner available).
- CI workflow: Added `--locked` to all `cargo` commands. Added `cargo audit` step for dependency vulnerability scanning.
- `safe-migrate sync`: Added runtime warning when `DATABASE_URL` points to a non-localhost host — the connection is unencrypted by default. Use `sslmode=require` or SSH tunnel for production databases.
- Consolidated duplicate `rowan` dependency: direct dependency downgraded from `0.16.1` to `0.15.18` to match squawk's transitive version.

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
- `partition-strategy-mismatch` — flags `ATTACH PARTITION` operations where the partition table's strategy (RANGE, LIST, or HASH) does not match the parent table's strategy. Mismatched strategies cause runtime failures during partition attachment.

**New capabilities:**

- Multi-file chain execution (`lint-chain --dir`) with state persisting across files
- Same-chain conflict detection via `MutationResult::Conflict`
- Ecosystem coverage: roles, ACLs, functions, triggers, policies, publications, subscriptions all tracked in state machine

**Test suite:** 185 → 235 tests (231 unit + 4 CLI integration). All 16 bug regression tests named `test_findingN_*`.

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
- Multi-platform binary releases (Linux x86_64/ARM64 incl. musl, macOS Intel/Apple Silicon, Windows x86_64)

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
