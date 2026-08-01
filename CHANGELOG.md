# Changelog

This file summarizes user-visible changes. Implementation details belong in
commits and pull requests. Published binaries, checksums, and generated release
notes are available on the
[GitHub Releases page](https://github.com/dsecurity49/safe-migrate/releases).

## v0.4.4 — Unreleased

- Added sourced, real-world-inspired differential cases for staged foreign-key
  validation, missing foreign-key columns, and index-backed constraints.
- Corrected constraint fixtures that previously reused CHECK statements under
  UNIQUE, PRIMARY KEY, and exclusion filenames.
- Modeled `NOT VALID` foreign keys, later validation, exclusion and primary-key
  constraint state, and `UNIQUE ... USING INDEX` without a false blocking-index
  finding.
- Added differential assertions for expected PostgreSQL errors, including the
  exact SQLSTATE and the safe-migrate rule that must predict the rejection.

## v0.4.3 — 2026-07-30

Reliability and trust-contract release.

- Added deterministic Markdown reports, source locations in machine-readable
  reports, cache inspection, a reusable GitHub Action, and configuration-only
  automatic cache synchronization.
- Added optional authenticated cache encryption using
  `SAFE_MIGRATE_CACHE_KEY`. Cache writes and refreshes are atomic; failed
  refreshes preserve and reuse the previous readable cache.
- Reset cache storage to the headered V3 format. V1 and V2 remain readable;
  v0.4.2 caches must be rebuilt with `safe-migrate sync`.
- Clarified report semantics: Tier 1 findings exit with status `2`, operational
  failures use `1`, missing or stale baselines taint confidence, and clean
  reports no longer imply that deployment is guaranteed safe.
- Hardened transaction/savepoint simulation, statement atomicity, object
  lifecycle and namespace handling, trigger identity, schema-scoped evidence,
  unsupported SQL handling, configuration validation, and Markdown escaping.
- Hardened distribution: the installer verifies release checksums, the GitHub
  Action does not trust checkout-local caches by default, and release tags must
  match the Cargo package version.
- Direct remote database synchronization is rejected; use localhost, a Unix
  socket, or an SSH tunnel.
- Expanded live validation with automatic-sync and encryption contracts plus a
  differential harness covering all 26 rule groups.

## v0.4.2

Parser and dependency-model update.

- Upgraded and pinned the Squawk parser stack from 2.58.0 to 2.61.0.
- Added `pg_depend` synchronization and consolidated dependency graph handling.
- Added the PostgreSQL differential harness and explicit fixture accounting for
  all 26 rule groups.
- Fixed schema-drop conflict modeling, cache-version validation, and
  grant/revoke identifier extraction.

## v0.4.1

State-model and usability release.

- Added the interactive terminal UI and schema-scoped synchronization.
- Introduced the compressed, versioned binary cache and cross-schema foreign-key
  dependency annotations.
- Added typed operation/object reporting and complete `DROP TYPE` tracking.
- Fixed type/domain recreation, partition-cycle rejection, rollback-safe cache
  writes, and unbounded `varchar` narrowing detection.

## v0.4.0

Major rule-engine and reporting release.

- Added ordered `lint-chain` analysis with retained schema state and conflict
  detection.
- Added the four-way verdict report, deterministic ordering, grouped findings,
  color control, and clearer SQL/object presentation.
- Added rules for destructive and irreversible operations, drift, trigger and
  function dependencies, row-level security, grants, database drops, and
  partition strategy conflicts.
- Corrected no-op handling, configuration failures, transaction confidence
  rollback, function/trigger identity, volatile-expression classification, and
  dependency cleanup.
- Added checksum verification to binary installation and locked/audited CI
  builds.

## v0.3.2

- Upgraded and pinned Squawk to 2.58.0, adapting expression extraction to its
  AST changes.

## v0.3.1

- Fixed fresh `cargo install` builds by pinning the compatible Squawk release.
  No runtime behavior changed.

## v0.3.0

State-machine rewrite.

- Replaced one-statement inspection with schema simulation covering
  transactions, rollback, cascading drops, partitions, renames, and
  dependencies.
- Added live PostgreSQL metadata/statistics synchronization, confidence
  reporting, per-rule configuration, ignore directives, and multi-platform
  binary releases.

## v0.2.1

- Stopped printing `DATABASE_URL` during synchronization and fixed installer
  file-check behavior.

## v0.2.0

- Replaced string matching with typed Squawk AST parsing.
- Split the original single-file program into dedicated AST, analysis, model,
  rule, configuration, and synchronization modules.
- Added index-to-table cache mapping, conservative handling of unknown table
  sizes, cache-corruption errors, and per-rule thresholds.

## v0.1.0

- Initial CLI with PostgreSQL row-count synchronization and a basic migration
  risk rule set.
