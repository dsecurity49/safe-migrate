# Changelog

This file summarizes user-visible changes. Implementation details belong in
commits and pull requests. Published binaries, checksums, and generated release
notes are available on the
[GitHub Releases page](https://github.com/dsecurity49/safe-migrate/releases).

## v0.8.0 — 2026-09-03

- Rule evaluation now uses one immutable context with explicit capability
  declarations and scoped evidence for missing catalog or transaction state.
- Cache hydration preserves namespace evidence across typed dependencies,
  publications, constraints, indexes, triggers, and generated/default links.
- Cache V7 records PostgreSQL-selected foreign-key equality operators and
  rejects incomplete proof; validated cache/state constructors keep malformed
  programmatic baselines conservative.
- Large dependency graphs reuse indexed rename and reverse-dependency lookups
  while preserving the existing small-graph behavior.
- Added the supported `safe_migrate::api` Rust façade for configuration, cache,
  analysis, findings, and evidence consumers, including managed analysis helpers
  that validate caches before hydration.
- Cache validation now rejects circular or internally inconsistent role
  membership edges before synchronized state can be treated as authoritative.
- Split GitHub Actions into trusted baseline refresh and offline PR analysis.
  The initializer generates both, environment-scopes database credentials, and
  makes the encrypted baseline mandatory for normal analysis.

## v0.7.0 — 2026-08-30

- Fixed `sync --out <filename>` for bare relative cache filenames and made the
  interactive-mode terminal requirement explicit.
- Added semantic Cache V6 validation and durable cache replacement; invalid
  cache, configuration, rollback, and report state now produces diagnostics.
- Matched PostgreSQL's 63-byte identifier behavior, including UTF-8-safe
  truncation, and added PostgreSQL 17 `MAINTAIN`/`GRANT ALL` support.
- Added inline foreign-key, CHECK, exclusion, and `NOT VALID` constraint state,
  with validation tracking and generated-constraint name reservation.
- Fixed cascade cleanup for foreign keys, views, indexes, triggers, and
  sequence-backed defaults, including cross-schema `DROP SCHEMA ... CASCADE`.
- Made scoped multi-target drops atomic and tightened validation for sequence
  ownership, trigger targets, partition changes, and dependent routines.
- Improved view dependency extraction and catalog filtering, preventing casts,
  function expressions, and unrelated catalog rows from creating false edges.
- Added conservative handling for incomplete baseline evidence, including
  expression indexes, inherited/publication tables, and type rewrite safety.
- Routed unsupported `ALTER TABLE`/type/view/materialized-view actions,
  copied-table forms, unmodeled role options, and incomplete domain/type forms
  to explicit tainted analysis rather than recording an exact no-op.
- Preserved relevant safety findings when an operation is skipped because cache
  evidence is incomplete, including irreversible drops and `WITH GRANT OPTION`.

## v0.6.2 — 2026-08-27

- Added reproducible, ignored performance scenarios for large synchronized
  baselines, ordered chains, transaction and savepoint rollback, compound
  statements, dependency graphs, reports, and the complete protected-cache
  round trip, with a recorded local baseline and no timing-sensitive CI gate.
- Added test-only cache and state invariant validation for modeled identities,
  cache relationships, dependency edges, constraints, pending validation, and
  transaction-frame consistency across conflicts and rollbacks.
- Hardened `ALTER DATABASE ... OWNER TO` extraction so an incomplete typed AST
  is rejected instead of reaching an unchecked accessor, while preserving the
  exact fact produced for valid SQL.

## v0.6.1 — 2026-08-26

- Upgraded the exactly pinned Squawk parser stack from 2.62.0 to 2.63.0 and
  migrated statement extraction to its typed AST children for transaction,
  schema, table, view, sequence, routine, replication, privilege, and session
  statements.
- Adopted Squawk's stricter validation for malformed `IN`/`NOT IN`, empty
  tuples, and `OVERLAPS` expressions, plus its corrected compound-select
  precedence and trailing-clause parsing.
- Added focused regressions for every affected extraction family and the new
  parser-validation behavior.

## v0.6.0 — 2026-08-22

- Expanded `sync` and Cache V6 to record effective migration timeouts, every
  PostgreSQL routine kind, publications, and redacted subscription metadata on
  PostgreSQL 14–18. Connection strings are never read or cached; V1–V5 caches
  must be rebuilt.
- Added rules for missing or ineffective `lock_timeout` and
  `statement_timeout` settings, including changes made within a migration.
- Fixed catalog snapshot consistency and state handling for `search_path`,
  routine identity, publication membership, guarded drops, identifier folding,
  volatile expressions, and ownership. Publication edits with unknown inherited
  tables remain `Tainted`.
- Added GitHub Action support for refreshing and reusing named baselines.
  Pull-request linting stays offline, and cache misses run with `Tainted`
  confidence.

## v0.5.0 — 2026-08-14

- Upgraded the pinned Squawk parser stack to 2.62.0 and raised the minimum
  supported Rust version to 1.94.
- Modeled `ALTER TYPE ... RENAME TO`, `ALTER TYPE ... SET SCHEMA`, and
  `ALTER TRIGGER ... RENAME TO`, including tracked dependent references and
  transaction rollback.
- Treat `COMMENT ON` as a schema-neutral no-op. PostgreSQL 19 property-graph
  syntax and duplicate DML assignments parse successfully but remain explicitly
  opaque, preserving conservative analysis.
- Added `safe-migrate rules` discovery and richer terminal, Markdown, JSON, and
  GitHub Action findings with rule metadata and statement indexes.
- Preserved compatibility: JSON remains schema version 1 and the Cache V5
  format is unchanged.

## v0.4.5 — 2026-08-08

- Introduced Cache V5 with authoritative synchronized schema and sequence
  catalogs, sequence owner/ownership/kind metadata, redacted inspect counts,
  scoped-catalog boundaries, and a required resync from V1–V4.
- Modeled schema authorization, ownership, duplicate/missing behavior,
  restrict/cascade removal, atomic namespace rename, search-path recomputation,
  baseline provenance remapping, and transaction/savepoint rollback.
- Modeled standalone, owned, serial-like, and identity sequence lifecycles,
  including `OWNED BY`, owner/rename/schema changes, implicit PostgreSQL-style
  sequence names and defaults, ownership updates, dependent drops, and rollback.
- Made the GitHub Action use checksum-verified exact release binaries for
  immutable refs, add job summaries and Tier 1/2 annotations, preserve all
  report artifacts, and support optional advisory gating without hiding exit
  code `2` or operational failures.
- Added Windows/MSYS `.zip` support to the existing installer while retaining
  Linux, macOS, GNU, musl, Termux, exact-version, curl-pipe, and dry-run paths.

## v0.4.4 — 2026-08-02

- Added sourced differential cases for staged foreign-key
  validation, missing foreign-key columns, and index-backed constraints.
- Corrected constraint fixtures that previously reused CHECK statements under
  UNIQUE, PRIMARY KEY, and exclusion filenames.
- Modeled `NOT VALID` foreign keys, later validation, exclusion and primary-key
  constraint state, and `UNIQUE ... USING INDEX` without a false blocking-index
  finding.
- Preserved PostgreSQL constraint names and tightened `USING INDEX` resolution
  and eligibility checks for indexes created within a migration.
- Modeled ordered enum labels from `CREATE TYPE ... AS ENUM` and PostgreSQL-
  compatible `ALTER TYPE ... RENAME VALUE` behavior, including search-path
  resolution, conflicts, quoted labels, and transaction rollback.
- Added differential assertions for expected PostgreSQL errors, including the
  exact SQLSTATE and the safe-migrate rule that must predict the rejection.
- Added role-sensitive chain analysis for `SET ROLE`, transaction-local role
  settings, session authorization, `$user` search paths, grants, and relation
  ownership. V4 caches include effective/session identities and role
  memberships so missing or unauthorized switches match PostgreSQL behavior.
- Added live PostgreSQL differential coverage for role transaction semantics,
  session resets and rollback, ownership, quoted role names, dynamic search
  paths, transitive role memberships, PostgreSQL 16+ `SET OPTION`, and rejected
  role switches.
- Added headered V4 caches for the expanded role/search-path provenance.
  Headered V3 caches remain readable; older formats now require
  `safe-migrate sync` and are rejected without internal version labels.
- Added a redacted role count to `cache inspect`; role names and membership
  edges remain omitted from inspection output.

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
