# Changelog

This file summarizes user-visible changes. Implementation details belong in
commits and pull requests. Published binaries, checksums, and generated release
notes are available on the
[GitHub Releases page](https://github.com/dsecurity49/safe-migrate/releases).

## v0.7.0 — 2026-08-30

- Made Cache V6 loading and writing reject semantically inconsistent metadata
  (including mismatched identities and dangling catalog relationships), and
  made cache installation durable after its atomic replacement.
- Preserved report locations while reusing the parser result already needed to
  calculate statement ranges; the local 250-statement location-report scenario
  improved from 922 ms to a 235 ms median in the optimized profile.
- Strengthened rollback, savepoint, graph, cache, and serialized-report
  contracts with deterministic regression coverage. Invalid internal
  savepoint data, automatic-sync configuration, and report serialization now
  produce diagnostics rather than unchecked failures.
- Expanded release readiness checks to cover the frozen fixture suite, package
  contents, Rust 1.94, and supported operating systems.
- Matched PostgreSQL's 63-byte identifier truncation for quoted and unquoted
  names, including UTF-8-safe clipping, namespace conflicts, routine aliases,
  and generated-name differential coverage.
- Added PostgreSQL 17 relation-ACL support for `MAINTAIN`, including
  version-aware `GRANT ALL` expansion and typed grant/revoke extraction.
- Hardened migration-state validation for dependent relation, routine, foreign
  key, partition, index, trigger, policy, view, and privilege targets, with
  conservative tainting for incomplete scoped baselines.
- Corrected view replacement metadata and `DROP VIEW`/`DROP MATERIALIZED VIEW`
  dependency cleanup, removed stale relation edges after table drops, and
  stopped unsupported domain, sequence, and role transitions from claiming
  exact state.
- Tightened sequence ownership and trigger target validation, and tainted
  cascades that remove relations omitted from a scoped baseline.
- Restricted view dependency discovery to relation-name AST nodes, avoiding
  false conflicts for casts and function expressions inside view definitions.
- Limited synchronized view edges to relation kinds currently modeled by the
  dependency graph.
- Made view-dependency synchronization require PostgreSQL rewrite-to-relation
  dependency classes, preventing unrelated catalog dependencies from entering
  the modeled graph.
- Removed foreign-key metadata from surviving tables during cascades, including
  cross-schema view and foreign-key cleanup for `DROP SCHEMA ... CASCADE`.
- Record inline foreign-key, CHECK, and exclusion constraints; reserve all
  generated constraint names before creating a table; and track `NOT VALID`
  constraints until validation completes.
- Validate partition parent, strategy, attachment, and detach state before
  applying partition changes. Publication scopes that imply all or inherited
  tables now conservatively taint confidence when those catalogs are absent.
- Match PostgreSQL statement atomicity for multi-target view drops when a
  scoped baseline cannot resolve one target, and retain conservative rewrite
  findings for type changes whose column evidence is incomplete.
- Keep irreversible-drop and `WITH GRANT OPTION` findings visible when the
  state matrix conservatively skips an operation because Cache V6 evidence is
  incomplete; guarded drops of absent columns remain no-ops.
- Match PostgreSQL `CASCADE` cleanup for `DROP SEQUENCE` and `DROP SCHEMA` by
  removing modeled `nextval(...)` column defaults that depend on dropped
  sequences, including cross-schema defaults.
- Route parser-accepted but unmodeled `ALTER TABLE` actions through the
  explicit opaque/tainted path instead of silently treating them as no-ops.
- Treat `CREATE TABLE` inheritance, typed-table, `LIKE`, and `ON COMMIT` forms
  as opaque until their copied metadata is modeled; CTAS now taints column
  completeness so later column edits remain conservative.
- Route parser-accepted `ALTER TYPE` owner, option, and attribute actions to
  the opaque path, and reject CTAS `ON COMMIT` lifecycle forms rather than
  recording a relation with the wrong transaction lifetime.
- Route unsupported `ALTER MATERIALIZED VIEW` actions to the opaque path
  instead of producing a fact that resolves to no mutation.
- Route unsupported `ALTER VIEW` column-default and option changes to the
  opaque path instead of producing facts that the resolver discards.
- Route unmodeled `CREATE ROLE`/`CREATE USER` options (such as `SUPERUSER`,
  `CREATEDB`, passwords, and memberships) to the opaque path rather than
  recording incomplete role state as exact.
- Route view options, `WITH CHECK OPTION`, unpopulated materialized views, and
  constrained/collated domains to the opaque path until
  their state semantics are modeled.
- Preserve policy mutations for restrictive-policy findings while tainting
  state when policy roles or `USING`/`WITH CHECK` expressions are unmodeled.
- Preserve expression indexes for their concurrency, uniqueness, and predicate
  checks; their unmodeled key/dependency metadata remains conservative during
  later constraint adoption.
- Keep aggregate identities for lookup while tainting their unmodeled
  transition functions and implementation options.
- Route composite, range, and base `CREATE TYPE` forms to the opaque path;
  only enum metadata is currently modeled completely.
- Keep database DDL available to database-specific rules while tainting
  confidence because database catalogs are outside the current schema model.
- Route unknown `RESET` settings through the opaque path; only the modeled
  timeout/search-path resets remain exact, while unrelated known settings stay
  explicit schema-neutral no-ops.

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
