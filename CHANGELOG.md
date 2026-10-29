# Changelog

This file summarizes user-visible changes. Implementation details belong in
commits and pull requests. Published binaries, checksums, and generated release
notes are available on the
[GitHub Releases page](https://github.com/dsecurity49/safe-migrate/releases).

## v0.12.0 — 2026-10-27

- Domains are modeled end to end: `CREATE`/`ALTER`/`DROP DOMAIN`, defaults,
  `NOT NULL`, collation, and named or generated constraints. Destructive column
  changes are reported when a relation's domain constraint still protects it.
- Sequences track runtime values, so `ALTER SEQUENCE` bound changes report a
  certain conflict, taint when a cached runtime may have advanced, and
  `TRUNCATE ... RESTART IDENTITY` is treated as unmodeled runtime state.
- Extensions are modeled from catalog membership: `ALTER EXTENSION SET SCHEMA`
  moves members atomically, `DROP EXTENSION` drops modeled members in dependency
  order, and a dependent outside the extension blocks the drop until `CASCADE`.
  Dropping an extension-owned member directly is reported, and schema renames
  remap extension membership and collation references.
- Extensions that provide base types now synchronize their catalog metadata,
  including the type delimiter.
- Range creation automatically produces the companion multirange type, explicit
  bidirectional links, and internal constructors. Independent multirange renames
  preserve companion links, composite attribute changes synchronize typed tables,
  and base/shell type options are fully represented in state.
- `schema-drift` now covers `ALTER DOMAIN`, `ALTER SEQUENCE`, `ALTER EXTENSION`,
  and unguarded `DROP EXTENSION`; `missing-idempotency` requires
  `IF [NOT] EXISTS` for extension creation and drops; and
  `destructive-general-cascade` reports `DROP EXTENSION ... CASCADE` and
  composite attribute drops or type changes performed with `CASCADE`.
- Cache V11 adds domain, sequence-runtime, and extension catalog state. Re-run
  `safe-migrate sync`; older caches are rejected rather than misread.

## v0.11.2 — 2026-10-24

- Upgraded the pinned Squawk parser stack from 2.65.0 to 2.70.0, raising the
  minimum supported Rust version to 1.99.
- The cache layout now carries aggregate kind and direct-argument metadata.
  Re-run `safe-migrate sync`; a cache written before this layout is rejected
  rather than misread.
- View analysis rejects `count(*)` and aggregate-only clauses that resolve to a
  scalar routine; aggregate overload resolution matches PostgreSQL, including
  ordered-set, hypothetical, and user-defined aggregates. Quoted `"serial"` is
  an ordinary type.
- The built-in type and aggregate fallbacks were regenerated from PostgreSQL
  18.6, including preferred-type flags and ordered-set aggregate signatures.
- JSON reports now include the `inline-suppression-disabled` rule title, so
  every emitted rule id is labeled in the top-level `rules` map.

## v0.11.1 — 2026-10-20

- The Markdown report shows how many checks did not run and collapses their
  rules and remedies into one expandable table grouped by cause, instead of
  repeating the same remedy for every rule. The terminal report groups them the
  same way.
- Aggregate overload resolution now follows PostgreSQL for variadic element
  types, explicit `VARIADIC` arrays, and omitted trailing defaults.
- Corrected generated constraint names, inherited foreign-key columns,
  partition column matching, version-gated privilege and subscription behavior,
  multirange names, and scoped routine dependency identities.

## v0.11.0 — 2026-10-19

- Report JSON schema version 3: violation fields are dropped, rule titles move
  to a top-level `rules` map, and consumers must branch on `schema_version`.
- Routine identity is checked as PostgreSQL does: return type and `SETOF`, named
  parameters, default count, and `RETURNS TABLE`/`OUT` as the row they define.
- `REINDEX` rejects `SYSTEM CONCURRENTLY` and the `SCHEMA`/`DATABASE`/`SYSTEM`
  forms inside a transaction block.
- `CREATE INDEX` validates key and `INCLUDE` columns and skips an `IF NOT EXISTS`
  name held by any relation; an index over a projection we could not derive is no
  longer a false conflict.
- Partitioned child indexes, including `ON ONLY` and equivalent-index reuse, are
  modeled, and `DROP INDEX` on an attached index is reported, not bypassed by
  `CASCADE` or `IF EXISTS`.
- `DROP TYPE`/`DROP DOMAIN`/`DROP SCHEMA` `CASCADE` is transitive and otherwise
  names its dependents; renaming or moving a referenced routine or type still
  reports dropping the new name.
- A view depends on every routine and type in its body, which catalog-synchronized
  views now carry — run `safe-migrate sync`.
- `CREATE OR REPLACE VIEW` rejects a renamed, retyped or dropped leading column;
  `CREATE VIEW`/`CREATE MATERIALIZED VIEW` apply an explicit column list, and
  `REFRESH ... CONCURRENTLY` needs a usable unique index.
- `CREATE SEQUENCE`/`ALTER SEQUENCE` merge options in PostgreSQL's order and
  report a repeat, zero increment, non-positive cache, unordered bounds or an
  out-of-range start.
- `SET (...)`/`RESET (...)` options are validated by relation kind and version: a
  view by its own set, a table or materialized view by the heap set, a column by
  the attribute set, an index by its access method's set; a partitioned table
  refuses any storage parameter and a foreign table the action.
- Any namespace other than `toast.` is refused; a `toast.` option is checked
  against the TOAST table's own set and dropped when the relation has none, and a
  name the option table cannot place taints.
- A name without a value means `true`, apart from an explicitly empty string,
  which stays empty rather than its quotes; `RESET` refuses a value.
- An option name folds like any identifier, a string literal is the value it
  spells, a `check_option` is refused unless the view is automatically updatable,
  and an `ALTER TABLE` action only where PostgreSQL allows one.
- An unqualified call is placed against the search path by name and argument types
  before it counts as an aggregate.
- Built-in types are read from `pg_catalog.pg_type`; a type declaration the server
  would refuse is reported, and a `character(n)` length change is a rewrite.
- A scoped baseline remembers the schemas that existed at synchronization, so
  resolution no longer taints on an absent schema, and a routine never resolves in
  `pg_temp`.
- A Tier 1 check that did not run, or a rule declined for an out-of-baseline
  target, is recorded as not evaluated and caps the verdict at `CAUTIOUS`.
- `GRANT`/`REVOKE` per-membership options are refused only for a known pre-16
  version, a grantee named by the statement is reported even outside the baseline,
  and `assume_pg_version` accepts only 14–18.
- Name resolution follows the synchronized session's search path, and an
  unqualified `CREATE` places at the first writable schema. Cache format V10; run
  `safe-migrate sync`.

## v0.10.0 — 2026-10-02

- Range types are read from the baseline and their constructor is owned by the
  type, so `DROP TYPE` no longer halts and dropping the constructor is reported.
  Cache format V9; run `safe-migrate sync`.
- Findings name the object they concern, using plain names instead of
  angle-bracket placeholders, and fall back to `unknown statement`. A
  subscription is now reported as one rather than as a publication.
- `CREATE TYPE ... AS RANGE` and `CREATE TYPE ... (INPUT = ...)` are modeled as
  the `range` and `base` type kinds instead of the opaque path.
- `schema-drift` fires for a relation provably absent from the baseline, and
  only taints otherwise.
- `ALTER INDEX ... ATTACH PARTITION` records the parent/child relationship, so
  dropping a partitioned index drops its attached children.
- Routine identity matches PostgreSQL's argument-type-OID keying, and renaming
  a type preserves dependents' schema qualification.
- `ALTER INDEX ... SET STATISTICS n` is validated, including numeric column
  targets and PostgreSQL's clamped upper bound.
- Added `require-concurrent-reindex` and `ALTER MATERIALIZED VIEW` /
  `ALTER INDEX` modeling, bringing the rule count to 30.
- Type modifiers are bounded to the ranges PostgreSQL accepts, `bpchar` without
  a length no longer collapses to `char`, and `timestamp(p) with time zone`
  keeps its qualifier when a precision precedes it.
- `REINDEX` and `ALTER INDEX` resolve against interrupted and crashed
  concurrent-operation catalog states; `REINDEX CONCURRENTLY` in a transaction
  block is flagged, and temporary tables and exclusion-backing indexes no
  longer draw false positives.
- Inline suppressions are disabled by default; set
  `allow_inline_suppressions = true` to restore them.
- Finding severity is no longer weakened by uncertainty elsewhere in the
  migration; `Finding.certainty` carries that instead.
- Name resolution now matches the live server: an empty `search_path` places
  nothing in `public`, temporary relations resolve in the session's temporary
  schema, and scoped `sync` reads the path before pinning to `pg_catalog`.
- `ALTER VIEW` / `ALTER MATERIALIZED VIEW` `SET`/`RESET` options are modeled,
  rejected by version, or tainted rather than dropped.
- Views created from DDL carry the same columns as catalog-synchronized views;
  `ALTER TABLE ... SET SCHEMA` is no longer silently dropped.

## v0.9.3 — 2026-09-23

- Upgraded the pinned Squawk parser stack from 2.64.0 to 2.65.0.
- Fixed privilege analysis for role names that are SQL keywords.
- Fixed serial/identity detection in `sync` so a column default that is the text
  literal `nextval('...')` is no longer mistaken for an implicit sequence.

## v0.9.2 — 2026-09-22

- Supported exact recursive propagation for inherited/partitioned column renames.
- Validated `DETACH CONCURRENTLY` interrupted/crashed catalog states against live PostgreSQL.
- Unified data-type classification for array elements and partition literals.
- Extracted exact partition-key definitions natively at AST visitor time.

## v0.9.1 — 2026-09-19

- Stabilized typed-table catalog synchronization, preventing layout-validation
  and type-resolution failures on PostgreSQL 15+ typed tables.
- Fixed cross-schema synchronization so identity-generating sequences resolve
  through the same foreign-key expansion as their owning tables.
- Expanded `DETACH PARTITION ... CONCURRENTLY` retained-CHECK synthesis to
  byte-exact PostgreSQL output for composite, mixed-varchar, and boundary
  sentinel partition ranges; parenthesized partition keys are accepted
  identically to bare names.
- Extended retained-CHECK synthesis to LIST partitions declaring `NULL`;
  true expression keys remain conservatively tainted.

## v0.9.0 — 2026-09-15

- Established `safe_migrate::api` as the supported Rust interface for analysis,
  configuration, synchronization, and reporting; `_internal` is now private.
- Unified API and CLI reports and evidence, with typed results, categorized
  errors, and redacted database/cache-key inputs for embedded callers.
- Added `table-lock` to flag explicit blocking locks, bringing the rule count
  to 29.
- Expanded SQL modeling for `TRUNCATE`, storage and column settings, inheritance,
  partition detach, `SELECT INTO`, sequence options, and temporary-table commits.
- Added Cache V8 metadata for CHECK definitions, extended statistics, column
  inheritance, generated/identity columns, and partition-trigger parentage.
- Improved constraint/index rename and drop propagation, generated CHECK names,
  expression preservation, `LIKE` copies, and replica-identity eligibility checks.
- Fixed concurrent-detach state and recursive rename collisions; invalidate
  descendant predicates after ancestry changes. Unsupported predicate forms
  remain conservative.
- Track PostgreSQL 16+ role-membership grantors and per-grant options for more
  accurate `REVOKE`/`CASCADE` analysis.
- Hardened rollback, baseline/version validation, secret cleanup, and report
  rendering; reject unsupported PostgreSQL-version assumptions.
- Expanded live catalog comparisons and interrupted-detach coverage, repaired
  the CI smoke-test target, and improved live scripts and crate packaging.

## v0.8.1 — 2026-09-06

- Upgraded Squawk's parser, lexer, syntax tree, and linter to 2.64.0, including
  its stricter routine validation and more precise type and transaction nodes.
- Preserved ordered-set aggregate and function signatures across the new AST,
  and stopped prepared-transaction completion from ending the analyzed
  migration transaction.
- Warn before GitHub secret setup when the baseline environment is missing,
  unverifiable, or lacks reviewer or deployment-branch protection.
- Prevent `cargo test` from opening the interactive viewer when run from a
  terminal.

## v0.8.0 — 2026-09-04

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
