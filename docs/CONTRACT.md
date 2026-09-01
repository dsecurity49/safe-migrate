# CLI and Report Contract

This document defines safe-migrate v0.7.0's CLI, report, cache, and GitHub
Action behavior.

If you are learning safe-migrate, start with the [README](../README.md). This
contract is the exact reference for scripts, CI integrations, exit codes, and
machine-readable output.

In this document, a *baseline* is the database snapshot stored in a cache file.
`sync` creates it; `lint` and `lint-chain` read it without contacting the
database.

## Commands

- `safe-migrate lint --file <path>` analyzes one SQL migration.
- `safe-migrate lint-chain --dir <path>` analyzes `.sql` files in filename
  order while preserving state across files.
- `safe-migrate sync` reads PostgreSQL catalog metadata, statistics, role and
  search-path context, and effective `lock_timeout` and `statement_timeout`
  values, then writes a local cache. It requires `DATABASE_URL` and accepts
  only localhost or Unix-socket connections in this build; remote databases
  must be reached through an SSH tunnel.
- `safe-migrate cache inspect` reads a local cache without connecting to
  PostgreSQL and prints provenance plus a redacted contents summary. `--json`
  emits that same summary as one JSON document.
- `safe-migrate rules` lists primary-rule descriptors. `--rule <id>`
  selects one descriptor and `--json` emits the stable discovery schema.

`lint` and `lint-chain` use an explicit cache, the default cache path, or
`--no-cache`. When `auto_sync = true` is set in configuration, they may refresh
the cache before analysis. `--no-auto-sync` suppresses that refresh for one
run; `--no-cache` also bypasses it.

Without `--config`, CLI commands read `safe-migrate.toml` from the current
directory when it exists and otherwise use built-in defaults. A path passed
with `--config` must exist and pass validation.

`cache inspect` omits object, column, role, membership, and dependency names.
It still includes database and schema provenance, versions, timeout values, and
object counts. Treat that output as infrastructure metadata.

## Output channels

Human-readable reports are written to standard output. Diagnostics about
configuration, cache age, missing cache, parsing, and internal failures are
written to standard error.

When `--json` is selected:

- standard output contains exactly one valid JSON document;
- standard output contains no progress text, ANSI escapes, or human preamble;
- diagnostics remain on standard error;
- the JSON report is produced for both `lint` and `lint-chain`.

When `--markdown` is selected:

- standard output contains one deterministic Markdown report;
- diagnostics remain on standard error;
- findings include file, line, and column when the parser produced a source
  range;
- JSON and Markdown modes are mutually exclusive.

Interactive output is mutually exclusive with `--json` and `--markdown`.
Conflicting output modes exit `1`.

## JSON report

The v2 JSON report has these top-level fields:

```json
{
  "schema_version": 2,
  "confidence": "Exact",
  "verdict": "HALT",
  "evidence": [],
  "violations": []
}
```

Each violation includes:

- `rule_id`
- `operation_kind`
- `object_kind`
- `object_name`
- `tier`
- `reason`
- `recipe`
- `dedup_key`
- `sql`
- `fk_dependency_related`

Location-aware lint output additionally includes a one-based
`statement_index` when the source range belongs to a parsed statement. Known
primary rules add `rule_title`, `rule_summary`, and `impact`. These are
additive fields; `rule_id` remains the stable identifier.

The additive top-level `summary` object contains `total`, `tier1`, `tier2`,
and `tier3` counts.

`evidence` is an ordered, deduplicated list of reasons the analyzer became
conservative. Each record has a stable snake-case `code`, a `scope` of either
`statement` or `chain`, a concise `summary`, and, when available, the migration
`file` and one-based `statement_index` that introduced it. Evidence contains no
connection strings, SQL text, or database credentials.

Schema v2 supersedes v1 by adding this field and versioning the document. JSON
consumers must branch on `schema_version`; the rule-discovery JSON schema is a
separate contract and remains version 2.

The additive `baseline` object records cache/baseline status, cache provenance,
and automatic-sync outcome:

```json
{
  "status": "available",
  "created_at_unix_secs": 0,
  "source_database": "app",
  "schemas": ["public"],
  "auto_sync": "not_requested",
  "observed_settings": {
    "lock_timeout_ms": 5000,
    "statement_timeout_ms": 900000
  }
}
```

`status` is `available`, `stale`, or `unavailable`; `auto_sync` is
`not_requested`, `refreshed`, `failed`, or `bypassed`. Observed timeout values
are `null` when no cache is available. Missing creation provenance makes an
otherwise readable baseline stale.

Each JSON violation may include this additive location object:

```json
"location": { "file": "migrations/001_add_status.sql", "line": 12, "column": 1 }
```

`rules --json` uses schema version 2. Descriptors include ID, title, summary,
impact, default tier, remediation, supported configuration fields, and the
effective values for those fields. Every primary rule supports `disabled`;
row thresholds are accepted only when listed by the descriptor. Unknown rule
IDs and unsupported fields are operational errors.

Fields may be added compatibly. Removing a field, renaming a field, changing its
type, or changing the meaning of an existing enum value is a report-contract
change and must be documented in `CHANGELOG.md`.

Violation ordering must be deterministic for the same SQL, configuration,
cache, and safe-migrate version.

## Verdict and exit status

The report verdict is derived from findings:

- `HALT`: at least one Tier 1 finding.
- `CAUTIOUS`: at least one Tier 2 finding and no Tier 1 finding.
- `SAFE WITH RISK`: an irreversible Tier 3 finding and no Tier 1 or Tier 2
  finding.
- `SAFE`: no higher verdict applies.

The exit-status contract is:

- `0`: analysis completed without a Tier 1 finding;
- `1`: invocation, configuration, I/O, cache, parser, or internal failure;
- `2`: analysis completed and found at least one Tier 1 finding.

Human, JSON, and Markdown modes must use the same exit-status policy.

## Confidence

`Exact` and `Tainted` describe consistency of the simulator relative to the
evidence available to it. They are not guarantees about production runtime,
lock wait duration, application compatibility, or data backfills.

- `Exact`: every state transition was either applied, skipped, or rejected with
  a deterministic outcome relative to the supplied baseline.
- `Tainted`: at least one transition or reference could not be resolved
  confidently.

An execution conflict that PostgreSQL would deterministically reject—such as
dropping a missing column or dropping a referenced table without `CASCADE`—is
reported as a Tier 1 `chain-conflict`, leaves simulated state unchanged, and
does not taint confidence by itself. This applies to both `lint` and
`lint-chain`; “chain” describes retained migration state, not a restriction to
the multi-file command.

Analysis without a database cache is `Tainted` because existing schema and
dependency state are unknown. Rules keep their default worst-case assumptions;
an absent cache does not lower a finding by itself. A stale cache taints
confidence and emits a warning on standard error. `stale_stats_days` uses the
timestamp inside the cache, not file modification time.

Cache V7 records explicit catalog coverage, ordered foreign-key column
identities, primary/unique constraint keys, stable direct inheritance topology
(with traditional inheritance distinct from declarative partitioning),
stable view-dependency relation/column identities, and typed index definitions
(method, simple key and included columns, complete dependency columns for
expression keys/predicates, usability, and default-ordering/operator-class/
collation proof). It also records direct `CHECK`/exclusion expression columns
from `pg_constraint`; an empty typed dependency is authoritative only for a
constant expression. Generated-column source identities are also retained from
`pg_attrdef`, including source-column CASCADE cleanup when the dependent
closure is fully modeled. It does not yet carry foreign-key operator proof.
Standalone sequence references used
by column defaults are retained separately from sequence ownership. A
transition whose correctness depends on missing catalog fact is skipped and
taints confidence rather than inventing state; syntax-level findings that are
independent of the skipped state update (for example `DROP COLUMN` being
irreversible or `WITH GRANT OPTION`) remain reportable. Multi-target view drops
with an unresolved target are likewise treated atomically, preserving known
targets in the simulated state.

`GRANT` and `REVOKE` on `ALL TABLES IN SCHEMA` update the modeled relations but
are `Tainted`: the cache does not represent every PostgreSQL relation kind that
the server may include in that target set.

Parser-valid DDL whose semantics are not represented by the state model is
handled as opaque and taints confidence. This includes copied or inherited
tables, CTAS transaction-lifecycle actions, unsupported role attributes, and
unmodeled type, view, or materialized-view alterations; these statements are never
silently recorded as exact no-ops.
The same rule applies to view options/check options, unpopulated materialized
views, and domain constraints or collations. CTAS `WITH NO DATA` and expression
indexes remain typed so their dedicated safety rules can report them.
Synchronized expression/predicate index dependency columns support exact
unrelated-column and automatic-index-cleanup transitions; locally parsed
complex indexes do not claim that precision. Policy mutations remain available
to security rules, but
policy role lists and expressions taint confidence because relation state does
not store them.
Aggregate creation retains its routine identity but is tainted because
transition-function and implementation-option dependencies are not modeled.
Composite, range, and base type creation is opaque because their attributes,
subtypes, and implementation dependencies are not represented.
Database create/alter/drop mutations remain available to their syntax rules but
taint confidence because database-level state is outside the current-database
schema model.
Unknown `RESET` parameters are opaque; only modeled timeout/search-path values
are exact, and explicitly schema-neutral settings such as `application_name`
remain no-ops.

Cache V7 synchronizes all `pg_proc.prokind` values in PostgreSQL's shared
routine namespace. Function, procedure, aggregate, and window-function
lifecycle operations use that baseline. Routine DDL without a typed Squawk
extractor remains opaque.

Publication synchronization is database-wide even when relation sync is
schema-scoped. It records owners, publication options, explicit tables, schema
membership, column lists, and row filters where the connected PostgreSQL
version provides them. Cache V7 stores stable direct `pg_inherits` rows, marked
as traditional inheritance or declarative partitioning, for dependency
reasoning; only the latter participates in partition lifecycle checks.
Publication table edits without
`ONLY` remain `Tainted` until the analyzer also proves their full effective
partition scope; `ONLY` edits do not require that proof.

Subscription synchronization is limited to the current database and selects
only non-secret catalog fields. It records owner, enabled state, slot name,
publication names, and supported settings. It never selects or serializes
`pg_subscription.subconninfo`; the cached connection target is `Redacted`.
Creating a connected subscription, refreshing publisher metadata, and dropping
a subscription remain `Tainted` because their outcome depends on remote state.

On PostgreSQL 17 and newer, relation ACL synchronization and grant/revoke
analysis recognize the table `MAINTAIN` privilege. `GRANT ALL` expands to that
privilege only when the cache identifies PostgreSQL 17 or newer; older or
version-unknown baselines retain the pre-17 expansion conservatively.

## Timeout evidence

`require-lock-timeout` and `require-statement-timeout` are Tier 2 primary rules.
For statements that Squawk's pinned `possibly_slow_stmt` classifier identifies
as potentially disruptive, they require known positive effective values. The
lock-timeout rule also reports a positive `lock_timeout` that is greater than
or equal to a positive `statement_timeout`, because PostgreSQL reaches the
statement timeout first in that ordering.

Analysis initializes both settings from Cache V7, or as unknown when no cache
is available. Ordered `SET`, `SET LOCAL`, `SET ... DEFAULT`, `RESET`, and
`RESET ALL` statements update modeled values. Transaction commit, rollback,
and savepoint rollback must match PostgreSQL session-versus-local behavior.
`SET LOCAL` outside an explicit transaction has no modeled effect. Each timeout
rule reports at most once per input file.

## Failure behavior

These conditions exit `1` instead of producing a clean report:

- SQL parse failure;
- unreadable input;
- invalid configuration;
- corrupt or incompatible cache;
- unsupported command-line combinations;
- internal serialization or analysis failure.

Automatic refresh failure prints the error and continues with the old readable
V7 cache, or with no baseline if none exists. A fresh retained cache keeps its
confidence; an unavailable or stale baseline is `Tainted`. JSON records the
failed refresh.

Sync replaces an existing cache only after the new payload is complete.
Encrypted caches require `cache_encryption = true` and a valid
`SAFE_MIGRATE_CACHE_KEY` from the environment. Plaintext mode rejects encrypted
caches, and encrypted mode rejects plaintext caches. Changing modes requires a
fresh `safe-migrate sync`.

V7 cache payloads carry an explicit format header, explicit catalog coverage,
and effective/session role provenance, the unexpanded search-path setting, effective lock and
statement timeouts in milliseconds, PostgreSQL role membership, authoritative
synchronized schemas, sequence ownership/kind, all routine kinds,
publications, and redacted subscriptions. They never include password hashes
or subscription connection strings. V1–V6 and unheadered payloads are rejected
with guidance to run `safe-migrate sync`. A failed automatic refresh may reuse
a readable V7 cache, but never an older format.

### GitHub Action

- A managed-cache miss runs `--no-cache` with `Tainted` confidence. A missing
  explicit cache is an error.
- `sync: "true"` refreshes the baseline before linting. Lint always suppresses
  config-driven `auto_sync`, and database access is removed after the
  Action-controlled refresh.
- An explicit config path must exist, and its `cache_encryption` setting must
  match `encrypted-cache`.
- An encrypted sync without a valid key fails before database access. A lint
  job without the key runs without the encrypted baseline.
- Exit `2` fails unless `advisory: "true"` is set. Exit `1` always fails.
- Exact release tags install checksum-verified release assets. Full
  40-character SHAs and local source invocations build the checked-out source.
  Mutable branch references are rejected.

Errors must identify the failed input or subsystem without printing
`DATABASE_URL`, credentials, or migration contents not already requested in the
report.

## Compatibility

Before v1.0, the CLI may evolve, but user-visible changes still require:

1. regression tests;
2. a `CHANGELOG.md` entry;
3. an update to this contract;
4. an explicit migration note for scripts or CI consumers.
