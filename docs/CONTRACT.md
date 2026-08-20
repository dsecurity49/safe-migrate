# CLI and Report Contract

This document defines the user-visible behavior of safe-migrate v0.6.0. A
requirement is not complete until an automated test enforces it.

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
- `safe-migrate rules` lists canonical primary-rule descriptors. `--rule <id>`
  selects one descriptor and `--json` emits the stable discovery schema.

`lint` and `lint-chain` use an explicit cache, the default cache path, or
`--no-cache`. When `auto_sync = true` is set in configuration, they may refresh
the cache before analysis. `--no-cache` always bypasses automatic sync.

`cache inspect` never lists object, column, role, membership, or dependency
names and edges. Its source database, schema scope, versions, observed timeout
values, and redacted counts—including the role count—still describe sensitive
infrastructure and must not be published automatically.

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

Interactive output is mutually exclusive with `--json` and `--markdown`. The
CLI must reject conflicting output selections rather than silently choosing one.

## JSON report

The v1 JSON report has these top-level fields:

```json
{
  "schema_version": 1,
  "confidence": "Exact",
  "verdict": "HALT",
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

`rules --json` has its own schema version 2 document. Every descriptor exposes
its ID, title, summary, impact, default tier, remediation, supported
configuration fields, and only the effective values that rule supports. Every
primary rule supports `disabled`; row thresholds are accepted only where the
descriptor advertises them. Unknown rule IDs and unsupported configuration
fields are operational errors.

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

Analysis without a database cache is reported as `Tainted`, because existing
production schema and dependency state are unknown. Rule evaluation retains
its default worst-case assumptions; an absent cache does not downgrade a
finding solely because the baseline is unavailable. A stale-cache warning does
not silently change individual findings, but it taints confidence, must be
visible on standard error, and must not be described as a production guarantee.
The configured `stale_stats_days` limit is evaluated from provenance recorded
inside a successful cache, not from file modification time.

## Timeout evidence

`require-lock-timeout` and `require-statement-timeout` are Tier 2 primary rules.
For statements that Squawk's pinned `possibly_slow_stmt` classifier identifies
as potentially disruptive, they require known positive effective values. The
lock-timeout rule also reports a positive `lock_timeout` that is greater than
or equal to a positive `statement_timeout`, because PostgreSQL reaches the
statement timeout first in that ordering.

Analysis initializes both settings from Cache V6, or as unknown when no cache
is available. Ordered `SET`, `SET LOCAL`, `SET ... DEFAULT`, `RESET`, and
`RESET ALL` statements update modeled values. Transaction commit, rollback,
and savepoint rollback must match PostgreSQL session-versus-local behavior.
`SET LOCAL` outside an explicit transaction has no modeled effect. Each timeout
rule reports at most once per input file.

## Failure behavior

The following conditions must never produce a successful clean report:

- SQL parse failure;
- unreadable input;
- invalid configuration;
- corrupt or incompatible cache;
- unsupported command-line combinations;
- internal serialization or analysis failure.

Automatic cache refresh failure is different: it prints the underlying error
and analysis continues with the old readable V6 cache, or with an unavailable
baseline if none exists. A retained cache that is still within
`stale_stats_days` keeps its existing confidence; an unavailable or stale
baseline is reported as `Tainted`. The JSON baseline records the failed refresh
in either case.
Sync writes replace an existing cache only after the new payload has been fully
produced. Encrypted caches require `cache_encryption = true` and a valid
`SAFE_MIGRATE_CACHE_KEY`; missing or invalid key material is an operational
failure and is never accepted from TOML or command-line arguments. Conversely,
when `cache_encryption = true`, plaintext cache files are rejected rather than
silently weakening the configured protection. When encryption is disabled,
encrypted cache files are also rejected; changing modes requires a fresh
`safe-migrate sync`.

V6 cache payloads carry an explicit format header and record effective/session
role provenance, the unexpanded search-path setting, effective lock and
statement timeouts in milliseconds, PostgreSQL role membership, authoritative
synchronized schemas, and synchronized sequence ownership/kind. They never
include password hashes. V1–V5 and unheadered payloads are rejected with
generic guidance to run `safe-migrate sync`; errors do not expose internal
cache-version labels. A failed automatic refresh may reuse an existing readable
V6 cache, but never an unsupported older cache.

When analysis is reached, the GitHub Action writes JSON, Markdown, and
diagnostics. It appends the Markdown report to the job summary, annotates Tier
1 findings as errors and Tier 2 findings as warnings using the rule title,
summary, reason, and remediation, and leaves Tier 3 in the summary only.
Analyzer status `2` fails normally; `advisory: "true"` makes the Action step
successful while preserving output `exit-code: 2`. Operational status `1`
always fails. Published Action accepts only exact semantic tags
matching `Cargo.toml` or full
40-character commit SHAs; mutable references are rejected. Release downloads
are exact-version, exact-target, checksum-verified, and never fall back to
another release, target, or source build after failure.

Errors must identify the failed input or subsystem without printing
`DATABASE_URL`, credentials, or migration contents not already requested in the
report.

## Compatibility

Before v1.0, the CLI may evolve, but user-visible changes still require:

1. regression tests;
2. a `CHANGELOG.md` entry;
3. an update to this contract;
4. an explicit migration note for scripts or CI consumers.
