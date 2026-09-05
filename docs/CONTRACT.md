# CLI and Report Contract

This document defines safe-migrate v0.8.0's CLI, report, cache, and GitHub
Action behavior.

If you are learning safe-migrate, start with the [README](../README.md). This
contract is the exact reference for scripts, CI integrations, exit codes, and
machine-readable output.

In this document, a *baseline* is the database snapshot stored in a cache file.
`sync` creates it; `lint` and `lint-chain` read it without contacting the
database.

## Commands

| Command | Contract |
| --- | --- |
| `lint --file <path>` | Analyze one migration. |
| `lint-chain --dir <path>` | Analyze `.sql` files in filename order with state carried forward. |
| `sync` | Read PostgreSQL metadata and settings into a local cache. Requires `DATABASE_URL` and a local, Unix-socket, or tunneled connection. |
| `cache inspect` | Show cache provenance and redacted counts without a database connection. Supports `--json`. |
| `rules` | List primary rules; `--rule <id>` selects one and `--json` emits the discovery schema. |
| `init github-actions --path <dir>` | Generate separate PR-analysis and trusted-refresh workflows. With `--configure-secrets`, warn before secret setup when the baseline environment is missing, unverifiable, or lacks an access-protection rule. |
| `init cache-key` | Generate a random 32-byte key as 64 lowercase hexadecimal characters. |

`init github-actions --configure-secrets` sends the database URL and generated
key through authenticated GitHub CLI without printing them. It detects the
default branch from `origin/HEAD`, falls back to `main`, and accepts `--branch`.
`init cache-key --set-github-secret` sends the key instead of printing it.

`lint` and `lint-chain` use an explicit cache, the default cache path, or
`--no-cache`. When `auto_sync = true` is set in configuration, they may refresh
the cache before analysis. `--no-auto-sync` suppresses that refresh for one
run; `--no-cache` also bypasses it.

Commands load `safe-migrate.toml` from the current directory when present.
`--config` selects another file and requires it to exist and validate.

`cache inspect` omits object, column, role, membership, and dependency names.
It still includes database and schema provenance, versions, timeout values, and
object counts. Treat that output as infrastructure metadata.

## Output channels

| Mode | Standard output |
| --- | --- |
| Human | The human-readable report. |
| `--json` | Exactly one JSON document, without progress text, ANSI escapes, or a preamble. |
| `--markdown` | One deterministic Markdown report, with source locations when available. |

Diagnostics always use standard error. JSON, Markdown, and interactive output
are mutually exclusive; conflicts exit `1`. Both lint commands support JSON.

## JSON report

The report schema is version 2:

```json
{
  "schema_version": 2,
  "confidence": "Exact",
  "verdict": "HALT",
  "evidence": [],
  "violations": []
}
```

Each violation includes `rule_id`, `operation_kind`, `object_kind`,
`object_name`, `tier`, `reason`, `recipe`, `dedup_key`, `sql`, and
`fk_dependency_related`. `rule_id` is the stable identifier.

Additional top-level objects are:

| Field | Contents |
| --- | --- |
| `summary` | `total`, `tier1`, `tier2`, and `tier3` counts. |
| `evidence` | Ordered, deduplicated reasons for conservative analysis. Each has a stable snake-case `code`, `statement` or `chain` scope, summary, and optional file/index. It contains no SQL or credentials. |
| `baseline` | Cache status, provenance, observed settings, and automatic-sync result. |

The `baseline` shape is:

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

Violations may also include a one-based `statement_index`, known-rule metadata
(`rule_title`, `rule_summary`, and `impact`), and this location object:

```json
"location": { "file": "migrations/001_add_status.sql", "line": 12, "column": 1 }
```

`rules --json` has its own version 2 schema. Descriptors expose identity,
guidance, tier, supported settings, and effective values. Every primary rule
supports `disabled`; other settings are accepted only when advertised.
Unknown rule IDs and unsupported fields are operational errors.

Consumers must branch on `schema_version`. Additive fields are compatible;
removal, renaming, type changes, and changed enum meanings require a changelog
entry. Violation ordering is deterministic for identical inputs and version.

## Verdict and exit status

| Verdict | Condition |
| --- | --- |
| `HALT` | At least one Tier 1 finding. |
| `CAUTIOUS` | Tier 2, but no Tier 1. |
| `SAFE WITH RISK` | Irreversible Tier 3, but no Tier 1 or Tier 2. |
| `SAFE` | No higher verdict applies. |

| Exit | Meaning |
| --- | --- |
| `0` | Analysis completed without Tier 1. |
| `1` | Invocation, configuration, I/O, cache, parser, or internal failure. |
| `2` | Analysis completed with Tier 1. |

Human, JSON, and Markdown modes must use the same exit-status policy.

## Confidence

Confidence describes the simulator's consistency with its available evidence,
not production runtime, lock duration, application compatibility, or backfills.

| Value | Meaning |
| --- | --- |
| `Exact` | Every transition had a deterministic outcome against the supplied baseline. |
| `Tainted` | At least one transition or reference could not be resolved confidently. |

No cache means `Tainted`; rules retain their conservative defaults. A stale
cache also taints confidence and warns on standard error.
`stale_stats_days` uses the cache timestamp, not file modification time.

PostgreSQL conflicts such as dropping a missing column produce a Tier 1
`chain-conflict`, leave state unchanged, and do not taint confidence by
themselves. This applies to both `lint` and `lint-chain`.

Cache V7 supplies typed evidence for:

- catalog coverage, schema scope, roles, privileges, and session settings;
- constraint keys and expressions, generated-column sources, and PostgreSQL's
  foreign-key equality operators;
- indexes, including included and expression/predicate dependency columns;
- inheritance and partition topology, view dependencies, sequence ownership,
  and standalone sequence references;
- every `pg_proc.prokind`, publications, and redacted subscriptions.

Missing required evidence never becomes invented state: the transition is
skipped and confidence is tainted. Independent syntax findings still report,
and multi-target view drops remain atomic.

The principal precision boundaries are:

| Area | Contract |
| --- | --- |
| Unsupported DDL | Parser-valid but unmodeled semantics are opaque and `Tainted`, never exact no-ops. This includes copied/inherited tables, CTAS lifecycle actions, unsupported role attributes, and unmodeled database, type, view, materialized-view, domain, or aggregate details. |
| Indexes | Synchronized complex-index dependencies support exact cleanup. Locally parsed complex indexes do not claim that precision. CTAS `WITH NO DATA` and expression indexes remain available to safety rules. |
| Grants and policies | `ALL TABLES IN SCHEMA` and policy role/expression changes are `Tainted`; their useful modeled effects remain available to security rules. PostgreSQL 17+ `MAINTAIN` is recognized only with a versioned baseline. |
| Routines and settings | All synchronized routine kinds are modeled; routine DDL without a typed Squawk extractor is opaque. Unknown `RESET` parameters are opaque, while modeled timeouts/search path and schema-neutral settings remain exact. |
| Publications | Sync is database-wide. Table edits without `ONLY` are `Tainted` until effective partition scope is proven. |
| Subscriptions | Only non-secret fields are cached; connection targets are `Redacted`. Connected create, refresh, and drop operations are `Tainted` because they depend on remote state. |

## Timeout evidence

`require-lock-timeout` and `require-statement-timeout` are Tier 2 primary rules.
They require positive effective values for statements identified by Squawk's
pinned `possibly_slow_stmt` classifier. `lock_timeout` must also be shorter than
a positive `statement_timeout`.

Values begin from Cache V7, or unknown without a cache. Ordered `SET`, local
settings, resets, commits, and rollbacks follow PostgreSQL session/local
behavior. `SET LOCAL` outside a transaction has no modeled effect. Each rule
reports at most once per input file.

## Failure behavior

These conditions exit `1` instead of producing a clean report:

- SQL parse failure;
- unreadable input;
- invalid configuration;
- corrupt or incompatible cache;
- unsupported command-line combinations;
- internal serialization or analysis failure.

Sync replaces a cache only after its new payload is complete. An automatic
refresh failure is recorded in JSON and may reuse a readable V7 cache; otherwise
analysis continues without a baseline and is `Tainted`.

Encrypted mode requires `cache_encryption = true` and a valid
`SAFE_MIGRATE_CACHE_KEY`. Cache modes cannot be mixed; switching requires a new
`sync`. V7 carries an explicit header, coverage and scope-completion markers,
role/session provenance, schemas, settings, dependencies, and redacted catalog
metadata. It never contains password hashes or subscription connection strings.
V1–V6 and unheadered caches are rejected with resync guidance.

### GitHub Action

| Concern | Contract |
| --- | --- |
| Mode | Analysis requires `path`. `mode: auto` uses `lint` for a file and `lint-chain` for a directory. `sync: "true"` without `path` is refresh-only; with `path`, analysis follows. |
| Baseline | Normal analysis requires a managed or explicit baseline. Only `no-cache: "true"` enables degraded analysis. |
| Configuration | An explicit config must exist. Caches are encrypted by default; plaintext requires `encrypted-cache: "false"`, and the config must agree. A missing/invalid key fails before database access or parsing. |
| Isolation | Analysis disables config-driven `auto_sync` and removes database access after refresh. `output-dir` must remain inside the workspace, without dot segments or symlink traversal. |
| Result | Exit `2` fails unless advisory; exit `1` always fails. Refresh-only success returns empty reports, `sync-status=refreshed`, and `baseline-source=synced`. |
| Source | Exact tags use checksum-verified assets. Full 40-character SHAs and local invocations build source. Mutable branch references are rejected. |

Errors must identify the failed input or subsystem without printing
`DATABASE_URL`, credentials, or migration contents not already requested in the
report.

## Compatibility

Before v1.0 the CLI may evolve. User-visible changes still require regression
tests, a changelog and contract update, and a migration note for automation.
