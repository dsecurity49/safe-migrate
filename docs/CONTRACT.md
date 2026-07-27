# CLI and Report Contract

This document defines the user-visible behavior safe-migrate intends to
stabilize for v0.4.3. A requirement is not complete until an automated test
enforces it.

## Commands

- `safe-migrate lint --file <path>` analyzes one SQL migration.
- `safe-migrate lint-chain --dir <path>` analyzes `.sql` files in filename
  order while preserving state across files.
- `safe-migrate sync` reads PostgreSQL catalog metadata and writes a local
  cache. It is the only command that requires `DATABASE_URL`.

`lint` and `lint-chain` must not connect to PostgreSQL. They may use an explicit
cache, the default cache path, or `--no-cache`.

## Output channels

Human-readable reports are written to standard output. Diagnostics about
configuration, cache age, missing cache, parsing, and internal failures are
written to standard error.

When `--json` is selected:

- standard output contains exactly one valid JSON document;
- standard output contains no progress text, ANSI escapes, or human preamble;
- diagnostics remain on standard error;
- the JSON report is produced for both `lint` and `lint-chain`.

Interactive output and `--json` are mutually exclusive. The CLI must reject the
combination rather than silently choosing one.

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

The v0.4.3 exit-status contract is:

- `0`: analysis completed without a Tier 1 finding;
- `1`: invocation, configuration, I/O, cache, parser, or internal failure;
- `2`: analysis completed and found at least one Tier 1 finding.

Human and JSON modes must use the same exit-status policy.

## Confidence

`Exact` and `Tainted` describe consistency of the simulator relative to the
evidence available to it. They are not guarantees about production runtime,
lock wait duration, application compatibility, or data backfills.

- `Exact`: no unsupported, unresolved, or contradictory state transition was
  encountered relative to the supplied baseline.
- `Tainted`: at least one transition or reference could not be resolved
  confidently.

Analysis without a database cache is reported as `Tainted`, because existing
production schema and dependency state are unknown. Rule evaluation retains
its default worst-case assumptions; an absent cache does not downgrade a
finding solely because the baseline is unavailable. A stale-cache warning does
not silently change findings, but it must be visible on standard error and the
report must not describe the result as a production guarantee.

## Failure behavior

The following conditions must never produce a successful clean report:

- SQL parse failure;
- unreadable input;
- invalid configuration;
- corrupt or incompatible cache;
- unsupported command-line combinations;
- internal serialization or analysis failure.

Errors must identify the failed input or subsystem without printing
`DATABASE_URL`, credentials, or migration contents not already requested in the
report.

## Compatibility

Before v1.0, the CLI may evolve, but user-visible changes still require:

1. regression tests;
2. a `CHANGELOG.md` entry;
3. an update to this contract;
4. an explicit migration note for scripts or CI consumers.
