# Live Tests

This directory contains end-to-end SQL fixtures for all 26 primary rules. Two
different suites use them:

- `run.sh` lints fixtures against the frozen local cache. It does not execute
  SQL in PostgreSQL.
- `scripts/live-differential` compares safe-migrate's modeled result with a
  disposable PostgreSQL database for fixtures enabled in
  `differential_manifest.json`.

## Fixture convention

- `safe_*.sql` must not emit the directory's target rule.
- `[0-9]*.sql` must emit the directory's target rule.

The frozen `.safe-migrate.cache` is part of the test corpus. Update it only
when fixtures require a different baseline, and regenerate it with
`safe-migrate sync`; do not edit it in place.

## Cached fixture suite

From this directory:

```bash
./run.sh
./run.sh -v
./run.sh -d rule_25_schema-drift
./run.sh -t rule_01_irreversible-migration/001_drop_table.sql
./run.sh --offline
```

`--offline` passes `--no-cache`, so baseline-dependent findings can differ.
Most directories lint each file independently; chain-conflict fixtures use
`lint-chain`.

## PostgreSQL differential suite

Run from the repository root with a disposable local database:

```bash
export DATABASE_URL='host=/path/to/socket dbname=postgres user=my_user'
scripts/live-differential -v
```

The harness rebuilds `differential_baseline.sql` before each enabled fixture
and executes migration SQL. Never point it at a shared or production database.

Useful selectors:

```bash
scripts/live-differential -vv --rule rule_01_irreversible-migration
scripts/live-differential --fixture rule_01_irreversible-migration/001_drop_table.sql
```

Verbosity is cumulative:

- `-v` shows lifecycle and fixture outcomes.
- `-vv` adds cache and normalized-state counts.
- `-vvv` prints complete normalized PostgreSQL and simulator projections.

CI runs the enabled manifest against PostgreSQL 14, 15, and 16 and uploads one
verbose log per version. Excluded fixtures remain documented in
`differential_manifest.json` with their reasons.
