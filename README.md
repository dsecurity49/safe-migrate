# safe-migrate v0.4.3

safe-migrate lint-checks PostgreSQL migrations by simulating their schema
changes. A synced local cache supplies production schema metadata and row-count
estimates for checks whose severity depends on the current database.

It is a safety aid, not a substitute for testing a migration on a representative
database or for planning application-level rollout and backfill work.

## Install

```bash
cargo install safe-migrate --locked
```

Or build this checkout with `cargo build --locked`.

## Quick start

Sync a local baseline before linting migrations that touch existing objects:

```bash
export DATABASE_URL='postgres://readonly_user:password@localhost:5432/app'
safe-migrate sync
safe-migrate lint --file migrations/20260727_add_status.sql
```

`sync` writes `.safe-migrate.cache` by default. It reads PostgreSQL catalog
metadata and needs a database role able to read those catalogs; do not put
`DATABASE_URL` or its credentials in `safe-migrate.toml`.

For safety, this build only syncs through localhost or a Unix socket. Use an
SSH tunnel for a remote database, then point `DATABASE_URL` at the local tunnel.

`lint` and `lint-chain` are offline commands. They never need to connect to
PostgreSQL unless `auto_sync = true` is configured.

## Confidence and exit status

Reports carry a confidence value:

| Confidence | Meaning |
|---|---|
| `Exact` | The simulator remained consistent with the available baseline and SQL. |
| `Tainted` | The cache/baseline is unavailable or stale, or analysis encountered an uncertain transition. A failed automatic refresh is recorded in the baseline metadata; a retained fresh cache keeps its existing confidence. Review before deployment. |

Without a cache, safe-migrate still evaluates visible DDL using conservative
defaults. It does not invent baseline-comparison findings such as
`schema-drift` when no baseline exists.

- Exit `0`: analysis completed with no Tier 1 finding.
- Exit `1`: invocation, configuration, cache, parser, or internal failure.
- Exit `2`: analysis completed and found one or more Tier 1 findings.

`--json` emits exactly one JSON document on standard output. Diagnostics go to
standard error. The JSON report includes a `baseline` object with baseline
status, cache provenance, and automatic-sync outcome.

## Configuration

All settings are optional. `safe-migrate.toml` is loaded from the current
directory unless `--config` specifies another path.

```toml
# Size thresholds used by lock-sensitive rules.
tier1_threshold_rows = 100000
tier2_threshold_rows = 10000
default_rows = 10000

# Version assumed only when no cache is available.
assume_pg_version = 100000

# Treat a cache older than this as an uncertain baseline.
stale_stats_days = 7

# Restrict sync (and configured automatic sync) to these schemas.
schemas = ["public", "auth"]

# Disabled by default. Before lint/lint-chain, refresh the configured cache.
# A failed refresh prints its cause and continues with the previous cache; if
# none exists, analysis continues with an uncertain baseline.
auto_sync = false

# Disabled by default. When true, sync encrypts new cache files. Supply a
# 32-byte key as 64 hexadecimal characters only through the environment.
cache_encryption = false

[rules.blocking-constraint]
tier1_threshold_rows = 5000
tier2_threshold_rows = 1000

[rules.missing-idempotency]
disabled = true
```

Rule entries support `disabled`, `tier1_threshold_rows`, and
`tier2_threshold_rows`. Global `disabled_rules = ["rule-id"]` is also
supported. A rule’s documented primary ID is the ID used for disabling it;
some rules emit more specific finding IDs as noted in the rule catalog.

### Automatic sync

Automatic sync is configuration-only—there is no CLI flag. It runs for `lint`
and `lint-chain`, before analysis, when `auto_sync = true`. `--no-cache`
always bypasses it. Sync failure never deletes a prior cache and never turns a
successful lint invocation into a crash: the error is printed, then the old
cache is used if readable. A cache still within `stale_stats_days` keeps its
existing confidence; the JSON baseline still records `auto_sync: "failed"`.

### Encrypted caches

With `cache_encryption = true`, set this environment variable before `sync`,
`lint`, or `lint-chain`:

```bash
export SAFE_MIGRATE_CACHE_KEY='64 hexadecimal characters (32 bytes)'
```

safe-migrate uses authenticated XChaCha20-Poly1305 encryption with a fresh
random nonce for each cache write. The key is deliberately not accepted in
TOML, command-line flags, or cache metadata. Keep it in your secret manager.
An encrypted cache without the setting and key fails closed; regenerate a cache
after enabling encryption rather than committing a key or decrypted cache.

## Commands

```bash
# One migration
safe-migrate lint --file migration.sql [--cache path] [--config path] [--no-cache] [--json]

# Ordered .sql files, retaining simulated state across the chain
safe-migrate lint-chain --dir migrations/ [--cache path] [--config path] [--no-cache] [--json]

# Refresh the local cache; --config is used for cache_encryption
safe-migrate sync [--out .safe-migrate.cache] [--config safe-migrate.toml] [--schemas public,auth]
```

`--interactive` is available for human exploration and cannot be combined with
`--json`.

## Rule catalog

The engine currently evaluates these 26 primary rules:

| ID | Checks |
|---|---|
| `irreversible-migration` | Irreversible table/column changes and lossy type changes. |
| `drop-database` | `DROP DATABASE`. |
| `drop-schema-cascade` | `DROP SCHEMA ... CASCADE`. |
| `destructive-general-cascade` | Cascading drops of non-table objects. |
| `destructive-cascade` | `DROP TABLE ... CASCADE` and dependent objects. |
| `create-table-as-select` | `CREATE TABLE ... AS SELECT` on an existing populated baseline. |
| `size-aware-add-column` | Add-column operations that can rewrite large tables. |
| `type-change-rewrite` | Type changes requiring a table rewrite. |
| `blocking-constraint` | Synchronous CHECK and foreign-key validation. |
| `require-concurrent-index` | Synchronous index creation or removal. |
| `blocking-mat-view-refresh` | Non-concurrent materialized-view refresh. |
| `blocking-partition-mutation` | Partition attach/detach locking. |
| `partition-strategy-mismatch` | Incompatible partition strategies. |
| `restrictive-policy` | Restrictive RLS policies. |
| `disable-trigger` | Disabling all triggers. |
| `broken-compute` | Dropping a function still referenced by a trigger. |
| `function-volatility-change` | Changing a function’s volatility classification. |
| `missing-idempotency` | Missing safe re-run guards where supported. |
| `concurrent-in-transaction` | Concurrent index operations inside a transaction. |
| `alter-type-add-value-txn` | `ALTER TYPE ... ADD VALUE` transaction constraints. |
| `vacuum-full` | `VACUUM FULL`. |
| `opaque-dynamic-sql` | Dynamic/opaque SQL that cannot be fully simulated. |
| `volatile-default` | Volatile column defaults. |
| `overbroad-grant` | Broad grants such as `PUBLIC` or `ALL PRIVILEGES`. |
| `schema-drift` | References inconsistent with a supplied database baseline. |
| `chain-conflict` | Conflicting state changes across `lint-chain` files. |

The `blocking-constraint` rule can emit `blocking-index-constraint`, and
`require-concurrent-index` can emit `require-concurrent-drop-index`. Rewrite
paths can also emit `table-rewrite-storage` or `table-rewrite-access-method`.
Those are finding IDs, not independently configurable primary rules.

## CI

Check in a reviewed cache only when it is acceptable for your team to store
schema metadata in the repository. Otherwise sync in CI from a protected
database secret and lint the migrations. Preserve exit status `2` as a blocked
migration, and treat `1` as an infrastructure/configuration failure.

```yaml
- name: Build and lint migrations
  run: |
    cargo build --locked --release
    ./target/release/safe-migrate lint-chain --dir migrations --json > safe-migrate-report.json
```

For database-backed CI, add `DATABASE_URL` as a protected secret and run
`safe-migrate sync` in a controlled network environment before the lint step.
Never echo the URL or write it to the cache/configuration file.

## Development

```bash
cargo fmt -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cd live_tests && ./run.sh
```

See [the user-visible CLI/report contract](docs/CONTRACT.md),
[contributing guide](CONTRIBUTING.md), and [maintainer documentation](docs/README.md).
