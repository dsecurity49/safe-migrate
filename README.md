# safe-migrate

safe-migrate analyzes PostgreSQL migrations before they reach production. It
parses SQL into a typed AST, simulates schema changes in order, and reports
operations that may block, rewrite data, destroy objects, or fail against the
modeled database state.

A local cache can supply production schema metadata and table statistics for
database-aware findings. Linting is otherwise offline.

safe-migrate is a review aid, not a substitute for testing migrations on a
representative database or planning application rollouts and backfills.

## Install

### With Rust

Cargo is the primary installation method when Rust is already available:

```bash
cargo install safe-migrate --locked
safe-migrate --version
```

### Prebuilt binary

The installer detects supported Linux, macOS, and Termux targets, verifies the
release checksum, and installs the latest published binary:

```bash
curl -fsSL https://raw.githubusercontent.com/dsecurity49/safe-migrate/main/install.sh | bash
safe-migrate --version
```

Piping a script from the default branch is convenient but not reproducible.
Review [install.sh](install.sh) first or download a tagged installer when you
need to pin exactly what runs:

```bash
VERSION='<release-tag>'
curl -fsSL "https://raw.githubusercontent.com/dsecurity49/safe-migrate/${VERSION}/install.sh" |
  bash -s -- --version "${VERSION}"
```

The installer also supports `--version`, `--target`, `--install-dir`
(`--bin-dir`), `--force`, `--dry-run`, and `--verbose`. See
`bash install.sh --help` after downloading it. Archives, checksums, and manual
downloads are available on the
[GitHub Releases page](https://github.com/dsecurity49/safe-migrate/releases).

## Quick start

Create a database baseline, then lint one migration or a directory of ordered
migrations:

```bash
export DATABASE_URL='postgres://readonly_user:password@localhost:5432/app'

safe-migrate sync
safe-migrate lint --file migrations/001_add_status.sql
safe-migrate lint-chain --dir migrations/
```

`sync` writes `.safe-migrate.cache` by default. Use a least-privilege database
role that can read the required PostgreSQL catalogs, and keep `DATABASE_URL`
out of source control.

Direct remote connections are rejected. Connect through localhost, a Unix
socket, or an SSH tunnel:

```bash
ssh -N -L 5433:db.internal:5432 bastion
export DATABASE_URL='postgres://readonly_user@localhost:5433/app'
safe-migrate sync
```

`lint` and `lint-chain` do not connect to PostgreSQL unless `auto_sync = true`
is configured.

## Commands

```text
safe-migrate lint --file migration.sql
safe-migrate lint-chain --dir migrations/
safe-migrate sync
safe-migrate cache inspect
```

Common options:

- `--cache <path>` selects a cache file.
- `--config <path>` selects a TOML configuration file.
- `--no-cache` uses conservative defaults without baseline-aware drift claims.
- `--json` emits one machine-readable JSON document.
- `--markdown` emits a deterministic review artifact with source locations.
- `--interactive` opens the terminal UI.
- `sync --schemas public,auth` limits the synchronized schema scope.

Run `safe-migrate <command> --help` for the complete command reference.

## Findings and exit status

Findings use three tiers:

| Tier | Meaning |
|---|---|
| Tier 1 — `HALT` | The migration should be corrected before deployment. |
| Tier 2 — `WARN` | The migration or available evidence needs review. |
| Tier 3 — `SAFE` | Informational or lower-risk behavior, including irreversible operations that still require normal safeguards. |

Reports also include confidence:

| Confidence | Meaning |
|---|---|
| `Exact` | The simulator stayed consistent with the supplied SQL and baseline. |
| `Tainted` | Some baseline evidence or state transition was unavailable, stale, unsupported, or uncertain. |

`Exact` means exact relative to the modeled evidence; it is not a production
deployment guarantee.

- Exit `0`: analysis completed without a Tier 1 finding.
- Exit `1`: invocation, configuration, parser, cache, I/O, or internal failure.
- Exit `2`: analysis completed with at least one Tier 1 finding.

Diagnostics go to standard error. JSON and Markdown reports go to standard
output.

## Configuration

All settings are optional. By default, safe-migrate reads
`safe-migrate.toml` from the current directory.

```toml
# Lock-sensitive size thresholds.
tier1_threshold_rows = 100000
tier2_threshold_rows = 10000
default_rows = 10000
toast_width_threshold_bytes = 2048

# Cache policy.
stale_stats_days = 7
schemas = ["public", "auth"]
auto_sync = false
cache_encryption = false

# Used only when no cache supplies a PostgreSQL version.
assume_pg_version = 100000

# Primary rule IDs disabled globally.
disabled_rules = ["missing-idempotency"]

[rules.blocking-constraint]
tier1_threshold_rows = 5000
tier2_threshold_rows = 1000

[rules.missing-idempotency]
disabled = true
```

Per-rule settings support `disabled`, `tier1_threshold_rows`, and
`tier2_threshold_rows`. Unknown settings and unknown primary rule IDs are
rejected, so configuration typos cannot silently change analysis.

### Suppressing reviewed findings

Use a primary rule ID in a SQL comment to suppress that rule for one statement
or the whole file:

```sql
-- safe-migrate: ignore(require-concurrent-index)
CREATE INDEX users_email_idx ON users (email);

/* safe-migrate: ignore-file(missing-idempotency) */
```

Keep suppressions narrow and explain the operational reason in the migration or
its review.

### Automatic sync

`auto_sync = true` refreshes the cache before `lint` and `lint-chain`. There is
no command-line flag for it. If refresh fails, safe-migrate prints the cause and
continues with the previous readable cache; the old cache is replaced only
after a new cache has been written successfully. `--no-cache` bypasses
automatic sync.

### Cache encryption

Set `cache_encryption = true` and provide a 32-byte key as 64 hexadecimal
characters:

```bash
export SAFE_MIGRATE_CACHE_KEY='64 hexadecimal characters'
safe-migrate sync
```

The key is accepted only through the environment. Encrypted mode rejects
plaintext caches, and plaintext mode rejects encrypted caches. Changing modes
requires a fresh `sync`.

Cache files contain schema names, object metadata, dependencies, privileges,
and statistics. They do not contain `DATABASE_URL` or credentials, but should
still be treated as sensitive and kept out of public artifacts.

### Cache compatibility

v0.4.3 writes the headered V3 cache format. V1 and V2 caches remain readable;
v0.4.2 caches must be rebuilt:

```bash
safe-migrate sync
```

Use `safe-migrate cache inspect` to view cache provenance and redacted counts
without connecting to PostgreSQL.

## Rule catalog

The engine evaluates these 26 primary rules:

| ID | Checks |
|---|---|
| `irreversible-migration` | Irreversible table/column changes and lossy type changes. |
| `drop-database` | `DROP DATABASE`. |
| `drop-schema-cascade` | `DROP SCHEMA ... CASCADE`. |
| `destructive-general-cascade` | Cascading drops of non-table objects. |
| `destructive-cascade` | `DROP TABLE ... CASCADE` and dependent objects. |
| `create-table-as-select` | `CREATE TABLE ... AS SELECT` against an existing baseline. |
| `size-aware-add-column` | Add-column operations that can rewrite large tables. |
| `type-change-rewrite` | Type changes requiring a table rewrite. |
| `blocking-constraint` | Synchronous constraint validation. |
| `require-concurrent-index` | Synchronous index creation or removal. |
| `blocking-mat-view-refresh` | Non-concurrent materialized-view refresh. |
| `blocking-partition-mutation` | Partition attach/detach locking. |
| `partition-strategy-mismatch` | Incompatible partition strategies. |
| `restrictive-policy` | Restrictive row-level security policies. |
| `disable-trigger` | Disabling triggers. |
| `broken-compute` | Dropping functions still referenced by triggers. |
| `function-volatility-change` | Changing function volatility. |
| `missing-idempotency` | Missing safe rerun guards where supported. |
| `concurrent-in-transaction` | Concurrent index operations inside transactions. |
| `alter-type-add-value-txn` | Transaction-sensitive enum changes. |
| `vacuum-full` | `VACUUM FULL`. |
| `opaque-dynamic-sql` | SQL that cannot be fully simulated. |
| `volatile-default` | Volatile column defaults. |
| `overbroad-grant` | Broad grants such as `PUBLIC` or `ALL PRIVILEGES`. |
| `schema-drift` | References inconsistent with, or outside, the supplied baseline. |
| `chain-conflict` | Statements that cannot execute against the simulated migration state. |

The `blocking-constraint` rule can emit `blocking-index-constraint`, and
`require-concurrent-index` can emit `require-concurrent-drop-index`. Rewrite
analysis can emit `table-rewrite-storage` or `table-rewrite-access-method`.
These are finding IDs, not independently configurable primary rules.

## GitHub Actions

The reusable Action creates JSON and Markdown artifacts without connecting to a
database. It defaults to `no-cache: "true"` because files in a pull-request
checkout are controlled by that pull request.

```yaml
- id: safe_migrate
  uses: dsecurity49/safe-migrate@v0.4.3
  with:
    mode: lint-chain
    path: migrations
    output-dir: safe-migrate-artifacts

- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: safe-migrate-report
    path: safe-migrate-artifacts/
```

To use database-aware findings, prepare a cache in a trusted workflow step and
set both `cache: <path>` and `no-cache: "false"`. The Action exposes
`json-report`, `markdown-report`, `diagnostic-log`, and `exit-code`.

## Documentation

- [CLI and report contract](docs/CONTRACT.md)
- [Contributing](CONTRIBUTING.md)
- [Maintainer documentation](docs/README.md)
- [Release history](CHANGELOG.md)
- [Releases and binary downloads](https://github.com/dsecurity49/safe-migrate/releases)

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
