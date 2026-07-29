# safe-migrate v0.4.3

safe-migrate checks PostgreSQL migrations by simulating schema changes before
they reach production. A synced local cache supplies production schema metadata
and row-count estimates for checks whose severity depends on the current
database.

It is a safety aid, not a substitute for testing a migration on a representative
database or for planning application-level rollout and backfill work.

## Install

### With Cargo

If you already use Rust, install the latest crates.io release with locked
dependencies:

```bash
cargo install safe-migrate --locked
safe-migrate --version
```

Use `cargo install safe-migrate --locked --version 0.4.2` to reproduce a
specific published crate release. Cargo installs the binary into its configured
binary directory (normally `~/.cargo/bin`), which must be on `PATH`.

### Without Rust: download a release binary

The recommended installation path is the repository installer. It detects the
supported Linux, macOS, and Termux target, downloads the matching GitHub Release
archive, verifies its published SHA-256 checksum, and installs `safe-migrate`
to a writable binary directory.

To install a specific release, download the installer from that same tag and
run it locally:

```bash
version=v0.4.2
curl -fLO "https://raw.githubusercontent.com/dsecurity49/safe-migrate/$version/install.sh"
sh install.sh --version "$version"
safe-migrate --version
```

Use `sh install.sh --help` to choose `--install-dir`, force a `--target`, or
replace an existing binary with `--force`. Running the current installer
without `--version` selects the latest published release.

Use `sh install.sh --dry-run --version v0.4.2` to inspect the selected target,
release URL, and destination without downloading or changing files. A dry run
with no version intentionally reports that a real install would first resolve
the latest release; it never makes that network request itself.

### Manual release download

Release archives and SHA-256 checksum files are published on the
[GitHub Releases page](https://github.com/dsecurity49/safe-migrate/releases).
Choose the archive matching your platform:

| Platform | Archive |
|---|---|
| Linux x86_64 (glibc) | `safe-migrate-x86_64-unknown-linux-gnu.tar.gz` |
| Linux x86_64 (musl/Alpine) | `safe-migrate-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 (glibc) | `safe-migrate-aarch64-unknown-linux-gnu.tar.gz` |
| Linux ARM64 (musl/Alpine) | `safe-migrate-aarch64-unknown-linux-musl.tar.gz` |
| macOS Intel | `safe-migrate-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `safe-migrate-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 | `safe-migrate-x86_64-pc-windows-msvc.zip` |

For example, install a published Linux x86_64 musl release and verify it. Set
`version` to the tag you want from the Releases page:

```bash
version=v0.4.2
asset=safe-migrate-x86_64-unknown-linux-musl
base="https://github.com/dsecurity49/safe-migrate/releases/download/$version/$asset"

curl -fLO "$base.tar.gz"
curl -fLO "$base.sha256"
sha256sum -c "$asset.sha256"
tar -xzf "$asset.tar.gz"
install -m 755 safe-migrate "$HOME/.local/bin/safe-migrate"
safe-migrate --version
```

Add `~/.local/bin` to `PATH` if needed. On macOS, use `shasum -a 256 -c` for
checksum verification. Windows users can extract the ZIP and verify the
adjacent `.sha256` file with `Get-FileHash` before adding the executable to
`PATH`. The installer is the preferred path on Termux because it selects the
appropriate install directory automatically.

### Build from source

Install the Rust toolchain, clone this repository, then build with the locked
dependency set:

```bash
git clone https://github.com/dsecurity49/safe-migrate.git
cd safe-migrate
cargo build --locked --release
install -m 755 target/release/safe-migrate "$HOME/.local/bin/safe-migrate"
```

Run `cargo test --locked` before relying on a locally built development binary.

## Quick start

Sync a local baseline before linting migrations that touch existing objects:

```bash
# Use a role that can read PostgreSQL catalogs. Keep this outside TOML and Git.
export DATABASE_URL='postgres://readonly_user:password@localhost:5432/app'

# Create the local baseline cache, then check one migration.
safe-migrate sync
safe-migrate lint --file migrations/20260727_add_status.sql
```

`sync` writes `.safe-migrate.cache` by default. It reads PostgreSQL catalog
metadata and needs a database role able to read those catalogs; use a
least-privilege role and do not put `DATABASE_URL` or its credentials in
`safe-migrate.toml`.

For safety, this build only syncs through localhost or a Unix socket. For a
remote database, create an SSH tunnel and point `DATABASE_URL` at the local
end, for example `ssh -N -L 5433:db.internal:5432 bastion` followed by
`postgres://readonly_user@localhost:5433/app`.

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

### Configuration reference

| Setting | Default | Effect |
|---|---:|---|
| `tier1_threshold_rows` | `100000` | Default table-size threshold for Tier 1 lock-sensitive findings. |
| `tier2_threshold_rows` | `10000` | Default table-size threshold for Tier 2 lock-sensitive findings. |
| `default_rows` | `10000` | Conservative row estimate when no usable statistics are available. |
| `stale_stats_days` | `7` | Maximum cache age before the baseline becomes `stale` and confidence becomes `Tainted`. |
| `toast_width_threshold_bytes` | `2048` | Width threshold used by storage/rewrite analysis. |
| `assume_pg_version` | `100000` | PostgreSQL version assumed only when no cache supplies one. |
| `schemas` | unset | Schemas included by `sync` and configured automatic sync. Explicit `sync --schemas` takes precedence. |
| `auto_sync` | `false` | Refreshes the cache before `lint` and `lint-chain`. It has no command-line flag. |
| `cache_encryption` | `false` | Encrypts new cache files and requires `SAFE_MIGRATE_CACHE_KEY` to read them. |
| `disabled_rules` | `[]` | Primary rule IDs disabled globally. |

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
safe-migrate lint --file migration.sql [--cache path] [--config path] [--no-cache] [--json | --markdown]

# Ordered .sql files, retaining simulated state across the chain
safe-migrate lint-chain --dir migrations/ [--cache path] [--config path] [--no-cache] [--json | --markdown]

# Refresh the local cache; --config is used for cache_encryption
safe-migrate sync [--out .safe-migrate.cache] [--config safe-migrate.toml] [--schemas public,auth]

# Inspect cache provenance and a redacted contents summary without connecting
# to PostgreSQL.
safe-migrate cache inspect [--cache .safe-migrate.cache] [--config safe-migrate.toml] [--json]
```

`--interactive` is available for human exploration and cannot be combined with
`--json` or `--markdown`. `--markdown` produces a deterministic review report
with file/line/column locations. `sync --schemas` overrides the configured `schemas` list for that
one refresh. Cache paths are local files; do not commit an unreviewed cache or
an encrypted cache key.

### Cache lifecycle

`sync` writes cache replacements atomically: a failed refresh leaves the prior
cache untouched. New cache files record their creation timestamp, source
database name, and selected schemas. `lint --json` and `lint-chain --json`
expose that information in the additive `baseline` object.

Refresh a cache after significant production schema changes, after changing
the selected schemas, or when the report marks it `stale`. A cache is not a
database backup and never stores connection credentials. It does contain schema,
object, column, function, role-grant, dependency, and statistical metadata, so
treat it as sensitive. `safe-migrate cache inspect` shows provenance and counts
only; it deliberately omits object and dependency names. Cache encryption
protects the local payload but does not make it safe to share indiscriminately.

### Sync access and cache handling

`sync` is read-only: it runs `SHOW`, `SELECT`, and catalog/view functions over
PostgreSQL metadata. Use a dedicated login role with no write, ownership,
replication, role-administration, or server-file privileges. Start with the
schemas that need migration review:

```sql
CREATE ROLE safe_migrate_sync LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE app TO safe_migrate_sync;
GRANT USAGE ON SCHEMA public, auth TO safe_migrate_sync;
```

Do not grant `pg_read_all_data`, `pg_monitor`, or broad table `SELECT` merely
to run safe-migrate. The catalog snapshot will work with reduced detail; in
particular, PostgreSQL exposes `pg_stats` rows only for tables a role can read,
so `avg_width` can be unavailable. If fuller width estimates are worth the data
access, grant `SELECT` only on explicitly approved tables (or columns) after a
security review. `pg_read_all_stats` is also optional and exposes wider server
statistics; do not treat it as a default least-privilege grant.

For a shareable or lower-sensitivity baseline, create a new cache from an
approved schema scope or sanitized database—do not try to edit a cache in
place, because object names and dependencies must remain consistent. Store
caches outside Git and CI logs, restrict local permissions (for example,
`chmod 600 .safe-migrate.cache`), and use short artifact retention. To rotate
an encrypted cache, generate a new `SAFE_MIGRATE_CACHE_KEY`, run `sync` to a
new cache, update the secret store, then remove the old cache/artifact through
your platform’s approved retention process.

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
| `chain-conflict` | Statements that cannot execute against the simulated state, including conflicts across `lint-chain` files. |

The `blocking-constraint` rule can emit `blocking-index-constraint`, and
`require-concurrent-index` can emit `require-concurrent-drop-index`. Rewrite
paths can also emit `table-rewrite-storage` or `table-rewrite-access-method`.
Those are finding IDs, not independently configurable primary rules.

## CI

Check in a reviewed cache only when it is acceptable for your team to store
schema metadata in the repository. Otherwise sync in CI from a protected
database secret and lint the migrations. Preserve exit status `2` as a blocked
migration, and treat `1` as an infrastructure/configuration failure. Do not
enable `auto_sync` implicitly in CI: make the sync step visible in the job.

```yaml
- name: Build, sync, and lint migrations
  env:
    DATABASE_URL: ${{ secrets.SAFE_MIGRATE_DATABASE_URL }}
  run: |
    cargo build --locked --release
    ./target/release/safe-migrate sync --out .safe-migrate.cache
    ./target/release/safe-migrate lint-chain --dir migrations --json > safe-migrate-report.json
```

For database-backed CI, add `DATABASE_URL` as a protected secret and run
`safe-migrate sync` in a controlled network environment before the lint step.
Never echo the URL or write it to the cache/configuration file. If CI cannot
reach PostgreSQL, use a deliberately reviewed cache or run with `--no-cache`
and treat the resulting `Tainted` confidence as a review requirement.

### Reusable GitHub Action

Starting with v0.4.3, the pinned Action produces deterministic JSON and Markdown
artifacts for one migration or an ordered migration directory. It is not
available in v0.4.2. The Action does not synchronize a database or use
`DATABASE_URL`; prepare a reviewed cache in a separate, explicit step if your
workflow needs database-aware findings.

```yaml
- id: safe_migrate
  uses: dsecurity49/safe-migrate@v0.4.3
  with:
    mode: lint-chain
    path: migrations
    cache: .safe-migrate.cache
    output-dir: safe-migrate-artifacts

- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: safe-migrate-report
    path: safe-migrate-artifacts/
```

The Action exposes `json-report`, `markdown-report`, `diagnostic-log`, and
`exit-code` outputs. It preserves exit code `2` for blocking findings, so use
`if: always()` for artifact upload and let the job fail when the migration must
be blocked. On exit `1`, inspect `diagnostic-log` for the operational failure.

## Development

```bash
cargo fmt -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cd live_tests && ./run.sh
```

See [the user-visible CLI/report contract](docs/CONTRACT.md),
[contributing guide](CONTRIBUTING.md), and [maintainer documentation](docs/README.md).
