# safe-migrate

safe-migrate checks PostgreSQL migrations against a synchronized database
baseline. Run `safe-migrate sync`, then use `lint` or `lint-chain` offline to
simulate migrations against the captured state.

safe-migrate is a review aid, not a substitute for testing migrations on a
representative database or planning application rollouts and backfills.

## Install

### With Rust

If Rust is installed:

```bash
cargo install safe-migrate --locked
safe-migrate --version
```

### Prebuilt binary

The installer selects a supported Linux, macOS, Windows/MSYS, or Termux target
and verifies the release checksum:

```bash
curl -fsSL https://raw.githubusercontent.com/dsecurity49/safe-migrate/main/install.sh | bash
safe-migrate --version
```

To pin the installer and binary to one release:

```bash
VERSION='<release-tag>'
BASE_URL='https://raw.githubusercontent.com/dsecurity49/safe-migrate'
curl -fsSL "${BASE_URL}/${VERSION}/install.sh" |
  bash -s -- --version "${VERSION}"
```

Run `bash install.sh --help` after downloading the installer for pinning and
destination options. Archives, checksums, and manual downloads are available on
the
[GitHub Releases page](https://github.com/dsecurity49/safe-migrate/releases).

## Quick start

Create a database baseline, then lint one migration or a directory of ordered
migrations:

```bash
export DATABASE_URL='postgres://readonly_user:password@localhost:5432/app'

safe-migrate sync
safe-migrate cache inspect
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

`--no-cache` runs the parser and state machine without a verified database
baseline. Findings use `Tainted` confidence, meaning some database evidence is
missing, and settings such as migration timeouts remain unknown.

### What sync provides

SQL alone cannot show the existing schema, table statistics, dependencies,
role and search-path context, or inherited timeout settings. `sync` captures
that baseline once, so later `lint` runs are offline and review the same state.

Cache V6 includes all routine kinds, publications, and redacted subscription
metadata as well as ordinary schema state. It never stores subscription
connection strings. Refresh publisher-side state, or a publication edit that
does not use `ONLY`, remains `Tainted` when PostgreSQL inheritance or remote
publisher state would decide the outcome.

Sync with the database, role, and defaults used by the migration runner; it
only reads them. Refresh the cache when that baseline changes. If the runner
does not already enforce timeouts, put them explicitly in the migration:

```sql
SET lock_timeout = '5s';
SET statement_timeout = '15min';
```

`lock_timeout` should be positive and shorter than a positive
`statement_timeout`; otherwise PostgreSQL can reach the statement timeout
first.

## Commands

| Command | Use it for | Important options |
| --- | --- | --- |
| `lint --file migration.sql` | Check one migration. | `--cache`, `--config`, `--no-cache`, `--json`, `--markdown` |
| `lint-chain --dir migrations/` | Check an ordered migration directory while carrying state forward. | `--cache`, `--config`, `--no-cache`, `--json`, `--markdown` |
| `sync` | Refresh the database baseline. | `--out`, `--schemas`, `--config` |
| `cache inspect` | Show cache provenance and redacted object counts. | `--cache`, `--json` |
| `rules` | Discover rules, remediation, and effective settings. | `--rule`, `--json`, `--config` |

`--no-auto-sync` suppresses configured automatic refresh for one `lint` or
`lint-chain` run. `--no-color` works with every command.

Use the CLI for less common options and subcommands:

```bash
safe-migrate --help
safe-migrate <command> --help
```

Machine-readable output, confidence values, and exit codes are defined in the
[CLI and report contract](docs/CONTRACT.md).

## Rule discovery

`safe-migrate rules` lists rule IDs, tiers, remediation, supported
configuration fields, and effective settings. Rule discovery JSON uses schema
version 2; lint JSON uses schema version 1.

```bash
safe-migrate rules
safe-migrate rules --rule require-concurrent-index
safe-migrate rules --rule require-concurrent-index --json
```

Unknown IDs are errors. Pass `--config` to include settings from a TOML file.

## Chain analysis

`lint-chain` analyzes files in filename order and carries modeled schema,
transaction, search-path, and role state across statements and files. This can
catch failures caused by interactions between otherwise valid migrations.

## Migration timeouts

The Tier 2 `require-lock-timeout` and `require-statement-timeout` rules apply to
statements that Squawk classifies as potentially disruptive to normal database
queries. They use the synchronized values and follow ordered SQL changes from
`SET`, `SET LOCAL`, `SET ... DEFAULT`, `RESET`, and `RESET ALL`, including
commit, rollback, and savepoint scope. A missing baseline is reported as
unknown evidence rather than silently treated as a configured timeout.

## Findings and exit status

Findings use three tiers:

| Tier | Meaning |
| --- | --- |
| Tier 1 — `HALT` | Fix before deployment. |
| Tier 2 — `WARN` | Review required. |
| Tier 3 — `SAFE` | Informational or lower-risk. |

Reports also include confidence:

| Confidence | Meaning |
| --- | --- |
| `Exact` | Analysis stayed consistent with the supplied SQL and baseline. |
| `Tainted` | Baseline evidence or modeled state is incomplete or uncertain. |

`Exact` means exact relative to the modeled evidence; it is not a production
deployment guarantee.

- Exit `0`: analysis completed without a Tier 1 finding.
- Exit `1`: invocation, configuration, parser, cache, I/O, or internal failure.
- Exit `2`: analysis completed with at least one Tier 1 finding.

Diagnostics go to standard error. JSON and Markdown reports go to standard
output.

## Configuration

Without `--config`, the CLI reads `safe-migrate.toml` from the current
directory when it exists and otherwise uses built-in defaults. A path passed
with `--config` must exist and pass validation.

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

Every primary rule supports `disabled`; only row-sensitive rules support one or
both threshold fields. `safe-migrate rules --json` lists the supported fields
for each rule. Unknown settings, unsupported fields, and unknown primary rule
IDs are errors.

### Suppressions

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
no command-line flag to enable it. Use `--no-auto-sync` to suppress it for one
lint run. If refresh fails, safe-migrate prints the cause and continues with the
previous readable cache; the old cache is replaced only after a new cache has
been written successfully. `--no-cache` also bypasses automatic sync. The
previous cache must already be V6; an unsupported V1–V5 cache cannot be reused
after a failed refresh.

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

Cache files contain schema and role names, dependencies, privileges, and
statistics. They do not contain connection credentials or password hashes.
Treat cache files as sensitive and do not publish them.

### Cache compatibility

When safe-migrate encounters an unsupported cache format, rebuild it from the
database:

```bash
safe-migrate sync
```

v0.6.0 introduces Cache V6 for synchronized timeout provenance, the complete
routine namespace, publications, and redacted subscriptions. Every V1–V5 cache
requires resynchronization.

Use `safe-migrate cache inspect` to view cache provenance and redacted object
and role counts without connecting to PostgreSQL. It never lists role names or
membership edges.

## GitHub Actions

The Action uses a baseline: one cache file containing a snapshot of your
database metadata. The Action manages that file and its GitHub cache entry for
you.

```text
Trusted default-branch job
PostgreSQL -> sync -> runner baseline file -> GitHub Actions cache

Pull-request job
GitHub Actions cache -> runner baseline file -> lint-chain -> reports
```

The Action uses
`~/.cache/safe-migrate-action/baselines/<baseline>/baseline-v6.cache` on the
runner. After a successful sync, it saves that file in GitHub Actions cache
under the `default` baseline name. A pull-request run restores the file to the
same managed path, then runs `lint-chain` with it; it does not connect to
PostgreSQL or run `sync` again. GitHub-hosted runners are discarded after the
job; on self-hosted runners the Action clears the selected baseline before each
restore.

### 1. Refresh the baseline

Run this after checkout in a trusted default-branch workflow. PostgreSQL must
be reachable through localhost or a Unix socket; keep its URL in a secret. We
recommend encrypting the saved baseline: it contains schema and role metadata,
and GitHub cache contents are not signed. Store a 64-character hexadecimal key
as `SAFE_MIGRATE_CACHE_KEY` and pass it to both workflows.

```yaml
- uses: dsecurity49/safe-migrate@v0.7.0
  env:
    DATABASE_URL: ${{ secrets.SAFE_MIGRATE_DATABASE_URL }}
    SAFE_MIGRATE_CACHE_KEY: ${{ secrets.SAFE_MIGRATE_CACHE_KEY }}
  with:
    path: migrations
    sync: "true"
    schemas: public
    encrypted-cache: "true"
```

Replace `public` with the schemas that contain your migrations, or omit
`schemas` to synchronize all non-system schemas.

### 2. Lint pull requests without syncing

Add this after checkout in the pull-request workflow:

```yaml
- uses: dsecurity49/safe-migrate@v0.7.0
  env:
    SAFE_MIGRATE_CACHE_KEY: ${{ secrets.SAFE_MIGRATE_CACHE_KEY }}
  with:
    path: migrations
    encrypted-cache: "true"
```

Do not set `sync: "true"` here, and do not add `actions/cache`. The Action
restores the baseline itself, passes it to `lint-chain`, and publishes the
report. Fork pull requests do not receive the encryption key, so they lint
without the baseline and report `Tainted` confidence.

For TOML configuration, encrypted caches, named baselines, and complete
workflows, see the [GitHub Action guide](docs/GITHUB_ACTIONS.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
