# safe-migrate

safe-migrate is a sync-first PostgreSQL migration linter. `safe-migrate sync`
records the target database's schema, dependencies, statistics, role context,
search path, PostgreSQL version, and effective migration timeouts in a local
cache. `lint` and `lint-chain` then use that evidence to simulate migrations in
order and report operations that may block, rewrite data, destroy objects, or
fail against the modeled database state.

After synchronization, linting is offline. `--no-cache` is available for a
parser and state-machine preview, but it has no verified database baseline,
reports `Tainted` confidence, and cannot know the session's timeout defaults.

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

The installer detects supported Linux, macOS, Windows/MSYS, and Termux targets, verifies the
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

### Why sync is the main workflow

SQL text alone cannot prove what already exists, how large a table is, which
objects depend on it, which role and search path resolve an unqualified name,
or which timeout defaults the migration session will inherit. `sync` captures
that evidence once; subsequent reviews stay local and use the same baseline.

Run sync with the database, role, and role/database defaults intended for the
migration runner. Sync reads settings but does not change them. If the runner
does not already enforce timeouts, put them explicitly in the migration:

```sql
SET lock_timeout = '5s';
SET statement_timeout = '15min';
```

`lock_timeout` should be positive and shorter than a positive
`statement_timeout`; otherwise PostgreSQL can reach the statement timeout
first. Refresh the cache whenever the database baseline or inherited session
settings change.

## Commands

```text
safe-migrate lint --file migration.sql
safe-migrate lint-chain --dir migrations/
safe-migrate sync
safe-migrate cache inspect
safe-migrate rules
```

Useful options:

- `lint` and `lint-chain`: `--cache <path>`, `--config <path>`, `--no-cache`,
  `--json`, and `--markdown`.
- `sync`: `--out <path>` selects the cache destination, `--config <path>`
  selects configuration, and `--schemas public,auth` limits the synchronized
  schema scope.
- `cache inspect`: `--cache <path>`, `--config <path>`, and `--json` for a
  machine-readable summary.
- `rules`: `--rule <id>` selects one rule, `--json` emits the stable discovery
  schema, and `--config <path>` shows effective configuration values.
- `--no-color` disables colored output for every command.

Run `safe-migrate <command> --help` for the complete command reference.

### Chain analysis

`lint-chain` analyzes files in filename order and carries modeled schema,
transaction, search-path, and role state across statements and files. This can
catch failures caused by interactions between otherwise valid migrations.

### Timeout-aware analysis

The Tier 2 `require-lock-timeout` and `require-statement-timeout` rules apply to
statements that Squawk classifies as potentially disruptive to normal database
queries. They use the synchronized values and follow ordered SQL changes from
`SET`, `SET LOCAL`, `SET ... DEFAULT`, `RESET`, and `RESET ALL`, including
commit, rollback, and savepoint scope. A missing baseline is reported as
unknown evidence rather than silently treated as a configured timeout.

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

Every primary rule supports `disabled`; only row-sensitive rules support one or
both threshold fields. `safe-migrate rules --json` is the authority for each
rule's `supported_configuration_fields`. Unknown settings, unsupported fields,
and unknown primary rule IDs are rejected, so configuration mistakes cannot
silently change analysis.

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
automatic sync. The previous cache must already be V6; an unsupported V1–V5
cache cannot be reused after a failed refresh.

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
statistics. They do not contain connection credentials or password hashes, but
should still be treated as sensitive and kept out of public artifacts.

### Cache compatibility

When safe-migrate encounters an unsupported cache format, rebuild it from the
database:

```bash
safe-migrate sync
```

v0.6.0 introduces Cache V6 for synchronized `lock_timeout` and
`statement_timeout` provenance. Every V1–V5 cache requires resynchronization.

Use `safe-migrate cache inspect` to view cache provenance and redacted object
and role counts without connecting to PostgreSQL. It never lists role names or
membership edges.

## Rule discovery

Use the CLI registry instead of a copied documentation table. It is the
canonical source for every primary rule's ID, title, impact, default tier,
remediation, supported configuration fields, and effective configuration.
The discovery document is schema version 2; lint JSON remains schema version 1.

```bash
safe-migrate rules
safe-migrate rules --rule require-concurrent-index
safe-migrate rules --rule require-concurrent-index --json
```

Unknown IDs fail without changing analysis configuration. Use `--config` when
you need the discovery output to reflect a reviewed non-default configuration.

## GitHub Actions

The reusable Action downloads and verifies the exact release binary, creates
JSON and Markdown artifacts, appends the Markdown report to the job summary,
and emits Tier 1 errors and Tier 2 warnings as source annotations. It never
connects to a database. By default it runs an explicit no-cache preview because
files in a pull-request checkout are controlled by that pull request; the best
results come from a cache created in a separate trusted sync step.

```yaml
- id: safe_migrate
  uses: dsecurity49/safe-migrate@v0.6.0
  with:
    mode: lint-chain
    path: migrations
    output-dir: safe-migrate-artifacts
    advisory: "false"

- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: safe-migrate-report
    path: safe-migrate-artifacts/
```

To use database-aware findings, prepare a cache in a trusted workflow step and
set both `cache: <path>` and `no-cache: "false"`.

Set `config: safe-migrate.toml` to use a reviewed project configuration. When
`config` is omitted, the Action uses built-in defaults and deliberately does
not read `safe-migrate.toml` from the pull-request workspace.

The Action exposes `json-report`, `markdown-report`, `diagnostic-log`, and
`exit-code`. Set `advisory: "true"` to keep a completed analysis with Tier 1
findings from failing the job; its `exit-code` output remains `2`. Operational
errors always fail. Published uses must be pinned to an exact semantic tag or a
full commit SHA; mutable branch references are rejected. Local `uses: ./`
testing retains locked source installation.

## Documentation

- [CLI and report contract](docs/CONTRACT.md)
- [Contributing](CONTRIBUTING.md)
- [Maintainer documentation](docs/README.md)
- [Release history](CHANGELOG.md)
- [Releases and binary downloads](https://github.com/dsecurity49/safe-migrate/releases)

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
