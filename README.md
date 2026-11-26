<p align="center">
  <img src="docs/logo.svg" width="120" alt="safe-migrate logo">
</p>

<h1 align="center">safe-migrate</h1>

<p align="center">
  <a href="https://github.com/dsecurity49/safe-migrate/actions/workflows/ci.yml"><img src="https://github.com/dsecurity49/safe-migrate/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://crates.io/crates/safe-migrate"><img src="https://img.shields.io/crates/v/safe-migrate.svg" alt="crates.io version"></a>
  <a href="https://docs.rs/safe-migrate"><img src="https://docs.rs/safe-migrate/badge.svg" alt="docs.rs"></a>
</p>

safe-migrate catches dangerous PostgreSQL migrations before they reach production.
It parses your `.sql` files, simulates schema transitions step by step, and checks them against a synchronized snapshot of your database—without ever executing migration SQL.

Supports **PostgreSQL 14–18**.

## Install

With Rust 1.99 or newer:

```bash
cargo install safe-migrate --locked
```

Or install a checksum-verified release binary from [GitHub Releases](https://github.com/dsecurity49/safe-migrate/releases):

```bash
VERSION='v0.14.0'
curl -fsSL "https://raw.githubusercontent.com/dsecurity49/safe-migrate/${VERSION}/install.sh" |
  bash -s -- --version "${VERSION}"
```

## Quick start

1. **Sync a read-only baseline snapshot** from your database (via localhost, Unix socket, or SSH tunnel):
   ```bash
   export DATABASE_URL='postgres://readonly_user@localhost:5432/app'
   safe-migrate sync
   ```
2. **Lint a single migration or an ordered migration directory offline**:
   ```bash
   safe-migrate lint --file migrations/20261126_add_index.sql
   safe-migrate lint-chain --dir migrations/
   ```

When safe-migrate finds a risk, it tells you what blocks, why, and how to rewrite it safely:

```text
[HALT] Require concurrent index (require-concurrent-index)
  object : public.users_email_idx (index)
  file   : migrations/20261126_add_index.sql:4:1
  reason : CREATE INDEX on table 'public.users' (250,000 rows) takes a SHARE lock that blocks writes while the index builds.
  recipe : Use CREATE INDEX CONCURRENTLY outside a transaction block.
```

## What it checks

safe-migrate models tables, columns, indexes, constraints, partitions, views, materialized views, sequences, routines (functions, procedures, aggregates, and SQL-standard `BEGIN ATOMIC` / `RETURN` bodies), user-defined casts, extended statistics, domains, extensions, roles, and logical replication:

- **Lock & rewrite hazards**: table rewrites (`SET DATA TYPE`, `SET EXPRESSION`, `SET LOGGED`/`UNLOGGED`), blocking constraint scans (`ADD CONSTRAINT` without `NOT VALID`), non-concurrent `CREATE INDEX` / `REINDEX` / `REFRESH MATERIALIZED VIEW`, and size-independent lock-mode advisories (`lock-risk`, `set-storage-lock`).
- **Schema & dependency safety**: destructive drops, cascades (`DROP ... CASCADE`), schema drift against the baseline, broken views or routines after column/type changes, and statement ordering conflicts (`chain-conflict`).
- **Access & operational guardrails**: overbroad grants, restrictive RLS policies, disabled triggers, missing `lock_timeout` / `statement_timeout`, transaction-incompatible DDL, dynamic SQL, volatile defaults, and missing `IF EXISTS` / `IF NOT EXISTS` guards.

## GitHub Actions

safe-migrate keeps database credentials out of pull requests. A protected workflow refreshes and encrypts the baseline cache (`SAFE_MIGRATE_DATABASE_URL`), while pull requests only restore the encrypted cache (`SAFE_MIGRATE_CACHE_KEY`) and run offline.

### 1. Generate the workflows

Create a protected GitHub environment named `safe-migrate-baseline` (restricted to your default branch), then run:

```bash
safe-migrate init github-actions --path migrations --configure-secrets
```

This creates `.github/workflows/safe-migrate-baseline.yml` (scheduled/manual baseline refresh) and `.github/workflows/safe-migrate.yml` (offline PR check) and uploads both secrets via GitHub CLI.

### 2. Minimal PR workflow example

```yaml
name: Check migrations
on:
  pull_request:
  merge_group:

permissions:
  contents: read

jobs:
  safe-migrate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false

      - uses: dsecurity49/safe-migrate@v0.14.0
        with:
          path: migrations
        env:
          SAFE_MIGRATE_CACHE_KEY: ${{ secrets.SAFE_MIGRATE_CACHE_KEY }}
```

See the [GitHub Action guide](docs/GITHUB_ACTIONS.md) for baseline refresh setup, self-hosted/tunneled runners, fork policies, and all Action inputs/outputs.

## CLI commands

| Command | Description |
| --- | --- |
| `lint --file <path>` | Check a single migration file (`--json`, `--markdown`, or `--report-dir <dir>`). |
| `lint-chain --dir <path>` | Check `.sql` files in filename order with simulated schema state carried forward. |
| `sync` | Refresh `.safe-migrate.cache` from `DATABASE_URL` (`--schemas a,b` scopes sync). |
| `cache inspect` | Inspect cache provenance, PostgreSQL version, timeouts, and redacted counts. |
| `rules` | Browse all rules (`--rule <id>` for details, `--json` for machine metadata). |
| `init github-actions --path <dir>` | Generate the two-workflow GitHub Actions setup (`--configure-secrets`). |
| `init cache-key` | Generate a 32-byte hex encryption key (`--set-github-secret`). |

### Verdicts and exit codes

| Tier / Verdict | Meaning | Exit code |
| --- | --- | --- |
| `Tier1` (`HALT`) | Blocking safety or migration-ordering error | `2` |
| `Tier2` (`CAUTIOUS`) | Review required (or a Tier 1 check lacked baseline evidence) | `0` |
| `Tier3` (`SAFE WITH RISK` / `SAFE`) | Informational advisory | `0` |
| Operational error | Parse, I/O, configuration, or cache error | `1` |

See the [CLI and report contract](docs/CONTRACT.md) for JSON schemas, confidence rules, and precision boundaries.

## Configuration

Configure project defaults in `safe-migrate.toml`:

```toml
schemas = ["public", "auth"]
tier1_threshold_rows = 100000
target_database = "app"
assume_pg_version = 170000
stale_stats_days = 7

[rules.missing-idempotency]
disabled = true
```

To allow inline SQL suppressions (`-- safe-migrate: ignore(require-concurrent-index)`), set `allow_inline_suppressions = true` in `safe-migrate.toml`; otherwise inline directives emit a Tier 1 `inline-suppression-disabled` finding so suppressions stay visible in TOML review diffs.

If your migration runner does not set timeouts automatically, set them before lock-sensitive statements:

```sql
SET lock_timeout = '5s';
SET statement_timeout = '15min';
```

## Rust library

Embed safe-migrate in Rust tools via `safe_migrate::api`:

```rust,no_run
use safe_migrate::api::{self, Baseline, Config};
use std::path::Path;

let config = Config::load_from_file(Path::new("safe-migrate.toml"))?;
let baseline = Baseline::load_optional(Path::new(".safe-migrate.cache"), &config)?;
let outcome = api::analyze(
    &config,
    "2026-09-05_add_index.sql",
    "CREATE INDEX ...",
    &baseline,
)?;

if outcome.should_halt() {
    eprintln!("{}", outcome.markdown());
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Full API documentation is on [docs.rs](https://docs.rs/safe-migrate). See [CONTRIBUTING.md](CONTRIBUTING.md) for architecture and development workflows.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
