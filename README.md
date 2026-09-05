<p align="center">
  <img src="docs/logo.svg" width="120" alt="safe-migrate logo">
</p>

<h1 align="center">safe-migrate</h1>

<p align="center">
  <a href="https://github.com/dsecurity49/safe-migrate/actions/workflows/ci.yml"><img src="https://github.com/dsecurity49/safe-migrate/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://crates.io/crates/safe-migrate"><img src="https://img.shields.io/crates/v/safe-migrate.svg" alt="crates.io version"></a>
  <a href="https://docs.rs/safe-migrate"><img src="https://docs.rs/safe-migrate/badge.svg" alt="docs.rs"></a>
</p>

safe-migrate finds risky PostgreSQL migrations before they reach production.
It parses SQL, simulates schema changes, and checks the result against a
synchronized database snapshot. It never executes migration SQL.

PostgreSQL 14–18 are supported.

## Install

With Rust installed:

```bash
cargo install safe-migrate --locked
```

Prebuilt binaries are available from
[GitHub Releases](https://github.com/dsecurity49/safe-migrate/releases). The
installer verifies release checksums:

```bash
VERSION='v0.8.1'
curl -fsSL "https://raw.githubusercontent.com/dsecurity49/safe-migrate/${VERSION}/install.sh" |
  bash -s -- --version "${VERSION}"
```

Download `install.sh` first and run `sh install.sh --help` to review destination
and target options.

## Quick start

```bash
export DATABASE_URL='postgres://readonly_user@localhost:5432/app'
safe-migrate sync
safe-migrate lint-chain --dir migrations
```

`sync` writes `.safe-migrate.cache`. Later checks use that snapshot offline.
Run `safe-migrate cache inspect` to view its provenance and redacted contents.

## What it checks

The 28 built-in rules cover:

- blocking locks, table rewrites, constraints, indexes, partitions, and
  materialized-view refreshes;
- destructive changes, cascades, schema drift, dependency breakage, and
  migration ordering conflicts;
- grants, policies, disabled triggers, roles, and privilege-sensitive changes;
- missing timeouts, transaction-incompatible operations, dynamic SQL,
  volatile defaults, and rerun safety.

Run `safe-migrate rules` for the catalog or inspect one rule directly:

```bash
safe-migrate rules --rule require-concurrent-index
```

## GitHub Actions

Create the `safe-migrate-baseline` GitHub environment, then run:

```bash
safe-migrate init github-actions --path migrations --configure-secrets
```

This generates a trusted baseline refresh and an offline PR check. Follow the
[GitHub Action guide](docs/GITHUB_ACTIONS.md) to connect the runner and create
the first baseline.

## Results

| Tier | Meaning | Default command result |
| --- | --- | --- |
| `Tier1` | Blocking safety problem | Exit `2` |
| `Tier2` | Needs review | Exit `0` |
| `Tier3` | Informational guidance | Exit `0` |

Operational failures—such as invalid SQL, configuration, or cache data—exit
`1`. Every finding includes a stable rule ID, a reason, and remediation:

```text
[HALT] Require concurrent index (require-concurrent-index)
  reason : Creating this index can block writes on a large table.
  recipe : Use CREATE INDEX CONCURRENTLY outside a transaction.
```

Use `--json` for automation or `--markdown` for review artifacts. See the
[CLI and report contract](docs/CONTRACT.md) for schemas, confidence, verdicts,
and compatibility guarantees.

## Commands

| Command | Purpose |
| --- | --- |
| `lint --file migration.sql` | Check one migration. |
| `lint-chain --dir migrations/` | Check ordered migrations with state carried forward. |
| `sync` | Refresh the database baseline. |
| `cache inspect` | Show baseline provenance and redacted counts. |
| `rules` | Browse rules and effective settings. |
| `init github-actions --path migrations/` | Generate the GitHub integration. |
| `init cache-key` | Generate a cache-encryption key. |

Run `safe-migrate <command> --help` for every option.

## Database baseline

`sync` reads PostgreSQL catalogs in a read-only, repeatable-read transaction.
Direct remote connections are rejected; use localhost, a Unix socket, or a
trusted tunnel:

```bash
ssh -N -L 5433:db.internal:5432 bastion
export DATABASE_URL='postgres://readonly_user@localhost:5433/app'
safe-migrate sync
```

The snapshot reflects the connected role and its session defaults. Choose
between a restricted catalog reader and the real migration role based on the
accuracy and credential tradeoff described in the
[Action guide](docs/GITHUB_ACTIONS.md#database-role-and-runner-security).

The cache contains infrastructure metadata, including schema, roles,
privileges, dependencies, and statistics. It contains no credentials, password
hashes, or subscription connection strings, but should still be treated as
sensitive.

`--no-cache` is an explicit degraded mode for parser investigation and limited
SQL-only checks. Existing objects are unknown, so confidence is `Tainted` and
many findings become conservative.

## Configuration

Most projects can start with the built-in defaults. Place overrides in
`safe-migrate.toml`:

```toml
schemas = ["public", "auth"]
tier1_threshold_rows = 100000

[rules.missing-idempotency]
disabled = true
```

Unknown settings and rule IDs are rejected. `safe-migrate rules --json` lists
the configuration supported by each rule.

Suppress a reviewed finding with its primary rule ID:

```sql
-- safe-migrate: ignore(require-concurrent-index)
CREATE INDEX users_email_idx ON users (email);
```

Keep suppressions narrow and explain the reason in the migration review.

## Migration timeouts

If the migration runner does not already set timeouts, add them before
lock-sensitive changes:

```sql
SET lock_timeout = '5s';
SET statement_timeout = '15min';
```

Keep a positive `lock_timeout` shorter than a positive `statement_timeout`.

## Rust library

Rust integrations should use the supported `safe_migrate::api` façade.
Documentation is published on [docs.rs](https://docs.rs/safe-migrate).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development commands, test suites,
and pull-request expectations.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
