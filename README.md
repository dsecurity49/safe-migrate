# safe-migrate

safe-migrate finds risky PostgreSQL migrations before they reach production. It
parses a migration, simulates its schema changes, and explains blocking locks,
unsafe constraints, dependency conflicts, privilege changes, and other rollout
risks.

Its analysis is grounded in a synchronized snapshot of the database it protects.
`sync` reads PostgreSQL catalogs in a read-only transaction; later checks use
that encrypted or local baseline without database access. safe-migrate never
executes migration SQL.

## Install

With Rust installed:

```bash
cargo install safe-migrate --locked
safe-migrate --version
```

Prebuilt binaries are available from
[GitHub Releases](https://github.com/dsecurity49/safe-migrate/releases). To use
the checksum-verifying installer, pin it to the release you want:

```bash
VERSION='v0.8.0'
curl -fsSL "https://raw.githubusercontent.com/dsecurity49/safe-migrate/${VERSION}/install.sh" |
  bash -s -- --version "${VERSION}"
safe-migrate --version
```

Download `install.sh` first and run `sh install.sh --help` for destination and
target options.

## Quick start

```bash
export DATABASE_URL='postgres://readonly_user@localhost:5432/app'
safe-migrate sync
safe-migrate cache inspect
safe-migrate lint-chain --dir migrations
```

`sync` reads PostgreSQL metadata and writes `.safe-migrate.cache`; it does not
execute migration SQL. Later lint runs are offline unless you explicitly enable
automatic synchronization.

The snapshot reflects the connected role and its session defaults. See the
[Action guide](docs/GITHUB_ACTIONS.md#database-role-and-runner-security) when
choosing between a restricted catalog reader and the actual migration role.

Direct remote database connections are rejected. Use localhost, a Unix socket,
or a trusted tunnel:

```bash
ssh -N -L 5433:db.internal:5432 bastion
export DATABASE_URL='postgres://readonly_user@localhost:5433/app'
safe-migrate sync
```

The cache contains schema, role, privilege, dependency, and statistics metadata.
It contains no credentials, password hashes, or subscription connection strings,
but it is still infrastructure metadata and should be treated as sensitive.

## Add it to GitHub Actions

Create a protected GitHub environment named `safe-migrate-baseline`, then run:

```bash
safe-migrate init github-actions \
  --path migrations \
  --configure-secrets
```

This creates a trusted baseline-refresh workflow and an offline PR-analysis
workflow. Configure the refresh runner's local or tunneled database access,
then run **Refresh safe-migrate baseline** once.

A missing baseline or encryption key is an operational error. This prevents a
normal CI run from silently degrading into broad conservative findings.

See the [GitHub Action guide](docs/GITHUB_ACTIONS.md) for manual secret setup,
runner access, forks, multiple databases, and the security model.

## Commands

| Command | Purpose |
| --- | --- |
| `lint --file migration.sql` | Check one migration. |
| `lint-chain --dir migrations/` | Check ordered migrations while carrying schema state forward. |
| `sync` | Refresh the local database baseline. |
| `cache inspect` | Show baseline provenance and redacted object counts. |
| `rules` | Explore rules, remediation, and effective settings. |
| `init github-actions --path migrations/` | Generate isolated baseline-refresh and PR-analysis workflows. |
| `init cache-key` | Generate a cache-encryption key. |

Run `safe-migrate <command> --help` for all options.

`--no-cache` is an explicit degraded mode for parser investigation and limited
SQL-only checks. Because existing objects and database evidence are unknown,
its findings are conservative and its confidence is `Tainted`; it is not the
recommended CI configuration.

## Understand the result

Findings are grouped by severity:

- `Tier1` is a blocking safety problem.
- `Tier2` needs review but does not fail the command by default.
- `Tier3` is informational guidance.

Every finding includes a stable rule ID, an explanation, and a remediation when
one is available. Use `safe-migrate rules` to browse the rule catalog or
`safe-migrate rules --rule require-concurrent-index` to inspect one rule.

Exit statuses are stable for automation:

- `0`: analysis completed without a Tier 1 finding.
- `1`: configuration, parsing, cache, I/O, or another operational failure.
- `2`: analysis completed with at least one Tier 1 finding.

Use `--json` for machine-readable output or `--markdown` for a deterministic
review report. The complete schema and confidence semantics are documented in
the [CLI and report contract](docs/CONTRACT.md).

## Configuration

safe-migrate uses `safe-migrate.toml` from the current directory when present.
Most projects can begin with the built-in defaults. A small configuration might
look like this:

```toml
schemas = ["public", "auth"]
tier1_threshold_rows = 100000

[rules.missing-idempotency]
disabled = true
```

Unknown settings and rule IDs are rejected. `safe-migrate rules --json` lists
the settings supported by each rule.

To suppress one finding where the operational tradeoff has been reviewed, use
its primary rule ID:

```sql
-- safe-migrate: ignore(require-concurrent-index)
CREATE INDEX users_email_idx ON users (email);
```

Keep suppressions narrow and explain the reason in the migration or its review.

For thresholds, automatic sync, cache encryption, compatibility, and report
fields, see the [CLI and report contract](docs/CONTRACT.md).

## Migration timeouts

safe-migrate reports when lock-sensitive migrations do not establish suitable
timeouts. If your migration runner does not already set them, add them to the
migration:

```sql
SET lock_timeout = '5s';
SET statement_timeout = '15min';
```

Keep a positive `lock_timeout` shorter than a positive `statement_timeout`, so
lock acquisition fails before the whole migration reaches its statement limit.

## Rust library API

Rust integrations should use the supported `safe_migrate::api` façade. It
provides configuration, cache loading, analysis, findings, and evidence without
exposing mutable parser or state-machine internals. API documentation is
published on [docs.rs](https://docs.rs/safe-migrate).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development commands, test suites,
and pull-request expectations.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
