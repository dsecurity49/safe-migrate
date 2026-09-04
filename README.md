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

`sync` captures the connected role and its session defaults. Use the migration
role when exact role-sensitive analysis matters, or a dedicated catalog-reading
login when minimizing credential impact matters more. Database access is needed
only while refreshing the baseline; the [Action guide](docs/GITHUB_ACTIONS.md)
explains this tradeoff in more detail.

```bash
export DATABASE_URL='postgres://readonly_user@localhost:5432/app'
safe-migrate sync
safe-migrate cache inspect
safe-migrate lint-chain --dir migrations
```

`sync` reads PostgreSQL metadata and writes `.safe-migrate.cache`; it does not
execute migration SQL. Later lint runs are offline unless you explicitly enable
automatic synchronization.

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

Generate separate trusted-refresh and pull-request workflows:

```bash
safe-migrate init github-actions --path migrations
```

This is one-time repository setup. Once the baseline exists, ordinary pull
requests need no database connection and no per-PR synchronization.

After creating the `safe-migrate-baseline` GitHub environment, the initializer
can also configure the two secrets through an authenticated GitHub CLI:

```bash
safe-migrate init github-actions \
  --path migrations \
  --force \
  --configure-secrets
```

`SAFE_MIGRATE_DATABASE_URL` is stored only in the baseline environment;
`SAFE_MIGRATE_CACHE_KEY` is a repository secret so trusted pull-request jobs can
decrypt the snapshot. Configure the refresh runner's localhost, Unix-socket, or
tunnel access, then run **Refresh safe-migrate baseline** once. Pull-request
jobs never receive the database URL and never save or refresh the baseline.

A missing baseline or encryption key is an operational error. This prevents a
normal CI run from silently degrading into broad conservative findings.

To create a cache key without configuring GitHub, run
`safe-migrate init cache-key`. Add `--set-github-secret` to send a new key to
the current repository through an authenticated GitHub CLI. The plain command
writes the secret to standard output, so do not run it in public CI logs.

See the [GitHub Action guide](docs/GITHUB_ACTIONS.md) for the manual workflow,
fork behavior, multiple databases, custom configuration, and the complete
security model.

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
