# safe-migrate

safe-migrate finds risky PostgreSQL migrations before they reach production. It
parses a migration, simulates its schema changes, and explains blocking locks,
unsafe constraints, dependency conflicts, privilege changes, and other rollout
risks.

You can try it without a database. For more accurate results, synchronize a
read-only snapshot of the PostgreSQL catalog once and lint against it offline.
safe-migrate never applies migration SQL.

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

## Try it

Check an ordered migration directory without connecting to PostgreSQL:

```bash
safe-migrate lint-chain --dir migrations --no-cache
```

Or check one file:

```bash
safe-migrate lint --file migrations/001_add_status.sql --no-cache
```

This first run uses `Tainted` confidence because safe-migrate cannot see the
existing database. It still reports risks that can be established from the SQL
itself. A synchronized baseline adds table sizes, dependencies, privileges,
PostgreSQL version, search path, and timeout settings.

## Add a database baseline

Use the database role and defaults that run your migrations. The role should
have only the catalog-read access needed by `sync`.

```bash
export DATABASE_URL='postgres://readonly_user@localhost:5432/app'
safe-migrate sync
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
It contains no credentials or password hashes, but you should still treat it as
sensitive and avoid publishing it.

## Add it to GitHub Actions

Generate a PR workflow in the current repository:

```bash
safe-migrate init github-actions --path migrations
```

That workflow works immediately without database access. On a cache miss it
checks the migrations with `Tainted` confidence and explains that the baseline
is unavailable.

When you are ready for database-aware CI, generate the trusted refresh job and
configure its two secrets through the authenticated GitHub CLI:

```bash
safe-migrate init github-actions \
  --path migrations \
  --force \
  --with-baseline \
  --configure-secrets
```

The generated workflow keeps `DATABASE_URL` out of pull-request jobs. Managed
baselines are encrypted by default, restored automatically, and refreshed only
from the default branch or a manual run. Review the runner and environment
settings before committing the workflow.

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
| `init github-actions --path migrations/` | Generate a safe GitHub Actions workflow. |
| `init cache-key` | Generate a cache-encryption key. |

Run `safe-migrate <command> --help` for all options.

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
