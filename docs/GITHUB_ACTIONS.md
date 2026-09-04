# GitHub Action

safe-migrate checks pull-request migrations against an encrypted snapshot of
the database they will change. It never executes migration SQL.

Database access is isolated to a trusted refresh workflow. Pull-request checks
restore the snapshot and run offline.

## Before you start

You need:

| Requirement | Purpose |
| --- | --- |
| A GitHub environment named `safe-migrate-baseline` | Protects the database credential. |
| A runner that can reach PostgreSQL locally, through a Unix socket, or through a trusted tunnel | Runs the baseline refresh. |
| GitHub CLI, if you want automatic secret setup | Keeps secrets out of commands and workflow files. |
| A self-hosted runner at version 2.327.1 or newer | Supports the Node.js 24 runtime used by the pinned Actions. GitHub-hosted runners already qualify. |

Setup is performed once. Normal pull requests need no database connection and
no synchronization step.

## Set up

### 1. Create the protected environment

In the repository settings, create `safe-migrate-baseline` and restrict its
deployment branches to the default branch.

Required reviewers add approval before every refresh, including scheduled
runs. Use them when that manual gate is appropriate. Otherwise, a branch
restriction and a carefully scoped database login allow unattended refreshes.

The generated workflow uses `deployment: false` to avoid deployment-history
noise. This is compatible with required reviewers and wait timers, but not with
custom deployment protection rules. Remove that line if you use a custom rule.

### 2. Generate and configure

From the repository root, run:

```bash
safe-migrate init github-actions \
  --path migrations \
  --configure-secrets
```

The command creates two files:

| Workflow | Responsibility |
| --- | --- |
| `.github/workflows/safe-migrate-baseline.yml` | Refresh and publish the encrypted baseline from a trusted job. |
| `.github/workflows/safe-migrate.yml` | Restore the baseline and analyze pull requests without database access. |

It asks GitHub CLI for the database URL, generates a random 32-byte cache key,
and sends both directly to GitHub. Neither value is printed or written to a
workflow file.

The default branch is detected from `origin/HEAD`, with `main` as the fallback.
Use `--branch <name>` when detection is wrong. This must be the default or PR
base branch because GitHub cannot restore a cache from an arbitrary sibling
branch.

### 3. Connect and bootstrap

The generated refresh workflow uses `ubuntu-latest`. Add a trusted tunnel or
proxy step, or replace it with an isolated runner that can reach PostgreSQL
through an accepted local endpoint.

Then run **Refresh safe-migrate baseline** once from the Actions tab. Do this
before making the PR workflow a required check.

The generated schedule refreshes twice each week, away from the top of the
hour. Adjust it to match your schema-change rate and runner availability.

## Day-to-day behavior

| Event | Database credential | Cache operation | Migration analysis |
| --- | --- | --- | --- |
| Schedule or manual refresh | Available from the protected environment | Save after successful synchronization | None |
| Pull request | Never available | Restore only | Offline |
| Merge queue | Never available | Restore only | Offline |

A refresh reads the PostgreSQL catalogs in one read-only, repeatable-read
transaction. A PR check decrypts and validates Cache V7, parses the proposed
SQL, and simulates its state changes.

Neither path applies the migration.

## Secrets

| Secret | Scope | Who receives it |
| --- | --- | --- |
| `SAFE_MIGRATE_DATABASE_URL` | `safe-migrate-baseline` environment | Baseline refresh only |
| `SAFE_MIGRATE_CACHE_KEY` | Repository | Trusted refresh and same-repository PR checks |

The cache key grants access to the snapshot, not to PostgreSQL. The environment
boundary keeps the database credential out of PR jobs.

### Manual secret setup

If you do not want the initializer to configure secrets:

```bash
safe-migrate init github-actions --path migrations
gh secret set SAFE_MIGRATE_DATABASE_URL --env safe-migrate-baseline
safe-migrate init cache-key --set-github-secret
```

Plain `safe-migrate init cache-key` prints the key. Do not use it under shell
tracing or in public CI logs.

## Database role and runner security

Synchronization records `current_user`, `session_user`, role membership,
search path, and timeout defaults. This creates a real tradeoff:

- A dedicated catalog-reading login limits credential impact, but
  role-sensitive findings describe that login.
- Connecting as the intended migration role gives more accurate privilege and
  `SET ROLE` analysis, but the credential may be more powerful.

Choose deliberately. Protect the environment and runner when using the
migration role.

safe-migrate makes its own synchronization transaction read-only. That does
not make a stolen credential read-only when used by another client.

The trusted workflow checks out no repository code and grants `GITHUB_TOKEN` no
permissions. Both generated jobs have a 15-minute timeout.

The PR workflow grants only `contents: read`, disables persisted checkout
credentials, and receives no `DATABASE_URL`. The composite Action also clears
database access before linting and pins its nested Actions by full commit SHA.

GitHub's read-only default-branch cache protection is conditional; ordinary PR
cache scopes may remain writable. safe-migrate does not rely on it: PR jobs use
only `actions/cache/restore`, and only the trusted refresh uses
`actions/cache/save`.

## Baseline contents and protection

The baseline contains:

- schema objects and dependencies;
- table statistics;
- roles and privileges;
- PostgreSQL version and search path;
- observed migration timeout defaults.

It does not contain `DATABASE_URL`, role password hashes, or subscription
connection strings.

Cache V7 uses authenticated XChaCha20-Poly1305 encryption. Without the key, a
modified cache, forged PR cache, or cache encrypted under another key fails
authentication. The decrypted payload is size-bounded, version-checked, and
semantically validated before use.

Encryption does not hide the existence, stored size, or GitHub key of a cache.
It also cannot prevent replay of an older valid cache. safe-migrate records the
creation time and marks stale evidence explicitly.

## Failure and recovery

| Condition | Result | Recovery |
| --- | --- | --- |
| No managed cache restored | Operational failure | Run the trusted refresh workflow. |
| Missing or malformed cache key | Operational failure | Restore or rotate `SAFE_MIGRATE_CACHE_KEY`, then refresh. |
| Invalid, modified, or incompatible cache | Operational failure | Refresh with the current safe-migrate version. |
| Readable but old baseline | Analysis continues with stale evidence | Refresh the baseline. |

Normal Action analysis never silently falls back to SQL-only results. Missing
database evidence otherwise turns many useful conclusions into broad Tier 2 or
Tier 3 findings.

`no-cache: 'true'` is an explicit diagnostic mode for parser investigation and
limited SQL-only checks. Its confidence is `Tainted`; it is not a replacement
for the synchronized CI baseline.

Staleness uses `stale_stats_days`, which defaults to seven days. Refresh sooner
when schema, roles, privileges, statistics, search path, PostgreSQL version, or
timeout defaults may change outside the migration pipeline.

GitHub caches are recoverable build data rather than durable storage. They may
expire after seven days without access or be evicted under storage pressure.
The schedule replenishes the cache; manual dispatch is the bootstrap and
recovery path. GitHub may disable schedules in inactive public repositories
after 60 days.

## Forks and contributor trust

Fork and Dependabot PRs do not receive repository secrets. They may download
the encrypted cache but cannot decrypt it, so the baseline-aware check fails.

Public repositories should document one fallback:

- reproduce the branch in the base repository before baseline-aware approval;
- run safe-migrate locally and attach the report;
- use a separately audited service that treats migration files strictly as
  untrusted data.

Do not work around this with `pull_request_target` or a privileged
`workflow_run` that executes PR content. That exposes secrets and trusted cache
state to untrusted code.

Same-repository workflows can receive repository secrets. Anyone who can
modify and run those workflows must therefore be trusted with baseline
metadata. Environment-scoping still keeps the database URL separate.

GitHub workflow-execution protections can further restrict which actors and
events start workflows. They are defense in depth, not a replacement for
workflow review and separate secret scopes.

## Required checks and merge queues

The generated analysis workflow runs for every PR targeting the selected
branch and handles `merge_group`.

It intentionally has no path filter. When an entire path-filtered workflow is
skipped, GitHub can leave a required check permanently Pending.

If safe-migrate is not required, you may add a path filter. If it is required,
keep the generated trigger or perform change detection inside an always-running
job that can explicitly succeed when there is nothing to analyze.

## Action reference

Analysis normally needs only `path`. The Action infers `lint` for a file and
`lint-chain` for a directory. A sync-only invocation sets `sync: 'true'` and
leaves `path` empty.

### Common inputs

| Input | Meaning |
| --- | --- |
| `path` | Migration file or ordered migration directory |
| `baseline` | Logical database identity; defaults to `default` |
| `schemas` | Comma-separated catalog scope; valid only with `sync` |
| `advisory` | Report Tier 1 findings without failing; operational errors still fail |
| `no-cache` | Explicit degraded SQL-only analysis |

For multiple databases, duplicate the workflow pair. Give each pair a distinct
`baseline`, environment, and cache key.

Do not add another `actions/cache` step. The Action owns the cache path,
format, encryption namespace, restore, and trusted save lifecycle.

### Outputs

| Output | Meaning |
| --- | --- |
| `json-report` | JSON report path; empty for sync-only runs |
| `markdown-report` | Markdown report path; empty for sync-only runs |
| `diagnostic-log` | Diagnostic log path |
| `exit-code` | `0` completed, `1` operational failure, `2` blocking finding |
| `cache-path` | Resolved cache path |
| `baseline-source` | `synced`, `github-cache`, `explicit-file`, or `unavailable` |
| `sync-status` | `not-requested`, `refreshed`, or `failed` |

## Reviewed configuration

The Action does not automatically read `safe-migrate.toml` from a PR checkout.
Otherwise a migration could weaken the rules evaluating itself.

To use a custom configuration, check out only the reviewed file from the PR
base commit:

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  with:
    ref: ${{ github.event.pull_request.base.sha }}
    path: .safe-migrate-base
    sparse-checkout: safe-migrate.toml
    persist-credentials: false

- uses: dsecurity49/safe-migrate@v0.8.0
  env:
    SAFE_MIGRATE_CACHE_KEY: ${{ secrets.SAFE_MIGRATE_CACHE_KEY }}
  with:
    path: migrations
    config: .safe-migrate-base/safe-migrate.toml
```

The file must exist, and its `cache_encryption` setting must agree with the
Action's `encrypted-cache` input.

## Action pinning

Generated workflows use the exact release tag matching the installed CLI. This
is the simplest portable default and installs checksum-verified binaries.

A tag can move unless the publisher enables immutable releases. For the
strongest supply-chain boundary, replace it with a reviewed full 40-character
commit SHA. GitHub can enforce full-SHA pins at repository or organization
level. safe-migrate rejects mutable branch and major-version references.

## References

- [GitHub dependency-cache security and scope](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
- [GitHub's 2026 read-only-cache change and its scope](https://github.blog/changelog/2026-06-26-read-only-actions-cache-for-untrusted-triggers/)
- [GitHub secure-use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub environments and environment secrets](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [GitHub workflow-execution protections](https://github.blog/changelog/2026-06-18-control-who-and-what-triggers-github-actions-workflows/)
- [GitHub fork workflow controls](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/approve-runs-from-forks)
- [GitHub workflow and required-check behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)
- [PostgreSQL read-only transactions](https://www.postgresql.org/docs/current/sql-set-transaction.html)
