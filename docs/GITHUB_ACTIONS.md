# GitHub Action

safe-migrate checks proposed PostgreSQL migrations against a synchronized
database baseline. Synchronization and pull-request analysis are deliberately
separate: the trusted workflow reads PostgreSQL catalogs, while the PR workflow
only reads migration files and the encrypted baseline. Neither workflow executes
migration SQL.

If the runner can already reach the database through localhost, a Unix socket,
or a tunnel, onboarding is one generated workflow pair, two scoped secrets, and
one initial refresh. That setup is done once; day-to-day PR checks stay offline.

## Setup

### 1. Create the baseline environment

In the repository settings, create a GitHub environment named
`safe-migrate-baseline`. Restrict its deployment branches to the default branch.
Store the database URL in this environment—not as a repository secret.

Required reviewers add a manual gate before every refresh, including scheduled
refreshes. Use them when the database connection needs that approval; otherwise,
branch restriction and a dedicated read-only database role provide an unattended
refresh path.

`deployment: false` avoids deployment-history noise. GitHub currently does not
allow that setting with custom deployment protection rules; remove it from the
generated baseline workflow if your environment uses such a rule. Required
reviewers and wait timers remain compatible.

### 2. Generate the workflows

From the repository root:

```bash
safe-migrate init github-actions --path migrations
```

This creates:

- `.github/workflows/safe-migrate-baseline.yml`, which refreshes the encrypted
  baseline on a trusted schedule or manual dispatch;
- `.github/workflows/safe-migrate.yml`, which restores that baseline and checks
  pull requests without database access.

The initializer detects the default branch from `origin/HEAD` and otherwise
falls back to `main`; use `--branch <name>` to override it. The configured branch
must be the default or PR base branch because GitHub does not allow an Actions
cache to be restored from an arbitrary sibling branch.

### 3. Configure the secrets

The two secrets intentionally have different scopes:

- `SAFE_MIGRATE_DATABASE_URL` is an environment secret in
  `safe-migrate-baseline`. Only the refresh job receives it.
- `SAFE_MIGRATE_CACHE_KEY` is a repository secret. It lets trusted PR jobs
  decrypt the baseline but does not grant database access.

With an authenticated GitHub CLI, configure both after creating the environment:

```bash
safe-migrate init github-actions \
  --path migrations \
  --force \
  --configure-secrets
```

The database URL is read by GitHub CLI interactively. safe-migrate generates a
random 32-byte cache key and sends it through standard input; neither value is
printed or placed in a workflow file.

To configure them manually:

```bash
gh secret set SAFE_MIGRATE_DATABASE_URL --env safe-migrate-baseline
safe-migrate init cache-key --set-github-secret
```

The plain `safe-migrate init cache-key` command prints the key. Do not run it
under shell tracing or in public CI logs.

### 4. Connect and bootstrap

The generated refresh job uses `ubuntu-latest` as a placeholder. Add a trusted
tunnel or proxy step, or select an isolated runner that can reach PostgreSQL
through localhost or a Unix socket.

Synchronization records `current_user`, `session_user`, role membership,
search path, and timeout defaults. A dedicated catalog-reading login minimizes
credential impact, but role-sensitive findings then describe that login. If you
need exact privilege and `SET ROLE` behavior for the migration runner, connect
as that intended role and protect its secret, environment, and runner
accordingly. safe-migrate starts a read-only, repeatable-read transaction, but
that does not make a stolen database credential read-only outside safe-migrate.

Run **Refresh safe-migrate baseline** once from the Actions tab before relying on
the PR check. The scheduled workflow then refreshes twice each week, away from
the top of the hour. Edit or remove that schedule to match the database's change
rate and your runner availability.

## Trust model

```text
trusted schedule or manual dispatch
  └─ baseline workflow
       ├─ environment-scoped DATABASE_URL
       ├─ read-only, repeatable-read catalog snapshot
       ├─ XChaCha20-Poly1305 encryption
       └─ save to default-branch cache scope

pull request or merge queue
  └─ analysis workflow
       ├─ no DATABASE_URL
       ├─ restore only; never save or synchronize
       ├─ decrypt and validate Cache V7
       └─ parse and simulate migration SQL offline
```

The baseline workflow checks out no repository code and gives `GITHUB_TOKEN` no
permissions. Its environment is marked `deployment: false`, so it can use
environment controls without creating deployment-history noise.

The PR workflow grants only `contents: read`, disables persisted checkout
credentials, and pins the checkout implementation. The safe-migrate Action also
pins its nested Actions by full commit SHA and unsets `DATABASE_URL` before lint.
Both generated jobs have a 15-minute timeout so a broken tunnel, runner, or
download cannot consume GitHub's multi-hour default indefinitely.

Since June 2026, GitHub issues a read-only token when an untrusted trigger runs
in shared default-branch cache scope. Non-default scopes, including ordinary PR
scope, may still be writable. safe-migrate therefore does not rely on that
platform protection: PR analysis invokes only `actions/cache/restore`, while
the trusted schedule or manual dispatch invokes `actions/cache/save` only after
synchronization completes.

## What a baseline contains

The cache records schema objects, dependencies, table statistics, roles,
privileges, PostgreSQL version, search path, and observed migration timeouts. It
does not contain `DATABASE_URL`, role password hashes, or subscription connection
strings.

Cache V7 is encrypted and authenticated with XChaCha20-Poly1305. Without the
key, a modified cache, a forged PR-scoped cache, or a cache encrypted under a
different key fails authentication. The decrypted payload is also bounded,
version-checked, and semantically validated before it becomes analysis state.

Encryption does not hide that a cache object exists, its stored size, or its
GitHub cache key. It also cannot prevent replay of an older valid cache, so
safe-migrate records creation time and marks stale evidence explicitly.

## Missing and stale baselines

A normal Action analysis now requires a readable baseline. These are operational
errors:

- no managed cache was restored;
- `SAFE_MIGRATE_CACHE_KEY` is missing or malformed;
- an encrypted cache was modified or encrypted under another key;
- the cache format or semantics are invalid.

The job explains how to run the trusted refresh workflow. It does not silently
fall back to conservative analysis, because missing database evidence can turn
most useful findings into broad Tier 2 or Tier 3 warnings.

`no-cache: 'true'` remains an explicit diagnostic mode. It is useful for parser
investigation and limited SQL-only checks, but its confidence is `Tainted` and
it should not replace the synchronized CI baseline.

A readable but old baseline remains usable and is marked stale according to
`stale_stats_days` (seven days by default). Refresh sooner when schema, roles,
privileges, statistics, search path, PostgreSQL version, or timeout defaults can
change outside the migration pipeline.

GitHub caches are recoverable build data, not durable storage. The default
retention is seven days after last access and entries can be evicted under
storage pressure. The generated schedule replenishes the baseline; manual
dispatch is the recovery path. Scheduled workflows in inactive public
repositories may be disabled after 60 days, so do not treat scheduling as the
only bootstrap mechanism.

## Forks and contributor trust

Fork and Dependabot pull requests do not receive repository secrets. They can
download ciphertext from the base-branch cache but cannot decrypt it, so the
baseline-aware check fails clearly.

For a public repository, choose one documented policy:

- require maintainers to reproduce the branch in the base repository before
  baseline-aware approval;
- run safe-migrate locally and attach the report during review;
- build a separately audited privileged analysis service that fetches migration
  files strictly as data.

Do not solve this with `pull_request_target` or a privileged `workflow_run` that
checks out and executes PR content. GitHub warns that this exposes secrets and
trusted caches to untrusted code. There is no GitHub-native mechanism that gives
an attacker-controlled runner a decryption key while preventing it from reading
that key.

Repository secrets are available to same-repository workflow runs. Treat users
who can create branches and modify workflows in the base repository as trusted
with respect to baseline metadata. Keeping the database URL in its restricted
environment limits a cache-key compromise to the encrypted snapshot.

Organizations that have GitHub's workflow-execution protections available can
also restrict which actors and events may start workflows. That is useful
defense in depth, but it does not replace workflow review or the separate secret
scopes above.

## Required checks and merge queues

The generated PR workflow intentionally runs on every PR targeting the selected
branch and also handles `merge_group`. This keeps a required safe-migrate check
from remaining permanently Pending: GitHub does not create a successful required
check when an entire workflow is skipped by a path filter.

If safe-migrate is not a required check, you may add a `paths` filter to reduce
CI usage. If it is required, keep the generated trigger or implement change
detection inside an always-running job so the job can explicitly succeed when no
migration needs analysis.

## Action inputs

Analysis normally needs only `path`; the Action infers `lint` for a file and
`lint-chain` for a directory. A sync-only invocation sets `sync: 'true'` and
leaves `path` empty.

Common inputs:

- `path`: migration file or ordered migration directory;
- `baseline`: logical identity for a target database, default `default`;
- `schemas`: comma-separated catalog scope, valid only with `sync`;
- `advisory`: report Tier 1 findings without failing; operational errors still
  fail;
- `no-cache`: explicitly perform degraded SQL-only analysis.

The generated workflows use the same default baseline name. For multiple target
databases, duplicate the job pair and give each pair a distinct `baseline`,
environment, and cache key.

Do not add another `actions/cache` step. The Action owns the cache path, format,
encryption-mode namespace, restore, and trusted save lifecycle.

## Reviewed configuration

The Action does not automatically read `safe-migrate.toml` from a PR checkout.
Otherwise a migration could weaken the rules evaluating itself. To use a custom
configuration, check out only the reviewed file from the PR base commit:

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

An explicit config must exist and its `cache_encryption` value must agree with
the Action's `encrypted-cache` input.

## Outputs

Analysis exposes:

- `json-report`, `markdown-report`, and `diagnostic-log`;
- `exit-code`: `0` completed, `1` operational failure, `2` blocking finding;
- `cache-path` and `baseline-source`;
- `sync-status`: `not-requested`, `refreshed`, or `failed`.

A sync-only invocation leaves `json-report` and `markdown-report` empty, reports
the diagnostic-log path, and sets `baseline-source: synced` and
`sync-status: refreshed` when successful.

## Pinning

The generated workflows use the exact release tag matching the installed CLI
because it is the simplest portable default. Release tags install
checksum-verified binaries, but a tag can still move unless the publisher has
enabled GitHub's immutable releases. For the strongest supply-chain boundary,
replace the tag with a reviewed full 40-character commit SHA; GitHub identifies
full-SHA pinning as the only universally immutable Action reference and can
enforce it with repository or organization policy. Mutable branch and
major-version references are rejected by safe-migrate.

References:

- [GitHub dependency-cache security and scope](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
- [GitHub's 2026 read-only-cache change and its scope](https://github.blog/changelog/2026-06-26-read-only-actions-cache-for-untrusted-triggers/)
- [GitHub secure-use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub environments and environment secrets](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [GitHub workflow-execution protections](https://github.blog/changelog/2026-06-18-control-who-and-what-triggers-github-actions-workflows/)
- [GitHub fork workflow controls](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/approve-runs-from-forks)
- [GitHub workflow and required-check behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)
- [PostgreSQL read-only transactions](https://www.postgresql.org/docs/current/sql-set-transaction.html)
