# GitHub Action

safe-migrate can check pull requests immediately without database access. A
trusted refresh job is optional and adds database-aware findings when you are
ready to provide PostgreSQL access.

## Choose your setup

| Setup | You provide | Result |
| --- | --- | --- |
| Quick trial | Migration directory | Offline checks with `Tainted` confidence |
| Database-aware | Migration directory, database secret, cache-key secret, trusted runner | Checks against an encrypted PostgreSQL baseline |

You do not need Rust, a separate `actions/cache` step, a TOML file, or database
access in a pull-request job.

## Quick trial

Generate the workflow:

```bash
safe-migrate init github-actions --path migrations
```

Or create `.github/workflows/safe-migrate.yml` yourself:

```yaml
name: Check database migrations

on:
  pull_request:
    paths: ['migrations/**']

permissions:
  contents: read

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: dsecurity49/safe-migrate@v0.8.0
        with:
          path: migrations
```

The Action infers `lint` for a file and `lint-chain` for a directory. With no
baseline, it runs `--no-cache`, reports `Tainted` confidence, and still blocks
Tier 1 findings established from migration SQL.

This is a complete first setup. Add a baseline only when you want findings that
depend on the existing schema, table statistics, roles, privileges, PostgreSQL
version, search path, or database timeout settings.

## Database-aware setup

The initializer can replace the trial workflow with a single workflow containing
separate PR-lint and trusted-refresh jobs:

```bash
safe-migrate init github-actions \
  --path migrations \
  --force \
  --with-baseline \
  --configure-secrets
```

`--configure-secrets` requires an authenticated GitHub CLI. It asks GitHub CLI
to read the database URL interactively, generates a random 32-byte cache key,
and sends both directly to GitHub as repository secrets. It does not print them
or place them in the workflow.

Without GitHub CLI, create these secrets in repository settings:

- `SAFE_MIGRATE_DATABASE_URL`: a PostgreSQL URL that reaches the representative
  database through localhost or a Unix socket on the refresh runner.
- `SAFE_MIGRATE_CACHE_KEY`: 64 hexadecimal characters. Generate one with
  `safe-migrate init cache-key` or `openssl rand -hex 32`.

Both generation commands print the key. Keep that output out of shell tracing
and public CI logs. `safe-migrate init cache-key --set-github-secret` stores a
new key through GitHub CLI without printing it.

Then generate the workflow with `--with-baseline` but without
`--configure-secrets`.

### Generated workflow model

```text
pull request
  └─ GitHub-hosted lint job
       ├─ no database URL
       ├─ restore encrypted baseline when the key is available
       └─ otherwise lint with Tainted confidence

push to main or manual run
  └─ trusted refresh job
       ├─ read database URL and cache key
       ├─ synchronize PostgreSQL metadata
       ├─ lint offline
       └─ save the encrypted baseline
```

The generated refresh job names the `safe-migrate-baseline` environment. Add
required reviewers to that environment when appropriate. It uses
`ubuntu-latest` as a safe placeholder; add a trusted tunnel step or change it to
an isolated runner that can reach PostgreSQL through localhost or a Unix socket.
Do not run untrusted PR code on that runner.

Start the workflow once from the Actions tab after adding the secrets. Later
pull requests restore the baseline automatically. A push to the default branch
that changes migrations refreshes it again.

## Security model

The two jobs have different trust levels:

- The PR job reads migration SQL but never receives `DATABASE_URL`.
- The refresh job runs only after trusted default-branch changes or a manual
  dispatch.
- The workflow grants `GITHUB_TOKEN` only `contents: read`.
- Checkout credentials are not persisted.
- Nested Actions are pinned to full commit SHAs.
- The lint process runs with database access removed and automatic sync disabled.
- Managed baseline caches are encrypted by default.
- A missing encryption key causes a visible Tainted fallback; it never silently
  reads encrypted data as plaintext.

Do not change the PR workflow to `pull_request_target`, and do not check out PR
code in a privileged `workflow_run` job. Those triggers can expose secrets,
write tokens, or trusted caches to untrusted code.

Fork and Dependabot pull requests do not receive repository secrets. They lint
without the encrypted baseline and report `Tainted` confidence. This is
intentional: sharing the key would also reveal the baseline contents.

GitHub caches are readable by pull requests targeting the branch that created
them and are not signed. Keep credentials out of baselines and leave managed
cache encryption enabled.

## What is automatic

After the first successful refresh, the Action handles:

- cache restoration and save;
- cache-version and encryption-mode separation;
- fallback when a managed cache is missing or a fork lacks the key;
- JSON and Markdown reports;
- job summaries and file annotations;
- blocking exit status unless `advisory: 'true'` is requested.

Do not add a separate `actions/cache` step.

Refresh after out-of-band schema, role, privilege, statistics, or timeout
changes. For databases that change outside migrations, add a trusted schedule to
the refresh trigger.

## Common options

Only `path` is required:

- A file selects `lint`.
- A directory selects `lint-chain`.

Common optional inputs:

- `sync`: set to `'true'` only in the trusted refresh job.
- `schemas`: comma-separated synchronization scope; valid only with `sync`.
- `baseline`: identity for one target database; defaults to `default`.
- `advisory`: report Tier 1 findings without failing the job. Operational errors
  still fail.

Use a distinct `baseline` value for every target database:

```yaml
with:
  path: migrations/production
  baseline: production
  sync: 'true'
```

The refresh and lint jobs must use the same baseline name, cache encryption
mode, and runner operating system.

## Custom configuration

The Action deliberately ignores `safe-migrate.toml` in the PR workspace unless
you pass `config`. Otherwise, a PR could disable security rules before linting
its own migration.

For a pull request, check out the reviewed configuration from the base commit:

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

The file must exist and pass validation. Because managed baselines are encrypted
by default, an explicit config must also set `cache_encryption = true`. Set
`encrypted-cache: 'false'` only for a reviewed plaintext-cache workflow.

## Advanced cache control

`cache` uses an explicit trusted file and disables GitHub cache transport:

```yaml
with:
  path: migrations
  cache: trusted-input/production.cache
```

Do not accept a cache or config from a PR checkout. Authenticated encryption
detects modification but does not make an unreviewed configuration trustworthy.

`no-cache: 'true'` deliberately bypasses every baseline. It cannot be combined
with `cache`, `sync`, or `schemas`. `encrypted-cache` is ignored when no cache is
used.

`output-dir` changes the report directory. It must be a relative path contained
inside the workspace and cannot contain dot segments or traverse symlinks.

## Outputs

The Action exposes:

- `json-report`, `markdown-report`, and `diagnostic-log` paths;
- `exit-code`: `0` completed, `1` operational failure, or `2` blocking finding;
- `cache-path`: baseline file used during the invocation;
- `sync-status`: `not-requested`, `refreshed`, or `failed`;
- `baseline-source`: `synced`, `github-cache`, `explicit-file`, or `unavailable`.

`sync-status: refreshed` means synchronization completed. Check the cache-save
step if a later job reports `baseline-source: unavailable`.

## Pinning and maintenance

An exact release tag downloads a checksum-verified prebuilt binary. A full
40-character commit SHA builds the checked-out source. Mutable branch and major
version references are rejected.

Full commit SHAs provide immutable Action source; exact tags are shorter and
faster because they use release binaries. Choose according to your supply-chain
policy and let Dependabot propose updates.

GitHub may evict caches that have not been accessed recently or when repository
cache storage is under pressure. A miss produces a visible Tainted result rather
than an operational failure.

References:

- [GitHub Actions secure-use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub cache scope and security](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
- [Fork secret restrictions](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflows-in-forked-repositories)
