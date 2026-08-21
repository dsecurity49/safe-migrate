# GitHub Action

The safe-migrate Action has two jobs:

1. a trusted job synchronizes PostgreSQL metadata and saves a named baseline;
2. pull-request jobs restore that baseline and lint migrations without database
   access.

Synchronization is optional. If no baseline can be restored, linting still
runs with `Tainted` confidence and conservative assumptions.

## Pull-request workflow

This is the normal lint job. `lint-chain` is the default mode, so only the
migration directory is required.

```yaml
name: Migration safety

on:
  pull_request:
    paths:
      - "migrations/**"

permissions:
  contents: read

jobs:
  safe-migrate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - uses: dsecurity49/safe-migrate@v0.6.0
        with:
          path: migrations
```

The Action writes JSON and Markdown reports, adds the Markdown report to the
job summary, and emits Tier 1 and Tier 2 annotations. Blocking Tier 1 findings
fail the step by default. Set `advisory: "true"` to keep the step successful
while preserving output `exit-code: 2`.

Before the first successful refresh, or after GitHub evicts the baseline, the
same workflow completes with an unavailable baseline and `Tainted` confidence.
The managed-cache miss is passed to the CLI as an offline `--no-cache` run, so
an explicit configuration containing `auto_sync = true` cannot make a
pull-request job attempt database access. A missing explicit `cache` path is
still an operational error rather than a fallback.

## Baseline refresh workflow

Run synchronization from the default branch. The database must be reachable
through localhost or a Unix socket, so use a self-hosted runner with suitable
network access or establish an SSH tunnel before invoking the Action.

```yaml
name: Refresh migration baseline

on:
  push:
    branches: [main]
    paths:
      - "migrations/**"
      - "safe-migrate.toml"
  schedule:
    - cron: "17 3 * * *"
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: safe-migrate-default-baseline
  cancel-in-progress: false

jobs:
  refresh:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - uses: dsecurity49/safe-migrate@v0.6.0
        env:
          DATABASE_URL: ${{ secrets.SAFE_MIGRATE_DATABASE_URL }}
        with:
          path: migrations
          sync: "true"
          schemas: public
```

Add `SAFE_MIGRATE_DATABASE_URL` as a repository or environment secret, then run
the workflow once with `workflow_dispatch` to create the first baseline. The
scheduled job refreshes it afterward. GitHub schedules run from the latest
default-branch commit, can be delayed, and are automatically disabled in a
public repository after 60 days without repository activity. A push trigger or
periodic manual check avoids treating the schedule as a delivery guarantee.

The managed transport uses `actions/cache` v6.1.0. Self-hosted runners must be
version 2.327.1 or later because the cache action uses the Node.js 24 action
runtime.

## Cache encryption

GitHub caches are not private artifacts: a pull request, including one from a
fork, can read caches in its base branch. Pull-request runs can also create
merge-ref caches that their own reruns can restore. Enable authenticated cache
encryption when baseline confidentiality or integrity matters.

Generate a 32-byte key once:

```bash
openssl rand -hex 32
```

Store it as `SAFE_MIGRATE_CACHE_KEY`. Add the key and encryption input to the
refresh job:

```yaml
      - uses: dsecurity49/safe-migrate@v0.6.0
        env:
          DATABASE_URL: ${{ secrets.SAFE_MIGRATE_DATABASE_URL }}
          SAFE_MIGRATE_CACHE_KEY: ${{ secrets.SAFE_MIGRATE_CACHE_KEY }}
        with:
          path: migrations
          sync: "true"
          encrypted-cache: "true"
```

Use the same baseline name, key, and encryption input in the pull-request job:

```yaml
      - uses: dsecurity49/safe-migrate@v0.6.0
        env:
          SAFE_MIGRATE_CACHE_KEY: ${{ secrets.SAFE_MIGRATE_CACHE_KEY }}
        with:
          path: migrations
          encrypted-cache: "true"
```

GitHub does not pass Actions secrets to workflows triggered from forks, and
Dependabot pull requests receive the same restricted treatment. In those runs,
the Action deliberately skips the encrypted baseline and produces a `Tainted`
preview instead of attempting decryption.

If `config` is omitted, the Action creates an internal configuration with the
requested encryption mode. An explicit config path must exist, and its
`cache_encryption` value must agree with `encrypted-cache`.

## Named baselines

The default baseline needs no configuration. Use `baseline` when one repository
targets more than one database:

```yaml
with:
  path: migrations/production
  baseline: production
```

Use exactly the same name, encryption mode, and runner operating system in the
refresh and lint jobs. Different encryption modes have separate cache keys.

## Explicit cache files

Set `cache` to bypass GitHub's cache transport and use a file supplied by an
earlier trusted step:

```yaml
with:
  path: migrations
  cache: trusted-input/production.cache
```

The Action does not commit, upload, or push an explicit file. A repository file
is controlled by the checked-out revision, so do not treat a pull-request-owned
cache or configuration file as trusted. Teams that deliberately track an
encrypted baseline must keep its key outside Git and accept binary history
churn from timestamps and fresh encryption nonces.

`no-cache: "true"` explicitly bypasses every baseline. It cannot be combined
with `cache`, `sync`, `schemas`, or `encrypted-cache`.

## Inputs and outputs

The common inputs are:

- `path`: migration file or directory; required.
- `mode`: `lint` or `lint-chain`; defaults to `lint-chain`.
- `sync`: refresh before linting; use only in a trusted database-connected job.
- `schemas`: optional comma-separated schema scope; requires `sync: "true"`.
- `baseline`: managed-cache name; defaults to `default`.
- `encrypted-cache`: require encrypted managed or explicit cache data.
- `advisory`: do not fail the step for completed Tier 1 analysis.

Advanced inputs are `cache`, `config`, `no-cache`, and `output-dir`. Omitting
`config` is intentional: the Action does not automatically trust
`safe-migrate.toml` from a pull-request checkout. If a PR workflow opts into an
explicit config, that file can change the enabled rules and must be reviewed as
part of the security boundary.

The Action exposes:

- `json-report`, `markdown-report`, and `diagnostic-log` paths;
- `exit-code`: `0` completed, `1` operational failure, or `2` blocking finding;
- `cache-path`: the file used during this invocation;
- `sync-status`: `not-requested`, `refreshed`, or `failed`;
- `baseline-source`: `synced`, `github-cache`, `explicit-file`, or
  `unavailable`.

`sync-status: refreshed` proves that local synchronization completed. GitHub's
cache save action is best-effort and reports service failures as workflow
warnings, so check the cache step log if later jobs unexpectedly report
`baseline-source: unavailable`.

## Cache lifetime and pinning

GitHub evicts caches that have not been accessed for more than seven days and
may evict older entries when repository cache storage is full. The Action is
therefore designed to lint safely after a miss rather than make the cache a
required service.

Published safe-migrate Action references must use the exact release tag or a
full 40-character commit SHA; mutable branch references are rejected. A full
commit SHA gives the strongest workflow supply-chain pinning. Nested Actions in
safe-migrate itself are also pinned to full commit SHAs.

GitHub documentation for the behavior relied on here:

- [Cache scope, low-trust writes, security, and eviction](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
- [Scheduled workflow behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)
- [Fork and Dependabot secret restrictions](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflows-in-forked-repositories)
