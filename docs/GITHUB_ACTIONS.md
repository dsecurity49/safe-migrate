# GitHub Action

Use the Action in two workflows:

1. Refresh a baseline from a trusted branch with database access.
2. Restore that baseline in pull requests and lint offline.

A baseline is one cache file created by `sync`. The Action writes it to its
managed runner path, saves it with GitHub Actions cache after a successful
refresh, then restores that file automatically in pull-request jobs. Do not
add an `actions/cache` step yourself. Pull-request linting uses `lint-chain`
with the restored baseline; it does not run `sync` or connect to PostgreSQL.

We recommend cache encryption because a baseline contains schema and role
metadata and GitHub cache contents are not signed. A baseline is optional: on a
cache miss, linting runs with `Tainted` confidence.

## Setup order

1. Add `SAFE_MIGRATE_DATABASE_URL` as a secret. Generate an encryption key as
   shown in [Cache encryption](#cache-encryption), then add it as
   `SAFE_MIGRATE_CACHE_KEY`.
2. Add the baseline refresh workflow and run it once with `workflow_dispatch`.
3. Confirm that the refresh job and its `Save synchronized baseline` step
   succeed.
4. Add the pull-request workflow. It will find the saved baseline
   automatically.

To try the Action before setting up database access, add only the pull-request
workflow. It will lint without a baseline and report `Tainted` confidence.

## Pull-request workflow

Pull-request jobs use `lint-chain` by default. Set `path` to the migration
directory. This job does not need `DATABASE_URL`, `sync: "true"`, or a separate
cache step.

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

      - uses: dsecurity49/safe-migrate@v0.7.0
        env:
          SAFE_MIGRATE_CACHE_KEY: ${{ secrets.SAFE_MIGRATE_CACHE_KEY }}
        with:
          path: migrations
          encrypted-cache: "true"
```

The Action writes JSON and Markdown reports, adds Markdown to the job summary,
and annotates Tier 1 and Tier 2 findings. Tier 1 fails the step unless
`advisory: "true"` is set; output `exit-code` remains `2`.

On a managed-cache miss, the Action runs `--no-cache` and reports `Tainted`
confidence. A missing explicit `cache` path is an error.

The Action suppresses `auto_sync` during lint, including when an explicit
config enables it. Only `sync: "true"` performs an Action-controlled refresh.
After refresh, the Action removes database access before linting.

## Using TOML configuration

`config` is a path to a TOML file, not inline TOML. When omitted, the Action
uses built-in defaults and does not read `safe-migrate.toml` from the checkout.
A pull request can change lint policy only when the workflow passes its config
explicitly.

In a trusted branch job, pass the checked-out file directly:

```yaml
      - uses: dsecurity49/safe-migrate@v0.7.0
        with:
          path: migrations
          config: safe-migrate.toml
```

To keep pull-request policy fixed to the base commit, check out the config
separately:

```yaml
      - name: Checkout pull request
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Checkout trusted configuration
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ github.event.pull_request.base.sha }}
          path: .safe-migrate-base
          sparse-checkout: safe-migrate.toml
          sparse-checkout-cone-mode: false
          persist-credentials: false

      - uses: dsecurity49/safe-migrate@v0.7.0
        with:
          path: migrations
          config: .safe-migrate-base/safe-migrate.toml
```

Use the pull request's config only when the policy change is part of the
review.

The file must exist and pass config validation. If it sets
`cache_encryption = true`, also set `encrypted-cache: "true"` and provide
`SAFE_MIGRATE_CACHE_KEY`. An encryption mismatch fails before synchronization.

## Baseline refresh workflow

Run synchronization from the default branch. Use a self-hosted runner or an
SSH tunnel so PostgreSQL is available through localhost or a Unix socket.

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

      - uses: dsecurity49/safe-migrate@v0.7.0
        env:
          DATABASE_URL: ${{ secrets.SAFE_MIGRATE_DATABASE_URL }}
          SAFE_MIGRATE_CACHE_KEY: ${{ secrets.SAFE_MIGRATE_CACHE_KEY }}
        with:
          path: migrations
          sync: "true"
          schemas: public
          encrypted-cache: "true"
```

Add `SAFE_MIGRATE_DATABASE_URL` as a repository or environment secret, then run
`workflow_dispatch` once to create the baseline. Scheduled workflows use the
latest default-branch commit, may be delayed, and are disabled in public
repositories after 60 days without activity.

The pinned cache Action requires self-hosted runner 2.327.1 or newer.

## Cache encryption

Pull requests, including forks, can read caches from the base branch. Cache
contents are not signed, so we recommend encrypting managed baselines.

The workflows above use the recommended encrypted setup. Generate a 32-byte
key once:

```bash
openssl rand -hex 32
```

Store it as the `SAFE_MIGRATE_CACHE_KEY` secret. Both workflows must use the
same key, baseline name, and `encrypted-cache: "true"` input. To use plaintext
instead, remove the key and encryption input from both workflows; encryption
is recommended, not required.

Fork and Dependabot jobs do not receive repository secrets. Without the key,
the Action skips the encrypted baseline and lints with `Tainted` confidence.

Without `config`, the Action generates a config that matches
`encrypted-cache`. With an explicit config, `cache_encryption` must match the
input.

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

The Action never uploads or commits an explicit file. Do not trust a cache or
config from a pull-request checkout. If an encrypted baseline is tracked in
Git, keep its key outside the repository; each sync changes the binary because
it records a timestamp and uses a fresh nonce.

`no-cache: "true"` explicitly bypasses every baseline. It cannot be combined
with `cache`, `sync`, `schemas`, or `encrypted-cache`.

## Inputs and outputs

The common inputs are:

- `path`: migration file or directory; required.
- `mode`: `lint` or `lint-chain`; defaults to `lint-chain`.
- `sync`: run the Action-controlled refresh before offline linting; use only in
  a trusted database-connected job.
- `schemas`: optional comma-separated schema scope; requires `sync: "true"`.
- `baseline`: managed-cache name; defaults to `default`.
- `encrypted-cache`: require encrypted managed or explicit cache data.
- `advisory`: do not fail the step for completed Tier 1 analysis.

Advanced inputs are `cache`, `config`, `no-cache`, and `output-dir`. See
[Using TOML configuration](#using-toml-configuration) before passing a file
from a pull-request checkout.

The Action exposes:

- `json-report`, `markdown-report`, and `diagnostic-log` paths;
- `exit-code`: `0` completed, `1` operational failure, or `2` blocking finding;
- `cache-path`: the file used during this invocation;
- `sync-status`: `not-requested`, `refreshed`, or `failed`;
- `baseline-source`: `synced`, `github-cache`, `explicit-file`, or
  `unavailable`.

`sync-status: refreshed` means synchronization completed; it does not mean the
GitHub cache save succeeded. Check cache-step warnings if a later job reports
`baseline-source: unavailable`.

## Cache lifetime and pinning

By default, GitHub removes cache entries that have not been accessed for more
than seven days. Storage pressure can evict older entries sooner. On a miss,
the Action lints without a baseline.

Use an exact release tag or a full 40-character commit SHA. Mutable branch
references are rejected. Exact tags install checksum-verified release assets.
A full SHA builds the checked-out Action source. Nested Actions are pinned by
full SHA.

References:

- [Cache scope, low-trust writes, security, and eviction](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
- [Scheduled workflow behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)
- [Fork and Dependabot secret restrictions](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflows-in-forked-repositories)
