# GitHub Action Guide

safe-migrate checks pull-request migrations offline against an encrypted
snapshot of your PostgreSQL catalog. It never executes migration SQL.

To keep database credentials out of pull requests, the integration uses two
workflows:
1. **Baseline refresh (`.github/workflows/safe-migrate-baseline.yml`)**: runs
   in a protected GitHub environment (`safe-migrate-baseline`) with access to
   `SAFE_MIGRATE_DATABASE_URL`, runs `safe-migrate sync` in a read-only
   transaction, encrypts the snapshot with `SAFE_MIGRATE_CACHE_KEY`, and saves
   it to the GitHub Actions cache.
2. **Pull-request check (`.github/workflows/safe-migrate.yml`)**: runs on
   `pull_request` and `merge_group` with `contents: read` and only
   `SAFE_MIGRATE_CACHE_KEY`, restores the encrypted snapshot read-only, lints
   the migration chain offline, and uploads `safe-migrate-reports`.

## Prerequisites

| Requirement | Purpose |
| --- | --- |
| `safe-migrate-baseline` GitHub environment | Protects `SAFE_MIGRATE_DATABASE_URL`. Restrict deployment branches to your default branch (and add required reviewers if you want manual approval before refreshes). |
| Local, socket, or tunneled PostgreSQL access on the refresh runner | `safe-migrate sync` refuses direct remote connections; use a self-hosted runner on your database network or add an SSH/WireGuard/cloud-proxy tunnel step before syncing. |
| GitHub-hosted runner or self-hosted runner `>= 2.327.1` | Supports the Node.js 24 runtime used by the pinned Actions. |

## Quick setup

### Option A: Automated setup with GitHub CLI

From the repository root, with `gh` authenticated:

```bash
safe-migrate init github-actions \
  --path migrations \
  --configure-secrets
```

This command:
- checks `gh` authentication and warns if `safe-migrate-baseline` lacks branch
  or reviewer protection;
- prompts for `SAFE_MIGRATE_DATABASE_URL` and uploads it to the
  `safe-migrate-baseline` environment;
- generates a 32-byte `SAFE_MIGRATE_CACHE_KEY` and uploads it as a repository
  secret without printing it;
- writes `.github/workflows/safe-migrate-baseline.yml` and
  `.github/workflows/safe-migrate.yml` atomically.

### Option B: Manual secret setup

```bash
safe-migrate init github-actions --path migrations
gh secret set SAFE_MIGRATE_DATABASE_URL --env safe-migrate-baseline
safe-migrate init cache-key --set-github-secret
```

### Bootstrap the first baseline

1. Add any required tunnel or self-hosted `runs-on` label to
   `.github/workflows/safe-migrate-baseline.yml`.
2. Trigger **Refresh safe-migrate baseline** once from the **Actions** tab so
   the encrypted cache exists before making the PR check required.

## Workflow examples

### Baseline refresh workflow (`.github/workflows/safe-migrate-baseline.yml`)

```yaml
name: Refresh safe-migrate baseline
on:
  workflow_dispatch:
  schedule:
    - cron: '17 3 * * 1,4'

permissions: {}

jobs:
  refresh-baseline:
    runs-on: ubuntu-latest
    environment:
      name: safe-migrate-baseline
      deployment: false
    timeout-minutes: 15
    steps:
      # Add your SSH tunnel or cloud proxy step here so localhost reaches PostgreSQL.
      - uses: dsecurity49/safe-migrate@v0.14.0
        with:
          sync: 'true'
        env:
          DATABASE_URL: ${{ secrets.SAFE_MIGRATE_DATABASE_URL }}
          SAFE_MIGRATE_CACHE_KEY: ${{ secrets.SAFE_MIGRATE_CACHE_KEY }}
```

### Pull-request analysis workflow (`.github/workflows/safe-migrate.yml`)

```yaml
name: Check migrations
on:
  pull_request:
    branches: [main]
  merge_group:

permissions:
  contents: read

jobs:
  safe-migrate:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false

      - id: analyze
        uses: dsecurity49/safe-migrate@v0.14.0
        with:
          path: migrations
        env:
          SAFE_MIGRATE_CACHE_KEY: ${{ secrets.SAFE_MIGRATE_CACHE_KEY }}

      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: safe-migrate-reports
          path: safe-migrate-artifacts
```

## Security & operational notes

- **Database login**: `sync` records `current_user`, `session_user`, role
  memberships, `search_path`, and `lock_timeout` / `statement_timeout`. A
  dedicated read-only catalog user minimizes credential blast radius, while
  connecting as the migration role yields exact `SET ROLE` and ownership checks.
- **What is cached**: schema objects, dependencies, statistics (`reltuples`),
  roles, privileges, version, search path, and timeouts, encrypted with
  XChaCha20-Poly1305 (`SMENC001` wrapping `SMCACHE12` V12.1). Password hashes,
  `DATABASE_URL`, and `pg_subscription.subconninfo` are never queried or stored.
- **Forks & Dependabot**: fork PRs do not receive repository secrets and fail
  preflight before downloading the cache. Do not use `pull_request_target` to
  run untrusted PR code with secrets.
- **Required checks**: keep the PR workflow free of `paths:` filters if it is a
  required status check, so skipped workflows do not leave PRs permanently
  `Pending`.

## Failure & recovery

| Condition | Outcome | Fix |
| --- | --- | --- |
| No cache restored or outdated cache format (`< V12`) | Exit `1` (operational failure) | Run **Refresh safe-migrate baseline**. |
| Missing or non-64-hex `SAFE_MIGRATE_CACHE_KEY` | Exit `1` before DB or SQL access | Rotate key with `safe-migrate init cache-key --set-github-secret` and refresh. |
| Baseline older than `stale_stats_days` (default `7`) | Analysis runs with `Tainted` confidence and stderr warning | Run **Refresh safe-migrate baseline**. |
| Tier 1 finding in migration | Exit `2` (or exit `0` when `advisory: 'true'`) | Fix the migration SQL per the reported `recipe`. |

## Action inputs and outputs

| Input | Default | Description |
| --- | --- | --- |
| `path` | `""` | Migration file or directory to analyze. Omit only when `sync: 'true'` for refresh-only jobs. |
| `mode` | `auto` | `auto` (`lint` for file, `lint-chain` for directory), `file`, or `dir`. |
| `sync` | `"false"` | Refresh the baseline from `DATABASE_URL` in this trusted job. |
| `schemas` | `""` | Optional comma-separated schema filter passed to `sync`. |
| `baseline` | `default` | Logical managed-cache name (use distinct names for multiple target databases). |
| `cache` | `""` | Explicit cache file path; disables automatic GitHub cache restore/save. |
| `config` | `""` | Explicit `safe-migrate.toml` path (when empty, built-in defaults apply). |
| `encrypted-cache` | `"true"` | Encrypt/decrypt the cache with `SAFE_MIGRATE_CACHE_KEY`. |
| `no-cache` | `"false"` | Explicit degraded SQL-only mode (`Tainted` confidence). |
| `output-dir` | `safe-migrate-artifacts` | Workspace-relative directory for JSON, Markdown, and diagnostic logs. |
| `advisory` | `"false"` | Do not fail the job on exit `2` (Tier 1 findings); operational errors (exit `1`) still fail. |

| Output | Description |
| --- | --- |
| `json-report` | Path to `safe-migrate-report.json` (empty on sync-only runs). |
| `markdown-report` | Path to `safe-migrate-report.md` (empty on sync-only runs). |
| `diagnostic-log` | Path to captured stderr diagnostics. |
| `exit-code` | `0` (clean/Tier 2/3), `1` (operational error), or `2` (Tier 1 findings). |
| `cache-path` | Resolved cache file path. |
| `sync-status` | `not-requested`, `refreshed`, or `failed`. |
| `baseline-source` | `synced`, `github-cache`, `explicit-file`, or `unavailable`. |
