# safe-migrate

`safe-migrate` is a CI/CD infrastructure tool that prevents PostgreSQL database migrations from causing catastrophic locking queues in production. 

It combines static AST (Abstract Syntax Tree) analysis of your SQL migrations with dynamic table statistics from your live database to proactively halt dangerous migrations.

## The Problem
Running `ALTER TABLE users ADD COLUMN email VARCHAR;` on a table with 100 rows is perfectly safe. Running that exact same statement on a table with 100,000,000 rows requires an `ACCESS EXCLUSIVE` lock that blocks all reads and writes, immediately taking down your application.

Standard linters only look at the code. `safe-migrate` looks at the code **and** the size of the tables it affects.

## Installation

The easiest way to install `safe-migrate` on macOS or Linux is via our automated install script, which fetches the correct pre-compiled binary for your system:

```bash
curl -fsSL https://raw.githubusercontent.com/dsecurity49/safe-migrate/main/install.sh | bash
```

**Alternative: Cargo (Rust users)**
If you already have a Rust toolchain installed, you can build from source via crates.io:

```bash
cargo install safe-migrate
```
## Quick Start

**1. Sync Database Statistics**
Pull the latest approximate row counts from your database (uses `pg_class.reltuples` for speed and safety).

```bash
export DATABASE_URL="postgres://user:pass@localhost:5432/mydb"
safe-migrate sync
```
*This generates a local `.safe-migrate-stats.json` cache.*

**2. Lint Your Migration**
Evaluate a migration file against the cached stats.

```bash
safe-migrate lint --file my_migration.sql
```

## CI/CD Integration (GitHub Actions)

Add this workflow to your repository to automatically lint new migration files on every pull request. 

> **Note:** You must set `fetch-depth: 0` in the checkout action so Git has enough history to compare branches!

```yaml
name: Safe Migrate

on:
  pull_request:
    branches: [ "main" ]

jobs:
  lint-migrations:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Required to run git diff against the base branch

      - name: Install safe-migrate
        run: curl -fsSL https://raw.githubusercontent.com/dsecurity49/safe-migrate/main/install.sh | bash

      - name: Sync database stats
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
        run: safe-migrate sync

      - name: Lint new migrations
        run: |
          # Get list of changed .sql files
          FILES=$(git diff --name-only origin/${{ github.base_ref }}...HEAD -- '*.sql')
          
          if [ -z "$FILES" ]; then
            echo "No SQL migrations changed. Skipping."
            exit 0
          fi
          
          for f in $FILES; do
            echo "Linting $f..."
            safe-migrate lint --file "$f"
          done
```

Make sure to add your database connection string to your GitHub repository secrets as `DATABASE_URL`.


## Configuration

You can customize lock tiers and row count thresholds by creating a `safe-migrate.toml` file in your repository root. By default, `safe-migrate` will flag Tier 1 operations on tables with over 1,000,000 rows.

```toml
# safe-migrate.toml

# Global threshold fallback
default_threshold = 500000 

# Override specific rules
[rules.adding-field-with-default]
tier = "Tier1"
threshold = 100000 # Stricter threshold for this specific rule

[rules.require-concurrent-index-creation]
tier = "Tier2"
# Omitting threshold falls back to default_threshold
```

### Risk Tiers
* **Tier 1 (ACCESS EXCLUSIVE):** Operations that rewrite the table or block all reads and writes (e.g., adding a field with a default, changing column types). If the threshold is breached, the build **halts**.
* **Tier 2 (SHARE ROW EXCLUSIVE):** Operations that can cause lock queues if not managed properly (e.g., non-concurrent index creation). Emits a **warning**.
* **Tier 3 (Safe):** Standard operations that do not acquire aggressive locks.

## Architecture
`safe-migrate` parses your SQL using a native PostgreSQL Abstract Syntax Tree (AST). It handles quotes, complex schemas, and multi-statement transactions natively without relying on brittle regular expressions or string splitting.

## License

This project is dual-licensed under either the [MIT license](LICENSE-MIT) or the [Apache License, Version 2.0](LICENSE-APACHE), at your option.
