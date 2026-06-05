# safe-migrate

A CLI that prevents PostgreSQL migrations from causing production outages by combining static SQL analysis with live database statistics.

Standard linters only look at the SQL. `safe-migrate` checks the SQL **and** the size of the tables it affects. `ALTER TABLE users ADD COLUMN status TEXT` is safe on a 500-row table. On a 50M-row table it acquires an `ACCESS EXCLUSIVE` lock that takes down your app.

---

## Installation

````bash
curl -fsSL https://raw.githubusercontent.com/dsecurity49/safe-migrate/main/install.sh | bash
````

Or with Cargo:

````bash
cargo install safe-migrate
````

---

## How It Works

**Step 1 — Sync:** Connect to your database once and pull approximate row counts from `pg_class`:

````bash
export DATABASE_URL="postgres://user:pass@localhost:5432/mydb"
safe-migrate sync
````

This writes a `.safe-migrate-stats.json` cache file. No credentials are stored — only table names, row estimates, and index mappings.

**Step 2 — Lint:** Analyze your migration file against the cache:

````bash
safe-migrate lint --file migration.sql
````

The engine parses the SQL into a typed AST, classifies every statement by its PostgreSQL lock type, and crosses it against the cached row count for that specific table. Large table with a dangerous lock — halt. Small table — silent pass.

---

## Output

````
--------------------------------------------------------------------------------
[FAIL] [TIER 1 - DANGER ] Adding column to 'public.users'. Verify it lacks a VOLATILE default.
                          Rule:   adding-field-with-default
                          Recipe: Since PostgreSQL 11, adding a column with a constant default is
                                  instant. However, volatile defaults (e.g., gen_random_uuid())
                                  will rewrite the entire table.
                                  Safe Migration (Expand/Contract):
                                  1. Add the column as nullable.
                                  2. Backfill existing rows in small batches.
                                  3. Add a check constraint using NOT VALID.
                                  4. Validate the constraint in a separate migration.
--------------------------------------------------------------------------------
````

Exit code `1` on any Tier 1 finding. Exit code `0` on warnings or clean runs.

---

## Risk Tiers

| Tier | Lock Type | Default Behavior |
|------|-----------|-----------------|
| Tier 1 | `ACCESS EXCLUSIVE` — blocks all reads and writes | Halts the build |
| Tier 2 | `SHARE ROW EXCLUSIVE` — blocks writes only | Warns, continues |
| Tier 3 | Safe / non-blocking | Silent pass |

Unanalyzed tables (never vacuumed) are treated as infinitely large and fail closed.

---

## Configuration

Create a `safe-migrate.toml` in your repo root to override thresholds and tiers per rule:

````toml
# Global row count threshold (default: 100,000)
default_threshold = 200000

[rules.adding-field-with-default]
tier = "Tier2"
threshold = 50000

[rules.require-concurrent-index-creation]
tier = "Tier1"
````

Available rules: 
- `adding-field-with-default`
- `changing-column-type`
- `adding-not-nullable-field`
- `adding-serial-primary-key-field`
- `adding-required-field`
- `renaming-column`
- `renaming-table`
- `disallowed-unique-constraint`
- `ban-drop-table`
- `ban-drop-column`
- `require-concurrent-index-creation`
- `require-concurrent-index-deletion`
- `adding-foreign-key-constraint`
- `constraint-missing-not-valid`

---

## CLI Reference

### `safe-migrate lint`

|  Flag  | Default | Description |
|--------|---------|-------------|
| `-f, --file` | required | Path to the SQL migration file |
| `--cache` | `.safe-migrate-stats.json` | Path to the stats cache file |
| `--config` | `safe-migrate.toml` | Path to TOML config overrides |
| `-s, --schema` | `public` | Default schema for unqualified table names |

### `safe-migrate sync`

| Flag | Default | Description |
|------|---------|-------------|
| `--out` | `.safe-migrate-stats.json` | Output path for the cache file |

Requires `DATABASE_URL` environment variable.

---

## CI/CD Integration

````yaml
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
          fetch-depth: 0

      - name: Install safe-migrate
        run: curl -fsSL https://raw.githubusercontent.com/dsecurity49/safe-migrate/main/install.sh | bash

      - name: Sync database stats
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
        run: safe-migrate sync --out prod-cache.json

      - name: Lint new migrations
        run: |
          FILES=$(git diff --name-only origin/${{ github.base_ref }}...HEAD -- '*.sql')

          if [ -z "$FILES" ]; then
            echo "No SQL migrations changed. Skipping."
            exit 0
          fi

          for f in $FILES; do
            echo "Linting $f..."
            safe-migrate lint --file "$f" --cache prod-cache.json
          done
````

Add `DATABASE_URL` to your repository secrets.

---

## Architecture

`safe-migrate` uses squawk's PostgreSQL AST parser as a library crate for typed SQL analysis rather than string matching or subprocess calls. The sync step is read-only (`pg_class` catalog queries only) and requires no application credentials. DML statements (`INSERT`, `UPDATE`, `DELETE`, `SELECT`) inside migration files are automatically ignored.

---

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at your option.
