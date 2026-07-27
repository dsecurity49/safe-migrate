# safe-migrate v0.4.2

A PostgreSQL migration linter that **executes a bi-directional state machine simulation** over your SQL, combining static typed AST analysis with live database statistics to prevent blocking locks before they reach production.

**The Problem:** `ALTER TABLE users ADD COLUMN status TEXT` is safe on 500 rows. On 50M rows, it acquires an `ACCESS EXCLUSIVE` lock that takes down your app. Standard linters only look at the SQL. **safe-migrate looks at the SQL AND the size of the tables it affects.**

---

## What's New in v0.4.2

v0.4.2 upgrades the squawk parser to 2.61.0, adds `pg_depend`-based dependency tracking, and introduces a differential test harness that compares the simulator against real PostgreSQL dry-runs across all 26 rules.

Highlights:
- **Parser upgrade**: squawk-{syntax,lexer,parser} 2.58.0 → 2.61.0; full AST extraction migration to `PathRef`/`NameRef`/`descendants_with_tokens()` API
- **Dependency tracking**: `safe-migrate sync` queries `pg_depend` and builds a `DependencyCache`; 9 graph edge types consolidated into unified `DependencyEdge`/`DependencyKind`
- **Differential harness**: `tests/live_differential_harness.rs` + `live_tests/` manifest and baseline — 0 mismatches across all 26 rules
- **Bug fixes**: `DropSchema` without `CASCADE` correctly returns conflict; cache format version validated at decode; role name extraction handles keyword tokens (`PUBLIC_KW`, `GROUP_KW`) with PostgreSQL case-folding
- 344 passing unit tests; 510 live_tests fixtures pass

### ✅ Live Database Statistics Integration

The `sync` command reads from PostgreSQL's catalog:
- `pg_class.reltuples` — estimated row counts
- `pg_class.relpages` — page estimates for TOAST threshold crossing
- `pg_stat_user_tables.last_analyze` — staleness detection
- `pg_attribute.avg_width` — column width for compression decisions
- Foreign key graph, index mappings, partition hierarchies

**No application credentials needed** — `sync` only requires `SELECT` on catalog tables.

---

## Installation

### From Binary (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/dsecurity49/safe-migrate/main/install.sh | bash
```

Supports:
- Linux (x86_64, ARM64, musl)
- macOS (Intel, Apple Silicon)
- Windows (x86_64)

### From Cargo

```bash
cargo install safe-migrate
```

---

## Quick Start

### Step 1: Sync Database Statistics

```bash
export DATABASE_URL="postgres://user:password@localhost:5432/mydb"
safe-migrate sync
```

Creates `.safe-migrate.cache` with table sizes, column info, constraints, and indexes. Safe to commit to source control — contains no secrets, only statistics.

**TLS warning:** When `DATABASE_URL` points to a non-localhost host, safe-migrate emits a warning that the connection is unencrypted. Use `sslmode=require` in your connection string or an SSH tunnel for production databases.

**Cache freshness:** Warnings if older than 7 days (configurable). Stale stats are flagged in the report.

### Step 2: Lint Your Migration

```bash
safe-migrate lint --file migration.sql
```

Output:

```
┌────────────────────────────────────────────────────────────────┐
│ safe-migrate lint                                              │
╞════════════════════════════════════════════════════════════════╡
│ Verdict: HALT       Confidence: Exact                          │
│ HALT: 1   WARN: 1   SAFE: 0                                    │
└────────────────────────────────────────────────────────────────┘

 [HALT] blocking-constraint
   object : table public.orders
   reason : synchronous FOREIGN KEY constraint addition locks public.orders and public.auth_users
   recipe : Add it as NOT VALID first, then VALIDATE in a separate transaction.
   sql    : ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES auth_users(id);

 ──────────────────────────────────────────────────

 [WARN] require-concurrent-index
   object : index public.idx_orders_user
   reason : synchronous index creation on public.orders can block writes
   recipe : Add the CONCURRENTLY keyword.
   sql    : CREATE INDEX idx_orders_user ON orders(user_id);

┌────────────────────────────────────────────────────────────────┐
│ SUMMARY                                                        │
╞════════════════════════════════════════════════════════════════╡
│ Verdict                 : HALT                                 │
│ Recommendation          : do not deploy                        │
│ HALT (Tier 1)           : 1                                    │
│ WARN (Tier 2)           : 1                                    │
│ SAFE (Tier 3)           : 0                                    │
└────────────────────────────────────────────────────────────────┘
```

Exit code: **1** (Tier 1 violation) → CI build fails

---

## The Trust Model

### Confidence Levels

| Level | Meaning | When It Happens |
|-------|---------|-----------------|
| **Exact** | Analysis is mathematically sound | Pure DDL, no opaque SQL |
| **Tainted** | Some DDL is hidden in opaque statements | `DO` blocks, `EXECUTE` statements, dynamic SQL |

When confidence is `Tainted`, the engine:
- Still evaluates all visible DDL
- Warns that hidden mutations may exist
- Does **not** suppress violations (conservative)

### Version-Gating

safe-migrate detects your PostgreSQL version from the cache and applies version-specific rules:

**Example: Constant DEFAULT on ADD COLUMN**

```sql
ALTER TABLE orders ADD COLUMN status VARCHAR(20) DEFAULT 'pending';
```

- **PG 11+**: Metadata-only, no rewrite → ✅ Safe (Tier 3)
- **PG <11**: Table rewrite → ⚠️ Warning (Tier 2 for small tables, Tier 1 for large)

The rule reads `pg_version_num` from the cache and applies the correct threshold.

### Cache Staleness

Tables without recent `ANALYZE`:
- Flagged as `[WARNING: Based on stale statistics]`
- Treated conservatively (assume Tier 2+ severity)
- Still evaluated (not suppressed)

Example:

```
[WARN] [TIER 2 - WARNING] Table statistics are stale. Lock evaluations may be 
                          inaccurate.
                          Rule:   blocking-constraint
                          Recipe: Run ANALYZE to ensure accurate row estimates.
```

---

## Rules Reference

All 26 rules with examples:

### 1. **blocking-constraint** (Tier 1)
Adding a valid `CHECK` or `FOREIGN KEY` constraint scans the entire table with an `ACCESS EXCLUSIVE` lock.

```sql
ALTER TABLE orders ADD CONSTRAINT fk_user 
  FOREIGN KEY (user_id) REFERENCES users(id);
```

**Safe alternative:**
```sql
ALTER TABLE orders ADD CONSTRAINT fk_user 
  FOREIGN KEY (user_id) REFERENCES users(id) NOT VALID;
-- Later, in a separate migration:
ALTER TABLE orders VALIDATE CONSTRAINT fk_user;
```

### 2. **size-aware-add-column** (Tier 1)
Adding a column with a volatile `DEFAULT` requires a table rewrite, even on PG11+.

```sql
ALTER TABLE orders ADD COLUMN created_at TIMESTAMP DEFAULT NOW();  -- REWRITE
ALTER TABLE orders ADD COLUMN id UUID DEFAULT gen_random_uuid();   -- REWRITE
```

**Safe alternative (PG11+):**
```sql
ALTER TABLE orders ADD COLUMN status VARCHAR(20) DEFAULT 'pending';  -- METADATA ONLY
```

### 3. **type-change-rewrite** (Tier 1)
Changing a column type usually requires a full table rewrite with `ACCESS EXCLUSIVE` lock.

```sql
ALTER TABLE users ALTER COLUMN id TYPE BIGINT;  -- REWRITE
```

**Safe alternatives:**
- Widen `varchar(10)` → `varchar(100)` (no rewrite)
- Widen `numeric(10,2)` → `numeric(20,2)` on PG12+ (no rewrite)

### 4. **concurrent-index** (Tier 2)
Synchronous index creation blocks writes. Use `CONCURRENTLY`.

```sql
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
DROP INDEX CONCURRENTLY idx_users_email;
```

### 5. **concurrent-in-transaction** (Tier 1)
PostgreSQL does not allow `CREATE/DROP INDEX CONCURRENTLY` inside an explicit transaction block.

```sql
BEGIN;
CREATE INDEX CONCURRENTLY idx ON users(id);  -- ❌ ERROR
COMMIT;
```

### 6. **cascading-drop** (Tier 1)
`DROP TABLE ... CASCADE` silently destroys views, indexes, constraints without warning.

```sql
DROP TABLE users CASCADE;  -- ❌ May drop dependent views
```

**Safe alternative:**
```sql
DROP VIEW dependent_view;
DROP TABLE users;
```

### 7. **blocking-mat-view-refresh** (Tier 2)
`REFRESH MATERIALIZED VIEW` (without `CONCURRENTLY`) blocks all reads during refresh.

```sql
REFRESH MATERIALIZED VIEW mv_order_totals;
```

**Safe alternative:**
```sql
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_order_totals;
```

### 8. **partition-lock** (Tier 1/2)
Partition operations (attaching/detaching) that affect large parent tables. HASH partitioned tables escalate locking severity (the tier thresholds are halved) due to more aggressive locking.

### 9. **opaque-dynamic-sql** (Tier 2)
`DO` blocks and `EXECUTE` statements hide mutations. Analysis confidence degrades.

```sql
DO $$
BEGIN
  EXECUTE 'ALTER TABLE ' || table_name || ' ADD COLUMN id int';
END $$;
```

**Recommendation:** Avoid dynamic DDL in migrations. Use explicit SQL.

### 10. **volatile-default** (Tier 3)
Using volatile functions like `random()` or `now()` as defaults can cause unexpected behavior in logical replication.

### 11. **vacuum-full** (Tier 1)
`VACUUM FULL` requires an `ACCESS EXCLUSIVE` lock and rewrites the entire table. Never in migrations.

### 12. **idempotency** (Tier 3, disabled by default)
Recommend `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS` for safer re-runs.

### 13. **overbroad-grant** (Tier 1/2)
Flags grants that apply too broadly — `GRANT ... TO PUBLIC` (Tier 1, applies to every role) or `GRANT ALL PRIVILEGES` to a non-owner role (Tier 2).

```sql
GRANT ALL PRIVILEGES ON orders TO PUBLIC;  -- ❌ Tier 1: PUBLIC is every role
GRANT SELECT ON orders TO app_user;        -- ✅ Safe
```

### 14. **broken-compute** (Tier 1)
Flags dropping a function that is used by one or more triggers. The trigger would be left pointing at a non-existent function.

```sql
CREATE TRIGGER audit BEFORE INSERT ON orders EXECUTE FUNCTION audit_fn();
DROP FUNCTION audit_fn();  -- ❌ breaks the trigger
```

### 15. **drop-database** (Tier 1)
`DROP DATABASE` is an irreversible, high-blast-radius operation that destroys the entire database. Should never appear in a migration file.

### 16. **schema-drift** (Tier 1)
Flags migrations that reference tables or objects not present in the synced production baseline. If `DROP TABLE orders` is in the migration but `orders` is not in the cache, the migration would fail at runtime. Also flags when creating a partitioned table (`CREATE TABLE ... PARTITION OF parent`) where the parent table does not exist in the production baseline.

**Requires `safe-migrate sync` to be meaningful.** Without a cache, this rule has no baseline to compare against.

### 17. **irreversible-migration** (Tier 1/3)
Classifies `DROP COLUMN`, `DROP TABLE`, and lossy type changes (`VARCHAR(255) → VARCHAR(50)`) as irreversible. Tier is gated on row count — empty tables get Tier 3 (low risk), populated tables get Tier 1.

```sql
ALTER TABLE orders DROP COLUMN legacy_code;  -- Tier 1 if rows > 0, Tier 3 if empty
```

### 18. **restrictive-policy** (Tier 2)
Flags RLS policies with `AS RESTRICTIVE` that could unexpectedly restrict access beyond what was intended.

### 19. **disable-trigger** (Tier 2)
Flags `ALTER TABLE ... DISABLE TRIGGER ALL` in migration files. Disabling triggers in a migration means constraints and audit trails are bypassed for the duration of the migration.

### 20. **chain-conflict** (Tier 1)
When using `lint-chain`, flags migrations in the same chain that add the same column with different types to the same table. Only applies to multi-file chain execution.

### 21. **partition-strategy-mismatch** (Tier 1)
Flags `ATTACH PARTITION` operations where the partition being attached does not match the parent table's partition strategy (RANGE/LIST/HASH). Mismatched strategies will cause the operation to fail at runtime.

```sql
-- If parent table is defined as PARTITION BY RANGE:
ALTER TABLE parent_table ATTACH PARTITION child_table FOR VALUES IN ('2023-01-01'); -- ❌ if child_table is HASH partitioned or has no partition strategy
```

---

## Configuration

Create `safe-migrate.toml` in your repo root to customize rule behavior and thresholds. All settings are optional — safe-migrate ships with sensible defaults. Invalid or unparseable config files cause safe-migrate to exit with an error (no silent fallback).

### Global Settings

```toml
# Row count threshold for Tier 1 (default: 100,000)
# Tables with >= this many rows trigger Tier 1 for dangerous operations
tier1_threshold_rows = 100000

# Row count threshold for Tier 2 (default: 10,000)
# Tables with >= this many rows trigger Tier 2 for dangerous operations
tier2_threshold_rows = 10000

# PostgreSQL version to assume when database is offline (default: 100000)
# Format: XXYYZZ (e.g., 100000 = PG 10.0, 110000 = PG 11.0, 170010 = PG 17.0.10)
# Used for version-gated rules like constant DEFAULT on ADD COLUMN (safe on PG11+)
assume_pg_version = 100000

# TOAST column width threshold in bytes (default: 2048)
# Columns wider than this are flagged for TOAST overflow risk
toast_width_threshold_bytes = 2048

# Default row count for unanalyzed tables (default: 10,000)
# Tables with unknown size are treated as having this many rows
default_rows = 10000

# Cache freshness threshold in days (default: 7)
# Warns if .safe-migrate.cache is older than this
stale_stats_days = 7
```

### Per-Rule Configuration

Override any rule's tier or thresholds:

```toml
[rules.blocking-constraint]
# Stricter thresholds for foreign key constraints specifically
tier1_threshold_rows = 5000
tier2_threshold_rows = 1000

[rules.size-aware-add-column]
# Escalate all table rewrites to Tier 1 regardless of size
tier1_threshold_rows = 0

[rules.missing-idempotency]
# Disable the idempotency rule (don't warn about missing IF NOT EXISTS)
disabled = true
```

### Complete Example

```toml
# Global defaults for the whole team
tier1_threshold_rows = 100000
tier2_threshold_rows = 10000
assume_pg_version = 170000   # Assume PG 17 for new staging envs
toast_width_threshold_bytes = 2048
default_rows = 10000
stale_stats_days = 7

# Stricter rules for high-traffic tables
[rules.blocking-constraint]
tier1_threshold_rows = 1000    # Flag FKs on tables >1K rows
tier2_threshold_rows = 100

[rules.concurrent-index]
tier1_threshold_rows = 50000   # Flag non-concurrent indexes on tables >50K rows

# Relax some rules for safer operations
[rules.blocking-mat-view-refresh]
tier1_threshold_rows = 500000  # Only flag materialized view refresh on huge tables

# Disable rules that don't apply to your workflow
[rules.vacuum-full]
disabled = true
```

### Rule Reference

| Rule ID | What It Does | Default Tier |
|---------|------------|--------------|
| `destructive-cascade` | Flags DROP TABLE ... CASCADE operations that affect baseline schema | Tier 1 |
| `size-aware-add-column` | Flags table rewrites for ADD COLUMN with volatile defaults or PG<11 constant defaults | Tier 1 |
| `type-change-rewrite` | Flags type changes that force ACCESS EXCLUSIVE table rewrites | Tier 1 |
| `blocking-constraint` | Flags synchronous CHECK or FOREIGN KEY constraint additions | Tier 1 |
| `blocking-index-constraint` | Flags synchronous PRIMARY KEY or UNIQUE constraint additions via index | Tier 1 |
| `require-concurrent-index` | Flags synchronous index creation | Tier 2 |
| `require-concurrent-drop-index` | Flags synchronous index dropping | Tier 2 |
| `blocking-mat-view-refresh` | Flags synchronous REFRESH MATERIALIZED VIEW (without CONCURRENTLY) | Tier 2 |
| `partition-lock` | Flags partition attach/detach operations on large tables | Tier 1/2 |
| `concurrent-in-transaction` | Blocks CONCURRENTLY index operations inside explicit transaction blocks | Tier 1 |
| `vacuum-full` | Flags VACUUM FULL usage (requires ACCESS EXCLUSIVE lock) | Tier 1 |
| `opaque-dynamic-sql` | Detects dynamic SQL (DO blocks, EXECUTE) that hides mutations | Tier 2 |
| `volatile-default` | Notes volatile functions like `clock_timestamp()` or `random()` in defaults | Tier 3 |
| `missing-idempotency` | Recommends IF NOT EXISTS on CREATE statements (disabled by default) | Tier 3 |
| `table-rewrite-storage` | Flags table rewrites caused by column storage parameter changes | Tier 1 |
| `table-rewrite-access-method` | Flags table rewrites caused by access method changes | Tier 1 |
| `overbroad-grant` | Flags GRANT ... TO PUBLIC or GRANT ALL PRIVILEGES to non-owner roles | Tier 1/2 |
| `broken-compute` | Flags dropping a function that backs a trigger | Tier 1 |
| `drop-database` | Flags DROP DATABASE in migration files | Tier 1 |
| `schema-drift` | Flags references to tables absent from the production baseline | Tier 1 |
| `irreversible-migration` | Flags DROP COLUMN, DROP TABLE, lossy type changes as irreversible | Tier 1/3 |
| `restrictive-policy` | Flags RESTRICTIVE RLS policies that could unexpectedly restrict access | Tier 2 |
| `disable-trigger` | Flags ALTER TABLE ... DISABLE TRIGGER ALL in migrations | Tier 2 |
| `chain-conflict` | Flags same-chain migrations adding the same column with different types | Tier 1 |
| `partition-strategy-mismatch` | Flags partition attachment where strategies mismatch | Tier 1 |

### Version-Gating Examples

The engine reads `assume_pg_version` and applies version-specific rules:

**PG 11+: Constant defaults are safe**
```sql
-- With assume_pg_version >= 110000, this is metadata-only (safe):
ALTER TABLE orders ADD COLUMN status VARCHAR(20) DEFAULT 'pending';
```

**PG <11: Constant defaults require rewrite**
```sql
-- With assume_pg_version < 110000, same SQL flags as Tier 1:
ALTER TABLE orders ADD COLUMN status VARCHAR(20) DEFAULT 'pending';
```

### Cache Behavior

If `safe-migrate sync` hasn't been run or the cache is missing:
- Uses `assume_pg_version` for version-gated rules
- Uses `default_rows` for all unanalyzed tables
- Sets confidence to `Tainted` (since actual row counts are unknown)

If the cache exists and is fresh:
- Uses actual `pg_version_num` from PostgreSQL
- Uses actual table row counts from `pg_class.reltuples`
- Sets confidence to `Exact` (unless dynamic SQL is detected)

---

## CLI Reference

### `safe-migrate lint`

```bash
safe-migrate lint \
  --file migration.sql \
  --config safe-migrate.toml \
  --cache .safe-migrate.cache \
  --no-cache \
  --interactive \
  --json
```

| Flag | Default | Description |
|------|---------|-------------|
| `-f, --file` | required | SQL migration file |
| `--config` | `safe-migrate.toml` | Config overrides |
| `--cache` | `.safe-migrate.cache` | Stats cache |
| `--no-cache` | false | Use worst-case assumptions (offline mode) |
| `-i, --interactive` | false | Launch full-screen TUI to browse violations |
| `--json` | false | Output violations as JSON for CI/CD integration |

### `safe-migrate lint-chain`

Lint an ordered directory of migration files with state persisting across files. Files are processed in lexicographic order (V1__, V2__, etc.).

```bash
safe-migrate lint-chain \
  --dir migrations/ \
  --config safe-migrate.toml \
  --cache .safe-migrate.cache
```

| Flag | Default | Description |
|------|---------|-------------|
| `--dir` | required | Directory of .sql files |
| `--config` | `safe-migrate.toml` | Config overrides |
| `--cache` | `.safe-migrate.cache` | Stats cache |
| `--no-cache` | false | Use worst-case assumptions |
| `-i, --interactive` | false | Launch full-screen TUI to browse violations |
| `--json` | false | Output violations as JSON |

### `safe-migrate sync`

```bash
export DATABASE_URL="postgres://user:pass@localhost/db"
safe-migrate sync --out prod-cache.json --schemas public,auth
```

| Flag | Default | Description |
|------|---------|-------------|
| `--out` | `.safe-migrate.cache` | Cache output path |
| `--schemas` | (all schemas) | Comma-separated list of schemas to sync; FK dependencies pulled cross-schema automatically |

**Requires `DATABASE_URL` environment variable.**

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Safe Migrate

on:
  pull_request:
    branches: [main]

jobs:
  lint-migrations:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install safe-migrate
        run: |
          curl -fsSL https://raw.githubusercontent.com/dsecurity49/safe-migrate/main/install.sh | bash

      - name: Sync database stats
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
        run: safe-migrate sync --out prod-cache.json

      - name: Lint changed migrations
        run: |
          FILES=$(git diff --name-only origin/main...HEAD -- '*.sql')
          
          if [ -z "$FILES" ]; then
            echo "No migrations changed."
            exit 0
          fi
          
          for f in $FILES; do
            echo "Linting $f..."
            safe-migrate lint --file "$f" --cache prod-cache.json
          done
```

### GitLab CI

```yaml
lint-migrations:
  image: ubuntu:latest
  script:
    - curl -fsSL https://raw.githubusercontent.com/dsecurity49/safe-migrate/main/install.sh | bash
    - safe-migrate sync --out prod-cache.json
    - |
      git diff --name-only origin/main...HEAD -- '*.sql' | while read f; do
        safe-migrate lint --file "$f" --cache prod-cache.json
      done
  only:
    - merge_requests
```

---

## live_tests/ — End-to-End Integration Suite

`live_tests/` is an exhaustive end-to-end suite that runs the compiled `safe-migrate` binary against 510 SQL migration fixtures across all 26 rule directories. It validates the AST parser, state machine, and rule evaluators in combination — not just unit logic.

```bash
cd live_tests

./run.sh            # Full suite (silent summary per directory)
./run.sh -v         # Verbose: pass/fail per file
./run.sh -d rule_09_blocking-constraint   # Single rule directory
./run.sh -t rule_01_irreversible-migration/001_drop_table.sql  # Single file
./run.sh --offline  # No cache, worst-case assumptions
```

**Fixture naming:** `safe_*.sql` files must emit 0 violations for the target rule; `[0-9]*.sql` files must emit ≥ 1.

The suite ships a frozen `.safe-migrate.cache` binary file so it runs in CI without a live PostgreSQL instance. `chain-conflict` directories are linted with `lint-chain -d`; all others use `lint -f` per file.

---

## Architecture

safe-migrate parses your migration into a typed AST, then simulates it statement-by-statement against an in-memory model of your schema (tables, columns, indexes, foreign keys, views, partitions, functions, triggers, roles, policies, publications, subscriptions). That model starts from your synced database statistics and is updated as each statement is applied — so by the time a rule runs, it's checking against the schema as it would actually look at that point in the migration, not just the raw SQL text.

This is what allows things like:
- Correctly evaluating a `DROP TABLE ... CASCADE` against everything that actually depends on it
- Knowing a table was renamed earlier in the same file when checking a later `ALTER TABLE`
- Treating `BEGIN ... ROLLBACK` as a no-op on the schema, rather than analyzing the in-transaction state as if it persisted (confidence correctly restored after rollback)
- Detecting that dropping a function would break a trigger that depends on it
- Flagging migrations that reference tables absent from the production baseline

DML statements (`INSERT`, `UPDATE`, `DELETE`, `SELECT`) are ignored. Dynamic SQL (`DO` blocks, `EXECUTE`) is detected and flagged, since it can hide schema changes the simulator can't see. When confidence is `Tainted` due to opaque SQL, Tier 1 violations are downgraded to Tier 2 — unless the opaque SQL was inside a transaction that was subsequently rolled back, in which case confidence is fully restored.

---

## Why This Matters

PostgreSQL lock behavior is invisible in the SQL itself. The same `ALTER TABLE` statement is a no-op on one table and an outage on another, depending entirely on size, version, and what else depends on it. safe-migrate makes that visible before you deploy, not after.

---

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE).

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for full release history.
