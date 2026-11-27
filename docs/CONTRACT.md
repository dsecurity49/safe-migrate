# CLI and Report Contract

This document is the technical specification for safe-migrate v0.14.0's CLI,
exit codes, JSON schemas, Cache V12 (`12.0` / `12.1`) format, precision
boundaries, and GitHub Action guarantees.

## 1. CLI commands and flags

| Command | Specification |
| --- | --- |
| `lint --file <path>` | Analyze a single `.sql` migration file. |
| `lint-chain --dir <path>` | Analyze all `.sql` files in `<path>` in lexicographical filename order, carrying simulated schema state across files. |
| `sync` | Query PostgreSQL catalogs in a `READ ONLY, ISOLATION LEVEL REPEATABLE READ` transaction and atomically write the cache (`--out <path>`, default `.safe-migrate.cache`; `--schemas a,b` scopes user schemas). Requires `DATABASE_URL` pointing to `localhost`, `127.0.0.1`, `::1`, or a Unix socket. |
| `cache inspect` | Read cache provenance, PostgreSQL version, observed timeouts, and object counts offline (`--cache <path>`, `--json`). Never prints object, role, column, or dependency names. |
| `rules` | List primary rules (`--rule <id>` for a single rule, `--json` for schema v3 descriptors). |
| `init github-actions --path <dir>` | Write `.github/workflows/safe-migrate-baseline.yml` and `.github/workflows/safe-migrate.yml` atomically (`--branch <name>` overrides `origin/HEAD`; `--configure-secrets` verifies `gh auth status` and uploads secrets). |
| `init cache-key` | Generate 32 random bytes as 64 lowercase hex characters (`--set-github-secret` pipes directly to `gh secret set SAFE_MIGRATE_CACHE_KEY`). |

- **Configuration**: loads `safe-migrate.toml` from the working directory if
  present, or `--config <path>` (which must exist). Unknown keys or rule IDs
  exit `1`.
- **Auto-sync**: when `auto_sync = true` in TOML, `lint` and `lint-chain`
  attempt an in-place refresh before analysis unless `--no-auto-sync` or
  `--no-cache` is passed. If refresh fails, a readable V12 cache is reused with
  `auto_sync: "failed"`; otherwise analysis degrades to no baseline (`Tainted`).

## 2. Output modes and exit codes

| Flag | stdout | stderr |
| --- | --- | --- |
| Default (human) | Formatted terminal report | Warnings and operational errors |
| `--json` | Single JSON document (no ANSI escapes or preamble) | Warnings and operational errors |
| `--markdown` | Deterministic Markdown report | Warnings and operational errors |
| `--report-dir <dir>` | Empty (writes `safe-migrate-report.json` and `safe-migrate-report.md` in one pass) | Warnings and operational errors |

Output mode flags (`--json`, `--markdown`, `--interactive`, `--report-dir`) are
mutually exclusive; combining them exits `2`.

| Verdict | Condition |
| --- | --- |
| `HALT` | At least one `Tier1` finding. |
| `CAUTIOUS` | No `Tier1` finding, and at least one `Tier2` finding or unevaluated `Tier1`-capable check (`not_evaluated`). |
| `SAFE WITH RISK` | An `irreversible-migration` `Tier3` finding, with no `Tier1`/`Tier2` findings and no unevaluated `Tier1` check. |
| `SAFE` | No higher verdict applies. |

| Exit code | Condition |
| --- | --- |
| `0` | Analysis completed with verdict `SAFE`, `SAFE WITH RISK`, or `CAUTIOUS`. |
| `1` | Operational failure: SQL syntax error, I/O failure, invalid TOML, corrupt/unsupported cache, or missing encryption key. |
| `2` | Analysis completed with verdict `HALT` (`Tier1` finding), or invalid CLI arguments. |

## 3. JSON schemas (Version 3)

### Lint report (`lint --json`, `lint-chain --json`)

```json
{
  "schema_version": 3,
  "confidence": "Exact",
  "verdict": "SAFE",
  "summary": { "total": 0, "tier1": 0, "tier2": 0, "tier3": 0 },
  "evidence": [
    {
      "code": "unknown_object_state",
      "scope": "chain",
      "summary": "Referenced object could not be resolved from the baseline.",
      "file": "migrations/002.sql",
      "statement_index": 1
    }
  ],
  "not_evaluated": [
    {
      "rule_id": "size-aware-add-column",
      "tier": "Tier1",
      "cause": "missing_table_statistics",
      "sql": "ALTER TABLE items ADD COLUMN c text;",
      "recipe": "Run `safe-migrate sync` after `ANALYZE` so row statistics are available.",
      "missing_schemas": []
    }
  ],
  "rules": {
    "require-concurrent-index": "Require concurrent index",
    "size-aware-add-column": "Size-aware add column"
  },
  "baseline": {
    "status": "available",
    "created_at_unix_secs": 1732600000,
    "source_database": "app",
    "schemas": ["public"],
    "auto_sync": "not_requested",
    "observed_settings": {
      "lock_timeout_ms": 5000,
      "statement_timeout_ms": 900000
    }
  },
  "violations": [
    {
      "rule_id": "require-concurrent-index",
      "object_kind": "Index",
      "object_name": "public.items_idx",
      "tier": "Tier1",
      "reason": "CREATE INDEX on table 'public.items' blocks writes.",
      "recipe": "Use CREATE INDEX CONCURRENTLY outside a transaction.",
      "sql": "CREATE INDEX items_idx ON items (id);",
      "statement_index": 2,
      "location": { "file": "migrations/001.sql", "line": 4, "column": 1 }
    }
  ]
}
```

- `violations[*].certainty` is omitted when `"Exact"` and present otherwise.
- `rules` maps every `rule_id` referenced in `violations` or `not_evaluated`
  (including auxiliary IDs such as `inline-suppression-disabled` and
  `blocking-index-constraint`) to its human title.
- Disabled rules and rules suppressed by `-- safe-migrate: ignore(<id>)` (when
  `allow_inline_suppressions = true`) are omitted from both `violations` and
  `not_evaluated`.
- `baseline.status` is `"available"`, `"stale"` (missing/future timestamp or
  age exceeding `stale_stats_days`), or `"unavailable"`.
  `baseline.auto_sync` is `"not_requested"`, `"refreshed"`, `"failed"`, or
  `"bypassed"`.

### Rule catalog (`rules --json`)

Independent `schema_version: 3` document listing every configurable primary
rule's `id`, `title`, `tier`, `summary`, `recipe`, and `settings` (supported
TOML keys and effective values).

## 4. Cache V12 (`12.0` / `12.1`) architecture and encryption

### Wire layout

1. **Optional encryption envelope (`SMENC001`)**: when `cache_encryption = true`,
   the file begins with the 8-byte magic `SMENC001`, a 24-byte random
   `XChaCha20-Poly1305` nonce, and the authenticated ciphertext of the zstd
   payload encrypted under the 32-byte `SAFE_MIGRATE_CACHE_KEY`. Plaintext and
   encrypted modes never mix.
2. **Zstd frame (bounded to 256 MiB decompressed)**:
   - **9-byte major magic**: `SMCACHE12` (`CACHE_FORMAT_VERSION = 12`).
   - **Bincode payload (`DbCacheVersioned`)**: variable-int encoded enum:
     - `DbCacheVersioned::V12(Box<DbCache>)` (**Cache V12.0**, discriminant 11):
       base `DbCache` layout.
     - `DbCacheVersioned::V12_1(Box<DbCache>, CacheExtensionV12_1)` (**Cache
       V12.1**, discriminant 12): unchanged `Box<DbCache>` plus typed minor
       extensions (`CacheExtensionV12_1 { casts: Vec<CastEntry>, routine_dependencies: Vec<RoutineDependencyCache> }`).
     - `V1`–`V11` and trailing bytes are rejected before semantic validation.
       `sync` writes `V12_1`, while the reader accepts both `V12.0` and `V12.1`
       under major version `12`.

### Synchronized catalog evidence

- **Cluster & session**: `server_version_num` (140000–189999), `current_database()`,
  `current_user`, `session_user`, bootstrap superuser, raw and resolved
  `search_path`, all existing schema names, `lock_timeout`, and
  `statement_timeout`.
- **Namespaces, roles & privileges**: schemas, roles, multi-grantor role
  memberships (`ADMIN`, `INHERIT`, `SET` options), and per-grantor table ACLs.
- **Relations & columns**: tables, partitioned tables, views, materialized views
  (including `relispopulated`), foreign tables, `relpersistence`, `reltuples`,
  `of_type`, column types/typmods/collations/defaults/storage/compression,
  identity and generated (`STORED`/`VIRTUAL`) columns, column inheritance
  counts, triggers, RLS flags/policies, rewrite rules, and extended statistics
  (`pg_statistic_ext` kinds, column keys, expressions, and targets).
- **Constraints, indexes & topology**: primary/unique/exclusion/check/not-null
  constraints, foreign keys with catalog equality-operator evidence, btree/hash/
  gin/gist/brin indexes (key/included columns, opclasses, collations, parsed
  key expressions and predicates, `indisvalid`/`indisready`/`indislive`),
  table/index inheritance and partition trees (including interrupted detach
  state), view-to-relation/column/routine/type dependencies, and cross-schema
  boundary dependency edges.
- **Types, routines, sequences, extensions & replication**: built-in types,
  opclasses, collations, aggregate signatures, user composite/enum/range/
  multirange/domain/base types, all routine kinds (`f`, `p`, `a`, `w`) with
  parameter modes/names/defaults and internal type ownership, sequences (bounds
  and standby-aware runtime state), extensions and owned members, publications,
  redacted subscriptions (`subconninfo` is never read), and—in `V12.1`—all
  built-in and user-defined casts (`IMPLICIT`, `AS ASSIGNMENT`, `EXPLICIT`,
  coercion method, and `castfunc` routine dependencies).

## 5. Confidence and precision boundaries

| Subsystem | Exact behavior | Tainted (`Confidence::Tainted`) boundary |
| --- | --- | --- |
| DDL & expressions | Modeled DDL and PostgreSQL catalog conflicts (`chain-conflict`, leaving state unchanged). | Parser-valid clauses outside the fact model, CTAS query projections, or unparseable catalog expressions. |
| Partitions | Multi-column `RANGE` (`MINVALUE`/`MAXVALUE`), `LIST` (`NULL`), boolean, varchar, and `DEFAULT` partition check synthesis. | Expression partition keys or missing ancestor partition bounds. |
| Indexes & views | Catalog-synced index/view column and object dependencies; simple local column projections. | Complex local index expressions/predicates or unresolvable overloaded routine references in local view bodies. |
| Routines & aggregates | Signature resolution, `CREATE OR REPLACE` return/OUT/default-count checks, `COST`/`ROWS`/`PARALLEL`/`SUPPORT` validation, SQL-standard `BEGIN ATOMIC` and `RETURN` body dependencies, and single-overload aggregate support function dependencies. | Opaque string bodies (`AS '...'`), retained parameter default type comparisons, and overloaded multi-arg aggregate support function resolution. |
| Casts (`V12.0` vs `V12.1`) | `CREATE CAST` / `DROP CAST` across all contexts, `WITH FUNCTION` 1–3 arg signature and binary-coercibility checks, `WITHOUT FUNCTION` physical layout checks, pseudo-type rejection, and `castfunc` / type drop dependencies. | `DROP CAST` (without `IF EXISTS`) on an unrecorded cast when loaded from a legacy `V12.0` cache (which only synced `pg_catalog` implicit casts). Refreshing to `V12.1` makes it exact. |
| Grants, roles & replication | Table/schema/type/routine grants, `SET ROLE` membership walks, publication table membership, and disconnected subscriptions. | `GRANT ... ON ALL TABLES IN SCHEMA`, policy USING/WITH CHECK expression rewrites, publication edits on partitioned tables without `ONLY`, and connected subscription DDL. |
| Timeouts | `require-lock-timeout` and `require-statement-timeout` track session, `SET LOCAL`, `RESET`, `RESET ALL`, `SET ... FROM CURRENT`, savepoint, and transaction lifecycles. | Unknown baseline timeouts when running with `--no-cache`. |
