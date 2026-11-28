# Contributing to safe-migrate

Before opening an issue or pull request, search
[existing issues](https://github.com/dsecurity49/safe-migrate/issues). For bug
reports, include minimal SQL, expected vs. actual output, safe-migrate version,
PostgreSQL version (14–18), and whether a baseline cache was used (with
credentials removed).

## Architecture and module map

safe-migrate is a deterministic five-stage pipeline:

```text
SQL -> Squawk 2.72.0 AST (src/_internal/ast/visitor/)
    -> Typed StatementFacts (src/_internal/analysis/facts.rs)
    -> Namespace-resolved Mutations (src/_internal/analysis/resolver/)
    -> Transactional State & DependencyGraph (src/_internal/analysis/state/, src/_internal/model/)
    -> Safety Rules & Reporters (src/_internal/rules/, src/_internal/report/)
```

| Path | Responsibility |
| --- | --- |
| `src/_internal/ast/visitor/` | Extracts typed facts from pinned Squawk AST nodes (`tables.rs`, `alter_table.rs`, `views.rs`, `indexes.rs`, `routines.rs`, `types.rs`, `publications.rs`). |
| `src/_internal/analysis/expr_visitor.rs` | Converts Squawk `ast::Expr` nodes into `ExprIr` for column reference extraction, literal evaluation, and column-rename rewriting. |
| `src/_internal/analysis/resolver/` | Resolves `QualifiedName`s against the effective `search_path` (`pg_temp`, `pg_catalog`, user schemas) into canonical `ObjectId` mutations. |
| `src/_internal/analysis/state/` | Applies mutations to `AnalysisState` with statement/savepoint/transaction undo journals (`apply_relation/`, `apply_routine/`, `apply_type/`, `apply_view_index.rs`, `apply_extension.rs`, `apply_misc.rs`, `snapshots.rs`, `rollback.rs`). |
| `src/_internal/analysis/graph.rs` | Tracks typed `DependencyEdge`s (`ForeignKey`, `ViewDependency`, `ViewUsesRoutine`, `RoutineUsesRoutine`, `RoutineUsesRelation`, `IndexOnRelation`, `PartitionOf`, etc.) with incremental index lookups and delta rollback. |
| `src/_internal/db/cache/` | Versioned `SMCACHE12` cache (`DbCacheVersioned::V12` for `12.0`, `DbCacheVersioned::V12_1(Box<DbCache>, CacheExtensionV12_1)` for `12.1`) and semantic validator. |
| `src/_internal/sync/` | Read-only PostgreSQL 14–18 catalog loaders (`load_relations.rs`, `load_indexes.rs`, `load_constraints.rs`, `load_types.rs`, `load_routines.rs`, `load_dependencies.rs`). |
| `src/_internal/rules/` | Primary safety rules and lock-mode predictor (`lock_risk.rs`, `table_circulation.rs`, `destructive.rs`, `functions.rs`, `timeout_settings.rs`, etc.). |
| `src/api.rs`, `src/api/` | Public Rust library API (`Config`, `Baseline`, `Outcome`). |
| `tests/` | Unit, state-mutation (`tests/state_mutation/`), rule-evaluation (`tests/rule_evaluation/`), CLI, and live differential harnesses (`tests/live_differential_harness/`). |
| `live_tests/` | End-to-end SQL fixtures, `differential_baseline.sql`, `differential_manifest.json`, and the frozen V12.1 `.safe-migrate.cache`. |

## Build and test commands

Always use `--locked`:

```bash
cargo build --locked
cargo test --locked
cargo fmt -- --check
cargo clippy --all-targets --locked -- -D warnings
```

- Internal test modules under `tests/` are compiled into the library test target
  (`cargo test --locked --lib <filter>`), while the public API facade and
  grammar checks run via `cargo test --locked --test api_facade` and
  `cargo test --locked --test grammar_action_lists`.
- Run the offline fixture suite and contract checks:
  ```bash
  (cd live_tests && ./run.sh)
  sh scripts/test-action-contract
  sh scripts/test-install-dry-run
  scripts/fuzz
  ```

### Live PostgreSQL 14–18 differential verification

Live tests require a disposable local database named `safe_migrate` (never point
them at a shared or production database):

```bash
export DATABASE_URL='postgres://postgres@127.0.0.1:5432/safe_migrate'
scripts/live-differential -v
scripts/live-catalog-sync
scripts/live-catalog-differential
scripts/live-auto-sync
scripts/live-cache-encryption
```

### Regenerating `live_tests/.safe-migrate.cache`

When baseline fixtures or cache extensions change, rebuild the frozen V12.1
cache from a clean local PostgreSQL 18 `safe_migrate` database:

```bash
psql "$DATABASE_URL" -f live_tests/differential_baseline.sql
psql "$DATABASE_URL" -c "ANALYZE;"
cargo run --locked -- sync --out live_tests/.safe-migrate.cache
```

Running `ANALYZE;` before `sync` is required so `pg_class.reltuples` records
`0` (analyzed empty) rather than `-1` (unanalyzed unknown) on empty baseline
tables.

## Engineering standards

- **Verify against PostgreSQL and Squawk**: verify catalog and error semantics
  against PostgreSQL 14–18 (and PostgreSQL C source such as `tablecmds.c`,
  `functioncmds.c`, `statscmds.c`, `analyze.c`) and the pinned Squawk `2.72.0`
  grammar before coding.
- **State & undo completeness**: every mutable field on `AnalysisState` must be
  covered by statement undo and transaction/savepoint rollback, and tested for
  apply, no-op, conflict, rename, drop, cascade, and rollback.
- **Rules**: rules must be pure readers of `AnalysisState` and `PreState`,
  explicitly handling `MutationResult::Applied`, `NoOp`, `NotExecuted`, and
  `Unresolved`.
- **Module cohesion and size**: keep production modules under 2,000 lines and
  test modules under 2,500 lines by splitting distinct responsibilities into
  cohesive submodules (`apply_routine/aggregate.rs`, `apply_type/domain.rs`,
  `apply_relation/create_table/finish.rs`, `graph_tests.rs`,
  `tests/state_mutation/types_advanced.rs`). Keep inline comments concise (1–3
  lines) and only where the invariant is non-obvious.
- **Commits**: group each complete feature or fix with its tests into one atomic
  commit using a concise single-line imperative subject (`feat: ...`,
  `fix: ...`, `docs: ...`) and no commit body. Update `CHANGELOG.md` and
  `docs/CONTRACT.md` for user-visible changes.
