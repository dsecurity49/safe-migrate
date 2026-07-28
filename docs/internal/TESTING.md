# Testing

Use the smallest test layer that proves the behavior, then run the broader
suite before merging user-visible changes.

## Standard checks

```bash
cargo fmt -- --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

Use focused tests while developing:

```bash
cargo test rule_evaluation
cargo test architectural_gap
cargo test expression_parsing
cargo test --test cli_tests
```

## Fixture suites

`live_tests/run.sh` checks SQL fixtures through the compiled CLI. Run one rule
directory while iterating, then the full suite before merge:

```bash
cd live_tests
./run.sh -d rule_25_schema-drift
./run.sh
```

From the repository root, the simulator-versus-PostgreSQL differential harness
needs a disposable local database exposed through `DATABASE_URL`:

```bash
DATABASE_URL='postgres://safe_migrate:safe_migrate@localhost:5432/safe_migrate' \
  scripts/live-differential
```

Use the script's selectors when diagnosing one case:

```bash
scripts/live-differential --rule rule_25_schema-drift
scripts/live-differential --fixture rule_25_schema-drift/001_drop_missing_table.sql
```

The harness resets only its `sm_*` schemas and named fixture objects, but it
still mutates the selected database. Never point it at a shared or production
database.

## What to assert

- AST work: exact facts and source distinctions.
- State work: apply, skip, conflict, rollback, rename, drop, and recreate
  effects as applicable.
- Rule work: rule ID, tier, object, reason, and recipe.
- CLI work: exit status plus exact stdout/stderr separation and JSON fields.
- Cache/sync work: preservation on failure, provenance/freshness, and
  encryption rejection paths.

Formatting and compilation are necessary checks; they are not proof that a new
behavior works. Add a regression that exercises the observed behavior.
