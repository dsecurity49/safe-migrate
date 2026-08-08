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

## Repository script gates

Run the installer contract and generated migration corpus from the repository
root:

```bash
sh scripts/test-install-dry-run
sh scripts/test-action-contract
scripts/fuzz
```

The installer test proves a pinned dry run does not need network tooling or
write its requested destination. Its offline download mocks also require
missing, malformed, and mismatched checksums to fail closed while a valid
checksum installs successfully for `.tar.gz` and `.zip` archives. Action tests
cover local source installation, immutable reference validation, advisory and
blocking gates, operational errors, summaries, and annotations. The fuzz script generates at least 400 SQL
migrations, requires every accepted case to produce valid JSON with a matching
exit status, permits only its named parser rejection, and fails on operational
errors, crashes, or timeouts.

Before tagging a release, verify the exact crate users will install:

```bash
cargo package --locked --allow-dirty
cargo install --locked --path target/package/safe-migrate-<version> \
  --root <temporary-install-root>
<temporary-install-root>/bin/safe-migrate --version
```

`--allow-dirty` is appropriate only for testing an uncommitted release-prep
worktree. The tagged release commit itself must be clean.

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

The same disposable database is required by the dedicated automatic-sync and
encrypted-cache contracts:

```bash
DATABASE_URL='postgres://safe_migrate:safe_migrate@localhost:5432/safe_migrate' \
  scripts/live-auto-sync
DATABASE_URL='postgres://safe_migrate:safe_migrate@localhost:5432/safe_migrate' \
  scripts/live-cache-encryption
```

`scripts/live-auto-sync` exercises successful refresh, cache creation, and an
`Exact` available baseline for both `lint` and `lint-chain`.
`scripts/live-cache-encryption` exercises encrypted sync, inspect, `lint`,
configured automatic sync, and `lint-chain`, plus rejection when encryption is
disabled or the key is missing or incorrect.

Use the script's selectors when diagnosing one case:

```bash
scripts/live-differential --rule rule_25_schema-drift
scripts/live-differential --fixture rule_25_schema-drift/safe_002_create_table.sql
```

The harness resets only its `sm_*` schemas and named fixture objects, but it
still mutates the selected database. Never point it at a shared or production
database.

GitHub Actions runs the enabled manifest against PostgreSQL 14 through 18.
It uploads a verbose log for each version, including failed runs. Treat that
matrix as the supported live-differential scope; excluded fixtures remain
documented in `live_tests/differential_manifest.json` with their reasons.

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
