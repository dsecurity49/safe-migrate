# Contributing to safe-migrate

Thanks for contributing. safe-migrate is a Rust PostgreSQL migration analyzer
with typed AST extraction, stateful schema simulation, and safety rules.

## Start here

- [README and user guide](README.md)
- [GitHub Action guide](docs/GITHUB_ACTIONS.md)
- [CLI and report contract](docs/CONTRACT.md)
- [Live fixtures and sourced cases](live_tests/README.md)

## Project structure

```text
src/analysis/   facts, resolution, mutations, dependency graph, state, transactions
src/ast/        extraction from the pinned Squawk typed AST
src/db/         versioned database cache
src/engine/     configuration, orchestration, and rule dispatch
src/model/      modeled PostgreSQL objects
src/report/     human, JSON, and interactive reporting
src/rules/      safety rule implementations
tests/          integration, state-machine, rule, CLI, and regression tests
live_tests/     end-to-end SQL fixtures and frozen database cache
docs/           Action guide and CLI/report contract
```

`rg --files src tests live_tests` lists the current files.

## Development commands

Use locked dependencies:

```bash
cargo build --locked
cargo test --locked
cargo fmt -- --check
cargo clippy --all-targets --locked -- -D warnings
```

Focused examples:

```bash
cargo test rule_evaluation
cargo test architectural_gap
cargo test expression_parsing
```

End-to-end fixtures:

```bash
cd live_tests
./run.sh
./run.sh -d rule_25_schema-drift
```

The fixture runner invokes the compiled binary. Most rule directories lint each
file independently; chain-conflict fixtures use `lint-chain`.

Repository checks:

```bash
sh scripts/test-install-dry-run
sh scripts/test-action-contract
scripts/fuzz
```

The installer test covers pinned offline installation and checksum failures.
The Action test covers installation, cache handling, gates, summaries, and
annotations. The fuzz script generates SQL inputs and rejects crashes,
timeouts, operational errors, invalid JSON, and inconsistent exit statuses.

Live checks require a disposable local PostgreSQL database:

```bash
export DATABASE_URL='postgres://USER:PASSWORD@localhost:5432/safe_migrate'
scripts/live-differential
scripts/live-auto-sync
scripts/live-cache-encryption
```

The differential harness requires a local database named `safe_migrate` and
mutates and resets its test schemas and fixture objects. Never point it at a
shared or production database. CI runs the enabled differential manifest
against PostgreSQL 14 through 18; excluded fixtures and their reasons live in
`live_tests/differential_manifest.json`.

## Adding or changing a rule

1. Implement one safety concept under `src/rules/`.
2. Register the rule in the primary rule registry.
3. Add configuration only when the rule needs a user-controlled policy.
4. Add focused regression tests.
5. Add or update end-to-end fixtures.
6. Update the rule-registry metadata.
7. Add a `CHANGELOG.md` entry for user-visible behavior.

Rules must:

- define behavior for `MutationResult::Skipped`;
- distinguish conflicts from applied mutations;
- infer operation and object kinds from the mutation;
- avoid mutating analysis state;
- explain the mechanism and a safer next step;
- document PostgreSQL-version assumptions;
- avoid using row count for lock behavior unless table size actually changes
  the rule's conclusion.

## Extending AST extraction

Use the pinned Squawk source and grammar when changing AST extraction:

1. confirm the exact Squawk versions in `Cargo.toml` and `Cargo.lock`;
2. inspect the resolved dependency source and grammar;
3. add an exact fact assertion in `src/ast/visitor_tests.rs`;
4. implement extraction in `src/ast/visitor.rs` or expression conversion in
   `src/analysis/expr_visitor.rs`;
5. test resolver, state, and rule effects when behavior crosses layers;
6. represent unsupported parser behavior explicitly.

A Squawk version upgrade is an AST migration. Update all three pinned Squawk
crates together and validate the full extraction surface through compilation and
tests.

## State-machine changes

When adding modeled state:

1. define the state or overlay in the appropriate model module;
2. add explicit mutations and resolution;
3. preserve baseline-versus-local identity;
4. add transaction undo state for every mutable component;
5. test apply, skip, conflict, rollback, rename, drop, and recreate behavior;
6. update dependency edges and generation metadata where applicable.

## CLI and report changes

User-visible output is an interface. Changes to JSON fields, confidence meaning,
verdicts, exit statuses, output channels, or ordering must:

1. follow [the CLI and report contract](docs/CONTRACT.md);
2. include integration or golden tests;
3. preserve machine-only JSON standard output;
4. update `CHANGELOG.md`;
5. include a migration note when scripts may break.

## Testing expectations

Add regression coverage with every behavior change:

- AST changes: assert exact extracted facts.
- Resolver/state changes: assert the resulting state and undo behavior.
- Rule changes: assert rule ID, tier, object, reason, and relevant recipe.
- Reporter changes: assert structured output and deterministic ordering.
- CLI changes: assert standard output, standard error, and exit status.
- Database metadata changes: use existing cache and live-test helpers.

`safe_*.sql` fixtures must not emit the target rule. Numbered fixtures must emit
the target rule. Use Rust tests for exact object, tier, reason, and source
assertions. Fixture counts only check suite coverage.

## Database synchronization

`safe-migrate sync`, and `lint` or `lint-chain` only when configured with
`auto_sync = true`, read `DATABASE_URL`. Do not commit credentials, connection
strings, or private database dumps. Use a least-privilege PostgreSQL role and
treat cache changes as reviewable schema-state changes.

The frozen cache under `live_tests/` belongs to the test corpus. Update it only
when a fixture requires a changed baseline, and explain the assumption in the
pull request.

Cache V6 synchronizes every PostgreSQL routine kind, publications, and redacted
subscription metadata. Never query or store `pg_subscription.subconninfo`.
Changes to the cache model require serialization and inspection regressions,
an updated frozen cache, and live catalog coverage across supported PostgreSQL
versions.

## Code style

- Format with `rustfmt`.
- Treat Clippy warnings as errors.
- Use idiomatic Rust naming and four-space indentation.
- Keep one rule concept per file or focused module.
- Document non-obvious undo-log and dependency-graph behavior inline.

## Reporting bugs

[Open an issue](https://github.com/dsecurity49/safe-migrate/issues/new/choose)
with:

- minimal SQL;
- expected and actual output;
- safe-migrate version;
- PostgreSQL version or assumed version;
- whether a cache was used;
- relevant configuration.
