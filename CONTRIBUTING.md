# Contributing to safe-migrate

Thanks for contributing. safe-migrate is a Rust PostgreSQL migration analyzer
with typed AST extraction, stateful schema simulation, and safety rules.

## Start here

- [Documentation index](docs/README.md)
- [Architecture and invariants](docs/internal/ARCHITECTURE.md)
- [AST development](docs/internal/AST_DEVELOPMENT.md)
- [CLI and report contract](docs/CONTRACT.md)

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
docs/           product contracts and maintainer documentation
```

Prefer this stable directory-level map over a copied inventory of every source
file or rule. Use `rg --files src tests live_tests` when you need the current
layout.

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

## Adding or changing a rule

1. Implement one safety concept under `src/rules/`.
2. Register the rule in the engine's canonical rule list.
3. Add configuration only when the rule needs a user-controlled policy.
4. Add focused regression tests.
5. Add or update end-to-end fixtures.
6. Update the canonical user-facing rule documentation.
7. Add a `CHANGELOG.md` entry for user-visible behavior.

Rules must:

- handle `MutationResult::Skipped` deliberately;
- distinguish conflicts from applied mutations;
- infer operation and object kinds from the mutation;
- avoid mutating analysis state;
- explain the mechanism and a safer next step;
- document PostgreSQL-version assumptions;
- avoid using row count for lock behavior unless table size actually changes
  the rule's conclusion.

## Extending AST extraction

Do not use an old AST reference or guess accessors from memory. Follow the
[source-first AST workflow](docs/internal/AST_DEVELOPMENT.md):

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

See [Architecture and invariants](docs/internal/ARCHITECTURE.md).

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

`safe_*.sql` fixtures are expected not to emit the target rule. Numbered
fixtures are expected to emit the target rule. A fixture count is not a
correctness claim by itself; prefer precise assertions in Rust tests for
object, tier, reason, and source behavior.

## Database synchronization

`safe-migrate sync`, and `lint` or `lint-chain` only when configured with
`auto_sync = true`, read `DATABASE_URL`. Do not commit credentials, connection
strings, or private database dumps. Use a least-privilege PostgreSQL role and
treat cache changes as reviewable schema-state changes.

The frozen cache under `live_tests/` belongs to the test corpus. Update it only
when a fixture requires a changed baseline, and explain the assumption in the
pull request.

## Code style

- Format with `rustfmt`.
- Treat Clippy warnings as errors.
- Use idiomatic Rust naming and four-space indentation.
- Keep one rule concept per file or focused module.
- Document non-obvious undo-log and dependency-graph behavior inline.

## Reporting bugs

Include:

- minimal SQL;
- expected and actual output;
- safe-migrate version;
- PostgreSQL version or assumed version;
- whether a cache was used;
- relevant configuration.

Classify the likely layer:

- AST extraction: add an exact visitor regression and inspect the pinned Squawk
  source.
- Resolution/state: test mutations, overlays, dependencies, and rollback.
- Rule: test false-positive/false-negative behavior and severity.
- CLI/report: test output channels, JSON, and exit status.

## Questions

Open an issue at <https://github.com/dsecurity49/safe-migrate> with a minimal
reproduction and the affected layer.
