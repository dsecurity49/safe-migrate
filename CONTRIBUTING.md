# Contributing to safe-migrate

Thanks for your interest in contributing! This guide explains the project structure and how to add new rules or extend the AST extraction logic.

## Project Structure

```
safe-migrate/
├── src/
│   ├── analysis/                 # State machine simulator
│   │   ├── expr_ir.rs            # Expression intermediate representation
│   │   ├── expr_visitor.rs       # Expression AST visitor (squawk_syntax 2.58.0)
│   │   ├── facts.rs              # Fact extraction results
│   │   ├── graph.rs              # Dependency graphs (FK, indexes, partitions, views, triggers, publications)
│   │   ├── mutations.rs          # Mutation types and resolution
│   │   ├── resolver.rs           # Schema resolution with search_path
│   │   ├── state.rs              # AnalysisState, LocalState, mutation application, undo-log
│   │   ├── transaction.rs        # Transaction frame management, StateChange variants
│   │   └── mod.rs
│   │
│   ├── ast/                      # AST visitor pattern, extraction from squawk_syntax
│   │   ├── visitor.rs            # Fact extraction from typed AST nodes
│   │   ├── visitor_tests.rs      # AST extraction unit tests
│   │   ├── identifiers.rs        # ObjectId, Path resolution, schema walking
│   │   └── mod.rs
│   │
│   ├── engine/                   # Rule engine and configuration
│   │   ├── engine.rs             # Main analysis pipeline, rule dispatch, violation ordering
│   │   ├── config.rs             # safe-migrate.toml parsing
│   │   ├── tests.rs              # 235-test suite (architectural_gap, rule_evaluation, state_mutation, chain_execution, reversibility, etc.)
│   │   └── mod.rs
│   │
│   ├── model/                    # Data model for schema state
│   │   ├── relation.rs           # RelationState (tables/views/sequences/materialized views)
│   │   ├── column.rs             # Column metadata, width, nullability, default expression
│   │   ├── function.rs           # FunctionState, Volatility, SecurityMode
│   │   ├── role.rs               # RoleState, PrivilegeGrant
│   │   ├── trigger.rs            # TriggerState
│   │   ├── replication.rs        # PublicationState, SubscriptionState
│   │   ├── sequence.rs           # Sequence state, OWNED BY tracking
│   │   ├── types.rs              # Type definitions (enums, domains)
│   │   └── mod.rs
│   │
│   ├── rules/                    # Rule implementations (26 rule IDs)
│   │   ├── destructive.rs        # destructive-cascade, size-aware-add-column, type-change-rewrite, drop-database, create-table-as-select
│   │   ├── constraints.rs        # blocking-constraint, blocking-index-constraint
│   │   ├── indexes.rs            # require-concurrent-index, require-concurrent-drop-index
│   │   ├── views.rs              # blocking-mat-view-refresh
│   │   ├── partitions.rs         # partition-lock
│   │   ├── idempotency.rs        # missing-idempotency
│   │   ├── transactions.rs       # concurrent-in-transaction, vacuum-full
│   │   ├── opaque.rs             # opaque-dynamic-sql
│   │   ├── expressions.rs        # volatile-default
│   │   ├── functions.rs          # broken-compute, function-volatility-change, function-schema-change
│   │   ├── security.rs           # overbroad-grant
│   │   ├── policies.rs           # restrictive-policy
│   │   ├── triggers.rs           # disable-trigger
│   │   ├── drift.rs              # schema-drift, irreversible-migration
│   │   ├── conflict.rs           # chain-conflict (MutationResult::Conflict surfacing)
│   │   └── mod.rs                # Rule trait definition, module exports
│   │
│   ├── report/                   # Violation reporting
│   │   ├── violations.rs         # Violation struct, ViolationTier, OperationKind, ObjectKind, Verdict
│   │   ├── reporter.rs           # CLI output formatting (header box, per-finding blocks, summary box)
│   │   ├── reporter_tests.rs     # Reporter unit tests
│   │   └── mod.rs
│   │
│   ├── db/                       # Database integration
│   │   ├── cache.rs              # DbCache serialization, ForeignKeyCache, IndexCache
│   │   └── mod.rs
│   │
│   ├── sync.rs                   # Database stats sync (6 queries to pg_class, pg_attribute, pg_stat_user_tables, etc.)
│   ├── sync_tests.rs             # Sync and cache unit tests
│   ├── lib.rs                    # Library root, public API exports
│   └── main.rs                   # CLI entry point (lint, lint-chain, sync subcommands)
│
├── tests/
│   └── cli_tests.rs              # Integration tests for CLI exit codes and flags
│
├── docs/
│   └── ast-reference/            # 22 PostgreSQL AST reference documents + index
│       ├── README.md             # Index, guide, and navigation
│       ├── columns.md            # Column lifecycle, TableArg dispatch
│       ├── constraints.md        # FK, CHECK, UNIQUE, PK, exclusion
│       ├── indexes.md            # Index creation/drop/alter, PartitionItem limitations
│       ├── partitions.md         # Partition hierarchies, reverse-graph walk
│       ├── sequences.md          # SequenceOption polymorphic dispatch, OWNED BY
│       ├── schemas.md            # Schema creation, NameRef.text() normalization
│       ├── views.md              # View/MV creation, DropView accessor
│       ├── materialized_views.md # Reference to views.md with storage emphasis
│       ├── functions.md          # Function creation, volatility detection
│       ├── triggers.md           # Trigger creation, event detection
│       ├── transactions.md       # BEGIN/COMMIT/ROLLBACK polymorphic forms, savepoints
│       ├── search_path.md        # Set node dispatch, schema resolution
│       ├── database.md           # CREATE/ALTER/DROP DATABASE
│       ├── roles.md              # Role/User/Group aliases, privilege management
│       ├── grant_revoke.md       # Grant/Revoke, PrivilegeTarget enum
│       ├── enums.md              # CreateType polymorphic forms (enum/range/composite/shell)
│       ├── domains.md            # CreateDomain, AlterDomainAction
│       ├── policies.md           # RLS policy creation, two-layer model
│       ├── publications.md       # Logical replication publication
│       ├── subscriptions.md      # Logical replication subscription
│       ├── security_model.md     # Two-axis risk model (structural vs access-control)
│       └── non_schema_effects.md # [SYNTHESIS] Session context, replication, config side effects
│
├── .github/workflows/
│   ├── ci.yml                    # Test on push/PR, cargo fmt/clippy checks
│   └── release.yml               # Build & release multi-platform binaries on tag
│
├── Cargo.toml                    # v0.4.0, squawk-syntax = "=2.58.0"
├── Cargo.lock
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── install.sh
├── LICENSE-MIT
├── LICENSE-APACHE
└── .gitignore
```

## Verifying against squawk_syntax source

`docs/ast-reference/` is verified directly against the actual squawk source in Cargo's registry cache — no intermediate dump file is kept or committed. To locate the source for a given version:

```bash
find ~/.cargo/registry/src -type d -name "squawk-syntax-2.58.0"
find ~/.cargo/registry/src -type d -name "squawk-lexer-2.58.0"
find ~/.cargo/registry/src -type d -name "squawk-parser-2.58.0"
```

Read the `.rs` files in those directories directly when verifying or updating an AST reference doc. Do not guess accessor names from memory — confirm against the actual source before documenting or relying on a method signature.

## Adding a New Rule

1. **Create the rule struct and impl Rule**

   ```rust
   pub struct MyNewRule;
   
   impl Rule for MyNewRule {
       fn id(&self) -> &'static str { "my-rule-id" }
       fn default_tier(&self) -> ViolationTier { ViolationTier::Tier2 }
       fn recipe(&self) -> &'static str { "How to fix this violation." }
       
       fn evaluate(
           &self,
           mutation: &Mutation,
           result: &MutationResult,
           pre_relations: &HashMap<ObjectId, RelationState>,
           state: &AnalysisState,
           config: &Config,
           cascade_closure: Option<&CascadeResult>,
       ) -> Vec<Violation> {
           // Always guard on Skipped first — every rule must do this
           if *result == MutationResult::Skipped {
               return vec![];
           }

           // Match on mutation type and create violations.
           // operation_kind and object_kind should be inferred from the
           // Mutation variant, not left as a default/unknown value.
           vec![]
       }
   }
   ```

2. **Register the rule in `src/engine/engine.rs`**

   ```rust
   pub fn new(config: Config) -> Self {
       Self {
           config,
           rules: vec![
               // ... existing rules ...
               Box::new(MyNewRule),
           ],
       }
   }
   ```

3. **Add configuration support (optional)**

   In `src/engine/config.rs`, add a field if your rule needs thresholds or toggles:

   ```toml
   [rules.my-rule-id]
   disabled = false
   my_threshold = 1000
   ```

4. **Write tests**

   Add tests to `src/engine/tests.rs` covering:
   - The rule fires on the mutation it's designed for
   - The rule does NOT fire when `MutationResult::Skipped` (e.g. `IF NOT EXISTS`/`IF EXISTS` on an object that already existed/didn't exist)
   - The rule respects configuration overrides
   - Edge cases specific to the rule (empty tables for row-count-gated rules, only if the rule actually uses row counts — a lock-behavior-only rule like index concurrency should not reference row counts or staleness at all)

## Extending AST Extraction

If you need to extract information from a new DDL statement:

1. **Check the AST reference docs first** — `docs/ast-reference/README.md` has an index of all 22 documents.

2. **Find your statement in the appropriate document**
   - Example: Adding FK constraint extraction? See `docs/ast-reference/constraints.md`
   - Need partition handling? See `docs/ast-reference/partitions.md`

3. **Review the accessor methods** in that document
   - Check if the data you need is extractable or if there's a grammar gap
   - Look for handwritten extensions that might help
   - Note any polymorphic nodes that need token dispatch

4. **Implement the extraction in `src/ast/visitor.rs`**

   ```rust
   fn extract_create_table(node: &CreateTable) -> Option<Fact> {
       let name = node.name()?.text();
       // ... use accessor methods documented in columns.md, constraints.md, etc.
   }
   ```

5. **Check against grammar limitations**
   - If you hit a limitation listed in `docs/ast-reference/`, add a test that documents it
   - Update the limitation in the appropriate AST doc if you work around it

## Running Tests

```bash
cargo test                      # Full test suite (235 tests)
cargo test rule_evaluation      # Just rule tests
cargo test architectural_gap    # Just simulator/state machine tests
cargo test chain_execution      # Just multi-file chain tests
cargo test reversibility        # Just reversibility classification tests
cargo test --doc               # Doc tests (if any)
```

For integration testing:

```bash
cargo run -- lint --file test.sql --no-cache       # Offline mode
export DATABASE_URL="postgres://..."
cargo run -- sync                                   # Create cache
cargo run -- lint --file test.sql                  # With cache
```

## Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy -- -D warnings` to catch lints
- Keep rule implementations self-contained (one rule per concept)
- Document non-obvious state machine logic inline

## Reporting Bugs

Found a bug in the simulator or a rule? Check if it's:

1. **AST extraction issue** — The parser isn't giving us the right data → check `docs/ast-reference/` for grammar gaps, update the doc, add a test
2. **State machine issue** — Mutations aren't applied correctly → check `src/analysis/state.rs`, ensure undo-log captures the right state changes
3. **Rule issue** — False positive or false negative → check the rule's logic, check thresholds in `src/engine/config.rs`

Include:
- Minimal SQL that reproduces the issue
- Expected vs actual output
- Your PG version (or use `assume_pg_version` in test)

## Versioning & Releases

safe-migrate uses semantic versioning:
- **Major:** API/rule changes, SQL parsing overhauls
- **Minor:** New rules, new config options, internal improvements
- **Patch:** Bug fixes

Before releasing:
1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Run full test suite: `cargo test`
4. Tag with `git tag vX.Y.Z` and push
5. GitHub Actions will build and release binaries automatically

## Questions?

Open an issue on [GitHub](https://github.com/dsecurity49/safe-migrate) or check the AST reference docs for extraction-related questions.

