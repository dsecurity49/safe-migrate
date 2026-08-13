# Architecture and Invariants

This document records boundaries that contributors should preserve. Source code
and tests remain authoritative.

## Analysis pipeline

```text
SQL
  -> Squawk typed AST
  -> statement facts
  -> resolved mutations
  -> AnalysisState transitions
  -> rule evaluation
  -> human, JSON, Markdown, or interactive report
```

Database synchronization is separate:

```text
PostgreSQL catalogs and statistics
  -> versioned DbCache
  -> baseline AnalysisState
```

`sync` connects to PostgreSQL. `lint` and `lint-chain` ordinarily operate on
SQL plus a local cache or an empty conservative baseline; they connect only
when configuration explicitly enables `auto_sync = true` and `--no-cache` is
not supplied.

## Layer responsibilities

### AST extraction

`src/ast/` converts parser nodes into typed facts. It should preserve syntax
distinctions needed downstream but must not decide rule severity.

### Resolution and mutations

`src/analysis/resolver.rs` resolves names and search paths. Mutations describe
schema effects independently of a particular safety rule.

### State

`AnalysisState` combines a database baseline with local overlays. Statement
order matters. A mutation returns `Applied`, `Skipped`, or `Conflict`; callers
must not treat skipped or conflicting mutations as successful state changes.

Transactions record reversible state snapshots in an undo log. Every new state
component that can change in a transaction needs a corresponding undo entry and
rollback test.

Role-sensitive state keeps effective role, session authorization, authenticated
identity, persistent transaction settings, and the unexpanded search-path
template distinct. Do not collapse these fields: PostgreSQL changes and rolls
them back under different rules.

### Dependency graph

Graph edges represent safe-migrate-owned dependency semantics. Baseline edges
may come from cache data; local edges come from analyzed migrations. Generation
metadata prevents stale edges from applying to recreated objects.

### Rules

Rules evaluate mutations and their results. They should be deterministic,
side-effect free, and scoped to one safety concept. Rules must handle
`MutationResult::Skipped` and conflicts deliberately.

### Reporting

Reporting converts the shared finding model into terminal, JSON, Markdown, and
Action output. Human presentation may evolve independently, but JSON fields,
exit behavior, confidence meaning, and deterministic ordering follow [the
contract](../CONTRACT.md). Rule titles, summaries, and impact are resolved from
the canonical registry; stable rule IDs remain the configuration contract.

## Core invariants

- Dependency internals are verified from the pinned source, not copied docs.
- The visitor extracts facts; the resolver resolves names; state applies
  effects; rules assess safety.
- Linting is offline by default. Automatic synchronization is an explicit
  configuration opt-in, must run before analysis, and must preserve a readable
  previous cache when refresh fails.
- Ordered chain analysis reuses one state across files in deterministic
  filename order.
- Baseline state and migration-created state remain distinguishable.
- Transaction rollback restores every modeled mutable component.
- Role switches use synchronized `SET OPTION` edges; ordinary membership alone
  is not authorization on PostgreSQL 16 and newer.
- Unsupported or unresolved behavior lowers confidence or fails explicitly; it
  must not silently become a clean result.
- User-visible contracts are protected by integration or golden tests.

## Where to add tests

- AST shape and exact facts: `src/ast/visitor_tests.rs`
- Expression conversion: `tests/expression_parsing.rs`
- Resolution/state transitions: `tests/state_mutation.rs` and
  `tests/architectural_gaps.rs`
- Transactions and rollback: `tests/transaction_lifecycle.rs` and
  `tests/reversibility.rs`
- Rule behavior: focused files under `tests/`
- CLI/report contracts: `tests/cli_tests.rs` and reporter golden tests
- End-to-end rule behavior: `live_tests/`
