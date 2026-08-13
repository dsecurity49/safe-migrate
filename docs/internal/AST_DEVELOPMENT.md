# AST Development

This guide is for contributors changing extraction from Squawk's typed
PostgreSQL AST.

## Source of truth

Safe-migrate pins `squawk-syntax`, `squawk-parser`, and `squawk-lexer` exactly
in `Cargo.toml` (currently 2.62.0). Their pinned source and safe-migrate's tests are authoritative.
Do not rely on remembered accessor names or a hand-maintained AST catalog.

Confirm the resolved versions:

```bash
cargo tree --locked -p squawk-syntax --depth 0
cargo tree --locked -p squawk-parser --depth 0
cargo tree --locked -p squawk-lexer --depth 0
```

To locate the resolved manifest when `jq` is available:

```bash
cargo metadata --locked --format-version 1 \
  | jq -r '.packages[] | select(.name == "squawk-syntax") | .manifest_path'
```

Inspect the crate's generated nodes, handwritten node extensions, and grammar
directly. An accessor that existed in a previous Squawk version is not evidence
that it exists or has the same shape in the pinned version.

## Extraction workflow

1. Add the smallest SQL example to `src/ast/visitor_tests.rs`.
2. Inspect the pinned AST node and grammar for that statement.
3. Assert the exact facts safe-migrate needs, including identifiers, options,
   and source distinctions that affect resolution.
4. Implement extraction in `src/ast/visitor.rs` or expression conversion in
   `src/analysis/expr_visitor.rs`.
5. Add resolver/state/rule tests when the fact changes downstream behavior.
6. Add a regression fixture when the behavior is user-visible.

Parser gaps must be represented explicitly. Do not guess from raw SQL text
unless the fallback is intentional, tested, and documented as lower
confidence.

## Dependency upgrades

A Squawk upgrade is a parser migration, not a version-number edit.

1. Update all three exact dependency versions together.
2. Run `cargo check --locked` and classify compile failures by AST shape.
3. Update extraction and expression tests before broad mechanical fixes.
4. Run formatting, locked tests, Clippy, and the live fixture suite.
5. Add line-ending regressions when lexer behavior changes, and keep newly
   accepted but unmodeled PostgreSQL syntax explicitly opaque.
6. Record meaningful AST behavior changes and known limitations in
   `CHANGELOG.md`.

Do not recreate a full external AST reference under `docs/`. Project
documentation should capture only safe-migrate-owned invariants, intentional
fallbacks, and known unsupported behavior.
