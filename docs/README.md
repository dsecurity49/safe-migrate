# Documentation

The repository keeps two kinds of documentation:

## Product contracts

- [CLI and report contract](CONTRACT.md) — user-visible behavior that must be
  protected by tests.
- The root [README](../README.md) — installation, quick start, rules, and
  product-level guidance.

## Maintainer documentation

- [Architecture and invariants](internal/ARCHITECTURE.md) — boundaries between
  parsing, resolution, state mutation, rules, reporting, and database sync.
- [AST development](internal/AST_DEVELOPMENT.md) — the source-first workflow for
  working with the pinned Squawk parser.
- [Contributing](../CONTRIBUTING.md) — development workflow and test commands.

## Documentation policy

Documentation in this directory must describe behavior owned by safe-migrate.
Do not duplicate generated accessor catalogs or other internal documentation
from dependencies. The pinned dependency source and executable tests are the
authority for dependency behavior.

User-visible contracts must be backed by tests. Maintainer documentation should
record architectural decisions and invariants that are difficult to infer from
one source file. Implementation details that change mechanically with a
dependency upgrade belong in code, tests, or the dependency source—not in a
hand-maintained reference manual.
