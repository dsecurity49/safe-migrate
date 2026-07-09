# Search Path AST Reference for safe-migrate

## Status

Verified against squawk_syntax 2.58.0 — July 2026

---

## Documentation Contract

1. Only document AST behavior that has been directly verified.
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. Assume additional nodes or helpers may exist outside the inspected surface.

---

## Architectural Context

From the blueprint, rule 14 (SEARCH PATH RULE — CRITICAL):

```
SET search_path → modifies LocalState
Resolver always expands: Path(None, "users") → ObjectId(public.users)
```

This document establishes the AST extraction surface that feeds this resolver rule.
`search_path` is the single most safety-critical configuration parameter in the
simulator because it determines how every unqualified `Path(None, name)` in
subsequent statements resolves to an `ObjectId`.

---

## Handwritten Extension Policy

No handwritten extensions exist for the `Set` node or `ConfigValue` enum.

Verified by exhaustive grep documented in `columns.md`.

---

# Critical Finding: No Dedicated search_path Node

```bash
grep -n "search_path\|SearchPath" src/ast/generated/nodes.rs src/ast/node_ext.rs
# no results
```

PostgreSQL's `SET search_path = ...` is **not** a distinct grammar construct in
this AST. It is parsed as a generic `Set` statement where the configuration
parameter name happens to be the identifier `search_path`.

**This means:** the AST Visitor cannot detect a search_path change by node type.
It must extract the generic `Set` statement, resolve `path()` to a string, and
compare it against the literal `"search_path"` (case-insensitive, per PostgreSQL
identifier folding rules — see schemas.md for identifier normalization).

This is an architecturally significant finding: search_path detection is a
**string comparison after generic SET extraction**, not a type-based dispatch.

---

# Generic SET Statement

## Set

### Verified Accessors (src/ast/generated/nodes.rs line 18605)

```rust
pub fn config_value(&self) -> Option<ConfigValue>
pub fn config_values(&self) -> AstChildren<ConfigValue>
pub fn literal(&self) -> Option<Literal>
pub fn path(&self) -> Option<Path>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn eq_token(&self) -> Option<SyntaxToken>
pub fn catalog_token(&self) -> Option<SyntaxToken>
pub fn content_token(&self) -> Option<SyntaxToken>
pub fn current_token(&self) -> Option<SyntaxToken>
pub fn default_token(&self) -> Option<SyntaxToken>
pub fn document_token(&self) -> Option<SyntaxToken>
pub fn from_token(&self) -> Option<SyntaxToken>
pub fn local_token(&self) -> Option<SyntaxToken>
pub fn option_token(&self) -> Option<SyntaxToken>
pub fn schema_token(&self) -> Option<SyntaxToken>
pub fn session_token(&self) -> Option<SyntaxToken>
pub fn set_token(&self) -> Option<SyntaxToken>
pub fn time_token(&self) -> Option<SyntaxToken>
pub fn to_token(&self) -> Option<SyntaxToken>
pub fn xml_token(&self) -> Option<SyntaxToken>
pub fn zone_token(&self) -> Option<SyntaxToken>
```

### Meaning

`Set` is a single polymorphic node covering many distinct PostgreSQL `SET` forms:

```sql
SET search_path = a, b, c
SET search_path TO a, b, c
SET LOCAL search_path = a
SET SESSION search_path = a
SET TIME ZONE 'value'
SET client_encoding = 'UTF8'
SET DEFAULT
SET CATALOG ...
SET XML OPTION DOCUMENT
```

This mirrors the `SequenceOption` and `Rollback` polymorphic pattern documented
in sequences.md and transactions.md.

### Key Accessor Notes

**Parameter name:** `path()` → `Path` → resolves to the config parameter identifier
(e.g. `search_path`, `client_encoding`, `statement_timeout`).

**Value form 1 (single):** `config_value()` → `ConfigValue` (single).

**Value form 2 (multiple, comma-separated):** `config_values()` → `AstChildren<ConfigValue>`.
`search_path = a, b, c` uses this multi-value form.

**LOCAL vs SESSION scope:**
- `local_token().is_some()` → `SET LOCAL` — scoped to current transaction only,
  reverts at transaction end (commit or rollback)
- `session_token().is_some()` → `SET SESSION` — persists for the session
- Neither present → defaults to session scope (per PostgreSQL semantics, not AST-derivable)

**DEFAULT detection:** `default_token().is_some()` → `SET param TO DEFAULT`
(resets to the parameter's default value).

**FROM CURRENT detection:** `from_token().is_some()` + `current_token().is_some()`
→ `SET param FROM CURRENT` (sets session value to current transaction's local value).
This form was confirmed via postgresql.ungram and was not initially identified
from accessor inspection alone — the token pair must be checked together since
both tokens have other uses on this polymorphic node (e.g. `from_token()` is
unrelated to `FROM CURRENT` in other `Set` forms).

### ConfigValue Enum (src/ast/generated/nodes.rs line 21979)

```rust
pub enum ConfigValue {
    Literal(Literal),
    NameRef(NameRef),
}
```

2 members. A config value is either a literal (string/number) or a bare identifier.
For `search_path = public, app, "$user"`, each comma-separated entry is a
`ConfigValue::NameRef` or `ConfigValue::Literal` depending on whether it was
quoted in the source SQL.

### safe-migrate guidance

```rust
struct SetConfigFact {
    parameter_name: String,          // resolved from path()
    values: Vec<ConfigValueFact>,    // from config_value() or config_values()
    scope: SetScope,                 // Local | Session
    is_default: bool,                // from default_token()
}

enum ConfigValueFact {
    Literal(String),
    Identifier(String),
}

enum SetScope {
    Local,
    Session,
}
```

**Detection logic for search_path specifically:**

```rust
fn is_search_path_set(fact: &SetConfigFact) -> bool {
    fact.parameter_name.eq_ignore_ascii_case("search_path")
}
```

---

# RESET Counterpart

## Reset

### Verified Accessors (src/ast/generated/nodes.rs line 17213)

```rust
pub fn path(&self) -> Option<Path>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn all_token(&self) -> Option<SyntaxToken>
pub fn authorization_token(&self) -> Option<SyntaxToken>
pub fn isolation_token(&self) -> Option<SyntaxToken>
pub fn level_token(&self) -> Option<SyntaxToken>
pub fn reset_token(&self) -> Option<SyntaxToken>
pub fn session_token(&self) -> Option<SyntaxToken>
pub fn time_token(&self) -> Option<SyntaxToken>
pub fn transaction_token(&self) -> Option<SyntaxToken>
pub fn zone_token(&self) -> Option<SyntaxToken>
```

### Meaning

```sql
RESET search_path
RESET ALL
```

`all_token().is_some()` → resets every session parameter to its default,
including `search_path`. This must be treated identically to an explicit
`SET search_path TO DEFAULT` for simulator purposes.

`path()` gives the specific parameter name when `ALL` is not used.

### safe-migrate guidance

```rust
struct ResetConfigFact {
    parameter_name: Option<String>,   // None when ALL
    reset_all: bool,
}
```

**Critical for the simulator:** `RESET ALL` is a wide blast radius — it silently
resets `search_path` to its default even when the migration never mentions
`search_path` by name. The resolver must treat `reset_all: true` as an implicit
search_path reset.

---

## ResetConfigParam

### Verified Accessors (src/ast/generated/nodes.rs line 17264)

```rust
pub fn path(&self) -> Option<Path>
pub fn all_token(&self) -> Option<SyntaxToken>
pub fn reset_token(&self) -> Option<SyntaxToken>
```

### Membership

Used within `AlterDatabase`, `AlterRole`, and similar contexts for
`ALTER ROLE/DATABASE ... RESET param` forms — distinct from the standalone
`Reset` statement.

### Important Distinction

In 2.58.0, both `ResetConfigParam` and `Reset` use `path()` (a `Path` node), resolving to a parameter name string through the same accessor type. This simplifies the resolver's extraction paths.

### safe-migrate guidance

If a migration contains `ALTER ROLE myrole RESET search_path` or
`ALTER DATABASE mydb RESET search_path`, this affects the **default**
search_path for future sessions under that role/database, not the
current session's simulated search_path. This should likely be tracked
separately from `LocalState.search_path` — it does not affect resolution
of subsequent statements within the same migration file.

---

# Verified Findings Summary

## Confirmed Complete

- `Set`: fully resolved — polymorphic node requiring string-based parameter
  name comparison to detect search_path specifically
- `ConfigValue` enum: both members verified
- `Reset`: fully resolved
- `ResetConfigParam`: fully resolved

## Architectural Findings

1. **No dedicated search_path node exists.** Detection requires extracting every
   `Set` statement, resolving `path()` to text, and string-comparing against
   `"search_path"`.
2. **`RESET ALL` implicitly resets search_path** — must not be missed by a
   detector that only looks for explicit `search_path` mentions.
3. **`ALTER ROLE/DATABASE ... RESET search_path`** uses a different accessor
   path (`ResetConfigParam.path()`) and affects future sessions, not the
   current simulation — these are semantically distinct from session-scoped
   `RESET search_path`.
4. **`SET LOCAL search_path`** reverts at transaction boundary — the resolver
   must track scope (`Local` vs `Session`) and tie `Local` search_path changes
   to the current `TransactionFrame`'s undo log (see transactions.md).

## Confirmed Partial

None — this surface is fully resolved given that no dedicated node exists to
leave unresolved.

## Grammar Cross-Check

This document has been cross-checked against postgresql.ungram. The `Set` grammar
rule confirms:

```
Set =
  'set'
  ('session' | 'local')?
  ( 'xml' 'option' ('document' | 'content')
  | 'time' 'zone' (ConfigValue | 'default' | 'local')?
  | ('catalog' | 'schema') Literal
  | Path (
      'from' 'current'
    | (('to' | '=') (ConfigValue* | 'default') )
    )
  ) ';'?
```

This confirms `search_path` flows through the `Path ( ... )` branch, and that
the FROM CURRENT form discovered during this cross-check is real and correctly
documented above. `TIME ZONE`, `XML OPTION`, and `CATALOG`/`SCHEMA` are confirmed
as separate branches that never carry `search_path` — the resolver can skip
these branches entirely when searching for search_path changes.

---

# Remaining Open Questions

None remaining. Both previously open questions have been resolved:

1. **Identifier-folding rules for `"search_path"` comparison**: Fully
   resolved in schemas.md (cross-reference). The complete verified
   implementation is `normalize_name_node()` in src/ast/node_ext.rs (line 452) —
   unquoted identifiers are lowercased via `to_ascii_lowercase()`, quoted
   identifiers preserve case. Since `search_path` (lowercase, unquoted) is
   the canonical PostgreSQL parameter name, any `path()` value that
   normalizes to `"search_path"` (i.e. unquoted `SEARCH_PATH`, `search_path`,
   `Search_Path` all fold correctly; quoted `"search_path"` matches; quoted
   `"SEARCH_PATH"` does NOT match) identifies a search_path mutation. The
   resolver must call `path().segment()` then `.name_ref().text()` (using
   the handwritten extension, not raw `ident_token()`) when building the
   comparison string.

2. **`SET search_path` inside a function body**: Fully resolved via grammar
   cross-check in this pass. A `CREATE FUNCTION ... SET search_path = ...`
   (a function-level configuration parameter) uses `SetFuncOption` as the
   relevant `FuncOption` variant, per the grammar:

   ```
   SetFuncOption =
     'set'
   ```

   `SetFuncOption` is **confirmed grammar-empty** — the same pattern as
   `SetSequenceOption` (sequences.md) and `SetGenerated` (columns.md). The
   parameter name (`search_path`) and its value (`public, pg_catalog`) are
   not extractable from this node in any form. This was already documented
   in functions.md's complete `FuncOption` resolution pass.

   **Practical implication for safe-migrate:** function-body search_path
   overrides (a common security hardening practice — setting
   `SET search_path = ''` or a specific schema on a `SECURITY DEFINER`
   function to prevent search_path-based privilege escalation) cannot be
   statically detected or verified from this AST. Any
   `CREATE FUNCTION ... SET ...` statement should note this limitation if
   safe-migrate ever implements search_path-related security rules for
   function definitions. The statement-level `Set` node (documented
   throughout this file) remains the only AST path where search_path changes
   are actually extractable.
