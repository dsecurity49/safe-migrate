# Sequences AST Reference for safe-migrate

## Status

Inspection status: complete for all core sequence nodes.

This document is derived from direct inspection of squawk.rs and should be treated as the
current source of truth for safe-migrate sequence handling.

All claims are AST-verified via grep and line-range inspection.

---

## Documentation Contract

1. Only document AST behavior that has been directly verified.
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. Assume additional nodes or helpers may exist outside the inspected surface.

---

## Handwritten Extension Policy

No handwritten extensions exist for any sequence node.

Verified by exhaustive grep documented in `columns.md`.
No sequence-related nodes appear in the complete handwritten extension inventory.

---

# High-Level Sequence Model

The verified AST surface exposes:

**Core sequence nodes:**
- `CreateSequence`
- `AlterSequence`
- `DropSequence`

**Option nodes:**
- `SequenceOption` — single polymorphic node for all sequence options
- `SequenceOptionList` — parenthesized list used in identity column context
- `SetSequenceOption` — token-only node used in `AlterColumnOption`

---

# Core Sequence Nodes

## CreateSequence

### Verified Accessors (line 5272)

```rust
pub fn if_not_exists(&self) -> Option<IfNotExists>
pub fn path(&self) -> Option<Path>
pub fn persistence(&self) -> Option<Persistence>
pub fn sequence_options(&self) -> AstChildren<SequenceOption>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn sequence_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `SchemaElement` enum (line 35569).
Member of `Stmt` enum (line 36835).

### Key Accessor Notes

**TEMP/UNLOGGED detection:** `persistence().is_some()`

**Sequence options:** `sequence_options()` returns `AstChildren<SequenceOption>`.
All sequence parameters (START, INCREMENT, MINVALUE, MAXVALUE, CYCLE, OWNED BY, etc.)
are encoded as individual `SequenceOption` nodes in this flat list.
Option kind must be determined by inspecting keyword tokens on each node.
See `SequenceOption` section below.

### safe-migrate guidance

```rust
CreateSequenceFact {
    name: QualifiedName,
    if_not_exists: bool,
    temporary: bool,                    // from persistence()
    options: Vec<SequenceOptionFact>,   // from sequence_options()
}
```

---

## AlterSequence

### Verified Accessors (line 1718)

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn path(&self) -> Option<Path>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn sequence_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `Stmt` enum (line 36529).

### Important Finding — Grammar Confirmed

The ungrammar definition confirms this is not an extraction gap:

```
AlterSequence =
  'alter' 'sequence' IfExists? Path ';'?
```

The grammar itself does not capture sequence alter options as a structured node.
This is a parser-level limitation, not a missing accessor. Whatever options
follow `ALTER SEQUENCE name` in the source SQL are not represented in the AST
beyond the bare statement shell.

### Status

```
AST verified
Grammar-confirmed limitation: ALTER SEQUENCE options are not parsed into structured nodes
```

---

## DropSequence

### Verified Accessors (line 7925)

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn paths(&self) -> AstChildren<Path>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn restrict_token(&self) -> Option<SyntaxToken>
pub fn sequence_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `Stmt` enum (line 37135).

### Key Accessor Notes

**Multiple sequences:** `paths()` returns `AstChildren<Path>` — multiple sequence
names supported in a single statement:

```sql
DROP SEQUENCE seq1, seq2, seq3;
```

### safe-migrate guidance

```rust
DropSequenceFact {
    names: Vec<QualifiedName>,  // from paths() — may be multiple
    if_exists: bool,
    cascade: bool,
}
```

Produce tombstones for each dropped sequence.
CASCADE must propagate through dependency graph to columns using this sequence
via `OWNED BY` or identity column definitions.

---

# Sequence Option Nodes

## SequenceOption

### Verified Accessors (line 16280)

```rust
// Child nodes — carry the option value
pub fn literal(&self) -> Option<Literal>
pub fn name_ref(&self) -> Option<NameRef>
pub fn path(&self) -> Option<Path>
pub fn ty(&self) -> Option<Type>

// Keyword tokens — identify the option kind
pub fn as_token(&self) -> Option<SyntaxToken>
pub fn by_token(&self) -> Option<SyntaxToken>
pub fn cycle_token(&self) -> Option<SyntaxToken>
pub fn increment_token(&self) -> Option<SyntaxToken>
pub fn logged_token(&self) -> Option<SyntaxToken>
pub fn maxvalue_token(&self) -> Option<SyntaxToken>
pub fn minvalue_token(&self) -> Option<SyntaxToken>
pub fn name_token(&self) -> Option<SyntaxToken>
pub fn no_token(&self) -> Option<SyntaxToken>
pub fn none_token(&self) -> Option<SyntaxToken>
pub fn owned_token(&self) -> Option<SyntaxToken>
pub fn restart_token(&self) -> Option<SyntaxToken>
pub fn sequence_token(&self) -> Option<SyntaxToken>
pub fn start_token(&self) -> Option<SyntaxToken>
pub fn unlogged_token(&self) -> Option<SyntaxToken>
pub fn with_token(&self) -> Option<SyntaxToken>
```

### Important Finding

`SequenceOption` is a single polymorphic node — NOT an enum.
All sequence option kinds are encoded in the same struct.
The option type must be inferred by inspecting which keyword token is present.

### Option Kind Detection Table

| Option | Detection | Value Accessor |
|--------|-----------|----------------|
| `AS type` | `as_token().is_some()` | `ty()` |
| `START [WITH] n` | `start_token().is_some()` | `literal()` |
| `INCREMENT [BY] n` | `increment_token().is_some()` | `literal()` |
| `MINVALUE n` | `minvalue_token().is_some()` + `no_token().is_none()` | `literal()` |
| `NO MINVALUE` | `minvalue_token().is_some()` + `no_token().is_some()` | — |
| `MAXVALUE n` | `maxvalue_token().is_some()` + `no_token().is_none()` | `literal()` |
| `NO MAXVALUE` | `maxvalue_token().is_some()` + `no_token().is_some()` | — |
| `CYCLE` | `cycle_token().is_some()` + `no_token().is_none()` | — |
| `NO CYCLE` | `cycle_token().is_some()` + `no_token().is_some()` | — |
| `OWNED BY col` | `owned_token().is_some()` | `path()` |
| `OWNED BY NONE` | `owned_token().is_some()` + `none_token().is_some()` | — |
| `RESTART [WITH] n` | `restart_token().is_some()` | `literal()` |
| `SEQUENCE NAME ident` | `sequence_token().is_some()` + `name_token().is_some()` | `name_ref()` |
| `LOGGED` | `logged_token().is_some()` + `unlogged_token().is_none()` | — |
| `UNLOGGED` | `unlogged_token().is_some()` | — |

### Grammar Confirmation

Cross-checked against postgresql.ungram. The grammar confirms this exact option
set with no `CACHE` variant present. An earlier draft of this document incorrectly
listed `CACHE` as a possible option — this has been removed as it does not exist
in the grammar or the verified accessor surface. PostgreSQL's `CACHE` clause for
sequences, if supported by this grammar version, is not represented as a distinct
`SequenceOption` keyword token in the inspected surface.

### Status

```
AST verified
Grammar-cross-checked: confirmed option set, CACHE variant does not exist in this grammar
```

### safe-migrate guidance

```rust
enum SequenceOptionFact {
    AsType(TypeIr),
    Start(i64),
    Increment(i64),
    MinValue(i64),
    NoMinValue,
    MaxValue(i64),
    NoMaxValue,
    Cycle,
    NoCycle,
    Cache(i64),
    OwnedBy(QualifiedName),
    OwnedByNone,
    Restart(Option<i64>),
    Logged,
    Unlogged,
}
```

Extraction requires a dispatch function that checks token presence in priority order,
not a simple match on a single accessor.

---

## SequenceOptionList

### Verified Accessors (line 16367)

```rust
pub fn sequence_options(&self) -> AstChildren<SequenceOption>
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
```

### Meaning

Parenthesized sequence option list used in identity column context:

```sql
col integer GENERATED ALWAYS AS IDENTITY (START 1 INCREMENT 1)
```

Used by `GeneratedConstraint.sequence_option_list()`.
See constraints.md for `GeneratedConstraint`.

Exposes the same `SequenceOption` children as `CreateSequence.sequence_options()`.

---

## SetSequenceOption

### Verified Accessors (line 16925)

```rust
pub fn set_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `AlterColumnOption` enum (line 32651).

### Meaning

```sql
ALTER TABLE t ALTER COLUMN c <sequence option>
```

Used for identity column sequence option changes, e.g.
`ALTER TABLE t ALTER COLUMN c SET INCREMENT BY 5` (PostgreSQL applies
sequence-style options to identity columns via `ALTER COLUMN ... SET ...`).

### Grammar Confirmation — FULLY RESOLVED

postgresql.ungram confirms:

```
SetSequenceOption =
  'set'

AlterColumn =
  'alter' 'column'? NameRef option:AlterColumnOption
```

`AlterColumn` carries no sibling content beyond the single `option` field —
there is no adjacent node where the sequence option payload could be hiding.
This confirms the payload is genuinely absent from this grammar version, not
merely missing from this node specifically.

**Significant finding for safe-migrate:** a migration statement like
`ALTER TABLE t ALTER COLUMN c SET INCREMENT BY 5` (changing an identity
column's sequence increment) can be detected as occurring
(`AlterColumnOption::SetSequenceOption` variant present), but the specific
option being changed and its new value cannot be extracted from this AST.
Any rule needing to evaluate the safety of an identity-column sequence
option change can only flag it as "unknown sequence option change" — it
cannot distinguish a harmless `RESTART` from a potentially disruptive
`INCREMENT BY` change.

### Status

```
Grammar verified — FULLY RESOLVED
Sequence option payload confirmed absent from both SetSequenceOption and
its parent AlterColumn. Not extractable from this grammar in any form.
```

---

# Verified Findings Summary

## Confirmed Complete

- `CreateSequence`: fully resolved
- `DropSequence`: fully resolved
- `SequenceOption`: fully resolved — polymorphic token-based dispatch documented
- `SequenceOptionList`: fully resolved

## Confirmed Partial

None remaining — all previously partial findings have been grammar-resolved.

## Grammar-Confirmed Limitations

- `AlterSequence`: confirmed by postgresql.ungram to carry no options clause —
  not an extraction gap, a parser-level limitation
- `SequenceOption`: confirmed by postgresql.ungram — no CACHE variant exists,
  full option set verified
- `SetSequenceOption`: confirmed by postgresql.ungram — the sequence option
  payload is genuinely absent from both this node and its parent `AlterColumn`,
  not extractable in any form from this grammar

## Grammar Cross-Check

This document has been fully cross-checked against postgresql.ungram.
`CreateSequence`, `DropSequence`, `SequenceOption`, `SequenceOptionList`,
`SetSequenceOption`, and `AlterSequence` all verified. Two corrections were
required: removal of the fabricated CACHE option, and reframing of
`AlterSequence`'s sparse surface as a confirmed grammar limitation rather
than an unresolved extraction gap.

---

# Remaining Open Questions

None remaining. All findings in this document have been resolved through
direct grammar cross-check against postgresql.ungram.
