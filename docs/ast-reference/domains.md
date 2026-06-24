# Domains AST Reference for safe-migrate

## Status

Inspection status: complete. Cross-checked directly against postgresql.ungram
and squawk.rs in a single pass.

---

## Documentation Contract

1. Only document AST behavior that has been directly verified.
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. Assume additional nodes or helpers may exist outside the inspected surface.

---

## Scope Note

PostgreSQL domains are a constrained alias over a base type
(`CREATE DOMAIN d AS integer CHECK (VALUE > 0)`). All three lifecycle nodes
(`CreateDomain`, `AlterDomain`, `DropDomain`) are documented here.
`AlterDomainAction`'s 11 members are mostly nodes already fully documented in
constraints.md and columns.md — this file references those rather than
re-documenting their accessor bodies.

---

# Core Nodes

## CreateDomain

### Verified Accessors (line 4372)

```rust
pub fn collate(&self) -> Option<Collate>
pub fn constraints(&self) -> AstChildren<Constraint>
pub fn path(&self) -> Option<Path>
pub fn ty(&self) -> Option<Type>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn as_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn domain_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
CreateDomain =
  'create' 'domain' Path 'as'? Type Collate? Constraint* ';'?
```

Matches exactly. `'as'?` confirms the `AS` keyword is optional in PostgreSQL
syntax (`CREATE DOMAIN d integer` is valid, same as `CREATE DOMAIN d AS integer`)
— `as_token()` presence is purely cosmetic and does not gate whether `ty()`
is populated.

`constraints()` reuses the same `Constraint` enum documented in full in
constraints.md (9 members: CheckConstraint, DefaultConstraint,
ForeignKeyConstraint, GeneratedConstraint, NotNullConstraint, NullConstraint,
PrimaryKeyConstraint, ReferencesConstraint, UniqueConstraint). In practice,
PostgreSQL only permits `CHECK`, `NOT NULL`, `NULL`, and `DEFAULT` constraints
on domains — `PRIMARY KEY`, `FOREIGN KEY`, `UNIQUE`, and generated-column
constraints are not valid on a domain and would be rejected by PostgreSQL at
execution time even though the AST grammar does not prevent parsing them.
This is a case where the **grammar is permissive but PostgreSQL semantics
are stricter** — the AST cannot be relied on to reject invalid domain
constraint combinations; that validation belongs in the rule engine, not
the AST layer.

### safe-migrate guidance

```rust
struct CreateDomainFact {
    name: QualifiedName,              // from path()
    base_type: TypeIr,                // from ty()
    collation: Option<String>,        // from collate()
    constraints: Vec<ConstraintFact>, // from constraints(), see constraints.md
}
```

A domain's `CHECK` constraint is evaluated against every existing value when
the domain already has columns using it via `ALTER DOMAIN ... ADD CONSTRAINT`
(see below), but at `CREATE DOMAIN` time there are no existing columns yet —
this is always safe at creation, the risk is entirely in later
`ALTER DOMAIN ... ADD CONSTRAINT` against an already-adopted domain.

---

## DropDomain

### Verified Accessors (line 6958)

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn paths(&self) -> AstChildren<Path>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn domain_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn restrict_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
DropDomain =
  'drop' 'domain' IfExists? (Path (',' Path)*)
  ('cascade' | 'restrict')? ';'?
```

Multi-name drop confirmed (`paths()` plural), consistent with the pattern
established across `DropSchema`, `DropSequence`, `DropType`,
`DropMaterializedView`.

### safe-migrate guidance

`DROP DOMAIN` fails if any column currently uses the domain as its type,
unless `CASCADE` is specified (which then drops those columns — a
significant, likely tier-1, blast-radius event). The dependency graph must
track domain-to-column usage to evaluate this correctly: any column whose
type resolves to a domain name must be tracked, not just columns with
"normal" built-in types.

---

## AlterDomain

### Verified Accessors (line 782)

```rust
pub fn action(&self) -> Option<AlterDomainAction>
pub fn path(&self) -> Option<Path>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn domain_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
AlterDomain =
  'alter' 'domain' Path action:AlterDomainAction ';'?
```

### Important Finding — Single Action Only

`action()` returns `Option<AlterDomainAction>` (singular), and the grammar
confirms `AlterDomain` takes exactly **one** action per statement — not a
repeated list like `AlterTable.actions()` (`AstChildren<AlterTableAction>`).
This means `ALTER DOMAIN d ADD CONSTRAINT c1 CHECK (...), ADD CONSTRAINT c2
CHECK (...)` in a single statement is **not valid PostgreSQL syntax for
domains** (unlike `ALTER TABLE`, which does support comma-separated multiple
actions) — and the grammar confirms this restriction is enforced at the
parse level, not just by convention. A migration needing multiple domain
changes requires multiple separate `ALTER DOMAIN` statements.

---

## AlterDomainAction (enum)

### Verified Members (11 total)

```rust
pub enum AlterDomainAction {
    AddConstraint(AddConstraint),
    DropConstraint(DropConstraint),
    DropDefault(DropDefault),
    DropNotNull(DropNotNull),
    OwnerTo(OwnerTo),
    RenameConstraint(RenameConstraint),
    RenameTo(RenameTo),
    SetDefault(SetDefault),
    SetNotNull(SetNotNull),
    SetSchema(SetSchema),
    ValidateConstraint(ValidateConstraint),
}
```

### Grammar Confirmation

```
AlterDomainAction =
  SetDefault
| DropDefault
| SetNotNull
| DropNotNull
| AddConstraint
| DropConstraint
| RenameConstraint
| ValidateConstraint
| OwnerTo
| RenameTo
| SetSchema
```

11 members confirmed exactly.

### Cross-References

All 11 member node types are documented in detail elsewhere:

| Node | Documented in |
|------|----------------|
| `AddConstraint` | constraints.md |
| `DropConstraint` | constraints.md |
| `RenameConstraint` | constraints.md |
| `ValidateConstraint` | constraints.md |
| `SetDefault` | columns.md (AlterColumnOption context) |
| `DropDefault` | columns.md (AlterColumnOption context) |
| `SetNotNull` | columns.md (AlterColumnOption context) |
| `DropNotNull` | columns.md (AlterColumnOption context) |
| `OwnerTo` | cross-cutting, used by many Alter* nodes |
| `RenameTo` | cross-cutting, used by many Alter* nodes |
| `SetSchema` | cross-cutting, used by many Alter* nodes |

No new accessor bodies need documenting here — the same verified accessor
surfaces apply in this context.

### Important Safety Distinction: ADD CONSTRAINT on a Domain

`ALTER DOMAIN d ADD CONSTRAINT c CHECK (VALUE > 0)` is **fundamentally
different in risk profile** from `ALTER TABLE t ADD CONSTRAINT c CHECK (...)`:
adding a `CHECK` constraint to a domain validates the constraint against
**every column in every table that currently uses that domain as its type**,
not just one table. This is a multi-table validation scan, and the safety
analysis must treat it accordingly — the dependency graph needs to resolve
"which columns use domain X" (potentially across many tables) before this
operation's risk can be assessed, not just "which single table is being
altered" as with a normal `ALTER TABLE ... ADD CONSTRAINT`.

### safe-migrate guidance

```rust
enum AlterDomainFact {
    AddConstraint(ConstraintFact),      // HIGH RISK: validates across all using columns
    DropConstraint { name: String },
    RenameConstraint { from: String, to: String },
    ValidateConstraint { name: String }, // also a full scan across using columns
    SetDefault(ExprIr),
    DropDefault,
    SetNotNull,                          // also validates across all using columns/values
    DropNotNull,
    OwnerChange(RoleFact),
    Rename { from: String, to: String },
    SchemaChange { new_schema: String },
}
```

`AddConstraint`, `ValidateConstraint`, and `SetNotNull` on a domain all share
the same multi-table blast-radius characteristic and should be flagged
together as the domain-specific high-risk subset of `AlterDomainAction`. The
rest (`DropConstraint`, `RenameConstraint`, `SetDefault`, `DropDefault`,
`DropNotNull`, `OwnerTo`, `RenameTo`, `SetSchema`) are lower-risk metadata or
removal operations that do not require scanning dependent data.

---

# Verified Findings Summary

## Confirmed Complete

- `CreateDomain`: fully resolved
- `DropDomain`: fully resolved
- `AlterDomain`: fully resolved, including the single-action-only constraint
- `AlterDomainAction` enum: all 11 members verified, all cross-referenced to
  their existing detailed documentation elsewhere

## Key Architectural Findings

1. **`AlterDomain` permits exactly one action per statement** (confirmed by
   grammar, not just convention) — distinct from `AlterTable`'s repeated
   action list.
2. **Grammar is more permissive than PostgreSQL semantics** for
   `CreateDomain` constraints — the AST will parse `PRIMARY KEY`/`UNIQUE`/
   `FOREIGN KEY` constraints on a domain even though PostgreSQL rejects them
   at execution time. Validation of constraint-type appropriateness for
   domains belongs in the rule engine.
3. **Domain constraint changes have multi-table blast radius** — `ADD
   CONSTRAINT`, `VALIDATE CONSTRAINT`, and `SET NOT NULL` on a domain
   validate against every column across every table using that domain, not
   just a single table. This is architecturally distinct from the equivalent
   `ALTER TABLE` operations and requires the dependency graph to resolve
   domain-to-column usage across the entire schema.

## Grammar Cross-Check

This document was written with postgresql.ungram available from the start.
All nodes cross-checked in this single pass; no corrections needed.

---

# Remaining Open Questions

None identified in this pass.
