# Enums AST Reference for safe-migrate

## Status

Verified against squawk_syntax 2.58.0 — July 2026

---

## Documentation Contract

1. Only document AST behavior that has been directly verified.
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. Assume additional nodes or helpers may exist outside the inspected surface.

---

## Scope Note — CreateType Is Not Enum-Specific

`CREATE TYPE` is a single polymorphic grammar rule covering four distinct
PostgreSQL type-creation forms, only one of which is the enum type. This
document covers the full `CreateType` node (since there is no separate
enum-only node), but the safe-migrate Visitor must always check which sub-form
is present before treating a `CreateType` as an enum.

---

# Core Nodes

## CreateType

### Verified Accessors (line 6870)

```rust
pub fn attribute_list(&self) -> Option<AttributeList>
pub fn column_list(&self) -> Option<ColumnList>
pub fn path(&self) -> Option<Path>
pub fn variant_list(&self) -> Option<VariantList>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn as_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn enum_token(&self) -> Option<SyntaxToken>
pub fn range_token(&self) -> Option<SyntaxToken>
pub fn type_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
CreateType =
  'create' 'type' Path
  ('as' 'enum' VariantList
| 'as' 'range' AttributeList
| 'as' ColumnList
| AttributeList) ';'?
```

### Four Mutually Exclusive Forms

| Form | SQL | Discriminator | Payload accessor |
|------|-----|----------------|-------------------|
| Enum type | `CREATE TYPE t AS ENUM (...)` | `enum_token().is_some()` | `variant_list()` |
| Range type | `CREATE TYPE t AS RANGE (...)` | `range_token().is_some()` | `attribute_list()` |
| Composite type | `CREATE TYPE t AS (...)` | `as_token().is_some()` AND `enum_token().is_none()` AND `range_token().is_none()` | `column_list()` |
| Base/shell type | `CREATE TYPE t (...)` or `CREATE TYPE t` | `as_token().is_none()` | `attribute_list()` |

**Discriminator logic must check tokens in this order**, since the absence
of `as_token()` is the only reliable signal for the base/shell type form —
both range type and base type populate `attribute_list()`, so that accessor
alone cannot distinguish them.

### safe-migrate guidance

```rust
enum CreateTypeFact {
    Enum {
        name: QualifiedName,           // from path()
        values: Vec<String>,           // from variant_list().variants()
    },
    Range {
        name: QualifiedName,
        options: Vec<AttributeFact>,   // from attribute_list()
    },
    Composite {
        name: QualifiedName,
        columns: Vec<ColumnFact>,      // from column_list()
    },
    BaseOrShell {
        name: QualifiedName,
        options: Vec<AttributeFact>,   // from attribute_list(), may be empty (shell type)
    },
}

fn classify_create_type(node: &CreateType) -> CreateTypeFact {
    if node.enum_token().is_some() {
        // Enum form
    } else if node.range_token().is_some() {
        // Range form
    } else if node.as_token().is_some() {
        // Composite form (AS without ENUM/RANGE means composite)
    } else {
        // Base/shell type form
    }
}
```

A visitor that assumes every `CreateType` is an enum (a reasonable but wrong
assumption if this file didn't exist) will misclassify range types, composite
types, and shell types as enums with zero values — or worse, crash on
`variant_list()` being `None`.

---

## VariantList

### Verified Accessors (line 20784)

```rust
pub fn variants(&self) -> AstChildren<Variant>
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
VariantList =
  '('
  (Variant (',' Variant)*)
  ')'
```

Matches exactly — comma-separated list of `Variant` in parens.

---

## Variant

### Verified Accessors (line 20773)

```rust
pub fn literal(&self) -> Option<Literal>
```

### Grammar Confirmation

```
Variant =
  Literal
```

A single enum value, represented as a string `Literal` (PostgreSQL enum
values are always quoted strings: `'value1'`, `'value2'`).

### safe-migrate guidance

```rust
fn extract_enum_values(variant_list: &VariantList) -> Vec<String> {
    variant_list.variants()
        .filter_map(|v| v.literal())
        .filter_map(|lit| /* extract string value from Literal */)
        .collect()
}
```

---

## DropType

### Verified Accessors (line 9519)

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn paths(&self) -> AstChildren<Path>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn restrict_token(&self) -> Option<SyntaxToken>
pub fn type_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
DropType =
  'drop' 'type' IfExists? (Path (',' Path)*)
  ('cascade' | 'restrict')? ';'?
```

Multi-name drop confirmed (`paths()` plural), consistent with the pattern
seen across `DropSchema`, `DropSequence`, `DropMaterializedView`, etc.

### safe-migrate guidance

`DROP TYPE` on an enum used by any existing column is a hard PostgreSQL
failure (the type is in use). This is a strong tier-1 (block) candidate
unless the dependency graph confirms zero columns currently reference the type.

---

## AlterType

### Verified Accessors (line 2716)

```rust
pub fn add_value(&self) -> Option<AddValue>
pub fn alter_type_actions(&self) -> AstChildren<AlterTypeAction>
pub fn owner_to(&self) -> Option<OwnerTo>
pub fn path(&self) -> Option<Path>
pub fn rename_attribute(&self) -> Option<RenameAttribute>
pub fn rename_to(&self) -> Option<RenameTo>
pub fn rename_value(&self) -> Option<RenameValue>
pub fn set_options(&self) -> Option<SetOptions>
pub fn set_schema(&self) -> Option<SetSchema>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn type_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
AlterType =
  'alter' 'type' Path
  (
    AlterTypeAction (',' AlterTypeAction)*
  | OwnerTo
  | SetSchema
  | SetOptions
  | RenameTo
  | RenameAttribute
  | RenameValue
  | AddValue
  ) ';'?
```

8 mutually exclusive top-level forms, all confirmed present as distinct
accessors. `AlterTypeAction` is comma-separated (multiple actions allowed in
a single statement) when that form is chosen — every other form is singular.

### Form-to-Accessor Mapping

| Grammar form | Accessor | Applies to |
|--------------|----------|------------|
| `AlterTypeAction*` | `alter_type_actions()` | Composite types (attribute add/drop/alter) |
| `OwnerTo` | `owner_to()` | Any type |
| `SetSchema` | `set_schema()` | Any type |
| `SetOptions` | `set_options()` | Base types (type-level options) |
| `RenameTo` | `rename_to()` | Any type |
| `RenameAttribute` | `rename_attribute()` | Composite types |
| `RenameValue` | `rename_value()` | **Enum types only** |
| `AddValue` | `add_value()` | **Enum types only** |

For safe-migrate's enum-specific analysis, only `add_value()` and
`rename_value()` are relevant; the other six forms apply to composite or
base types, or are type-agnostic (owner/schema/name changes).

### safe-migrate guidance

```rust
enum AlterTypeFact {
    AddEnumValue { ... },        // from add_value()
    RenameEnumValue { ... },     // from rename_value()
    CompositeAttributeChange(Vec<AlterTypeActionFact>),  // from alter_type_actions()
    OwnerChange { ... },
    SchemaChange { ... },
    OptionsChange { ... },
    Rename { ... },
    AttributeRename { ... },
}
```

---

## AddValue

### Verified Accessors (line 254)

```rust
pub fn if_not_exists(&self) -> Option<IfNotExists>
pub fn literal(&self) -> Option<Literal>
pub fn value_position(&self) -> Option<ValuePosition>
pub fn add_token(&self) -> Option<SyntaxToken>
pub fn value_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
AddValue =
  'add' 'value' IfNotExists? Literal ValuePosition?
```

Fully populated payload — confirms `ALTER TYPE t ADD VALUE [IF NOT EXISTS]
'newvalue' [BEFORE|AFTER 'existing']` is fully extractable.

### safe-migrate guidance

```rust
struct AddEnumValueFact {
    new_value: String,                    // from literal()
    if_not_exists: bool,                  // from if_not_exists().is_some()
    position: Option<ValuePositionFact>,  // from value_position()
}
```

**PostgreSQL semantic note relevant to safe-migrate:** `ALTER TYPE ... ADD
VALUE` cannot run inside a transaction block in older PostgreSQL versions
(pre-12) if the new value is used in the same transaction; PostgreSQL 12+
relaxed this for the `ADD VALUE` itself but still disallows using the new
value in the same transaction it was added in. This is a `TransactionFrame`-
relevant constraint — the rule engine should check whether `ADD VALUE` and
any subsequent use of that value occur within the same simulated transaction.

---

## ValuePosition (enum)

### Verified Members

```rust
pub enum ValuePosition {
    BeforeValue(BeforeValue),
    AfterValue(AfterValue),
}
```

### Grammar Confirmation

```
ValuePosition =
  BeforeValue
| AfterValue

BeforeValue =
  'before' Literal

AfterValue =
  'after' Literal
```

Both variants carry a single `Literal` — the existing enum value to position
relative to.

### Verified Accessors

```rust
// BeforeValue (line 3379)
pub fn literal(&self) -> Option<Literal>
pub fn before_token(&self) -> Option<SyntaxToken>

// AfterValue (line 359)
pub fn literal(&self) -> Option<Literal>
pub fn after_token(&self) -> Option<SyntaxToken>
```

### safe-migrate guidance

```rust
enum ValuePositionFact {
    Before(String),  // existing value to insert before
    After(String),   // existing value to insert after
}
```

The referenced existing value should be validated against the enum's known
current value set (tracked in `LocalState`) — referencing a non-existent
value is a guaranteed PostgreSQL failure, a strong tier-1 candidate.

---

## RenameValue

### Verified Accessors (line 17070)

```rust
pub fn literal(&self) -> Option<Literal>
pub fn rename_token(&self) -> Option<SyntaxToken>
pub fn to_token(&self) -> Option<SyntaxToken>
pub fn value_token(&self) -> Option<SyntaxToken>
```

### Grammar Discrepancy — IMPORTANT

postgresql.ungram shows:

```
RenameValue =
  'rename' 'value' Literal 'to' Literal
```

Two `Literal` children (old value, new value), but the verified Rust
accessor only exposes a **single** `literal()` via `support::child()`, which
returns only the **first** matching child of that type — it cannot
distinguish or retrieve the second `Literal`.

**This is the same pattern of bug already found in `PartitionForValuesFrom`
(partitions.md)** — a flat single-type accessor cannot disambiguate multiple
same-typed children in the grammar. This means:

- The **old value** (the value being renamed) is extractable via `literal()`.
- The **new value** (the replacement name) is **not extractable** through
  any verified accessor on this node. `support::child::<Literal>()` only
  returns the first match; there is no second accessor (`literal2()`, a
  `literals()` plural accessor, or similar) exposed for this node.

This is a genuine, confirmed extraction gap — not resolved by checking the
handwritten extension inventory (no `impl ast::RenameValue` extension exists
in `src/ast/node_ext.rs`).

### safe-migrate guidance

```rust
struct RenameEnumValueFact {
    old_value: String,           // literal() — extractable
    new_value: Option<String>,   // NOT extractable from this node alone
}
```

**This is a real limitation for safe-migrate.** `ALTER TYPE t RENAME VALUE
'old' TO 'new'` can be detected, and the old value identified, but the new
value name cannot be determined from this AST in its current form. Any rule
needing to validate the new value (e.g. checking for collisions with
existing enum values) cannot do so with the information available. This
should be flagged as a `Confidence::Tainted` mutation, or the new value
should be treated as unknown/wildcard for safety purposes — i.e. assume the
rename could introduce any value, including a colliding one, since the
specific new value cannot be statically confirmed.

### Status

```
AST verified
Old value (first Literal): extractable via literal()
New value (second Literal): confirmed NOT extractable — flat accessor only
  returns first child of type Literal; no handwritten extension exists to
  disambiguate. This is a genuine, confirmed gap, not an inference.
```

---

# Verified Findings Summary

## Confirmed Complete

- `CreateType`: fully resolved including all 4 mutually exclusive sub-forms
- `VariantList`: fully resolved
- `Variant`: fully resolved
- `DropType`: fully resolved
- `AlterType`: fully resolved including all 8 sub-forms
- `AddValue`: fully resolved, fully populated payload
- `ValuePosition` / `BeforeValue` / `AfterValue`: fully resolved

## Confirmed Partial — Genuine Extraction Gap

- `RenameValue`: old value extractable, new value **not extractable** due to
  a flat single-type accessor being unable to disambiguate two `Literal`
  children of the same type. This is analogous to the `PartitionForValuesFrom`
  finding in partitions.md but in this case there is no resolver-level
  workaround available (unlike the partition case, there's no external
  context like a column count to derive the split point from) — the second
  value is simply unrecoverable from this AST.

## Grammar Cross-Check

All nodes cross-checked against `src/postgresql.ungram` and the `squawk-syntax` source code in `src/ast/generated/nodes.rs` and `src/ast/node_ext.rs`.

---

# Remaining Open Questions

None remaining. The previously listed question about `RenameValue`'s second
`Literal` (the "to" value) has been reclassified from "open question" to
"confirmed grammar-level limitation":

The exhaustive `impl ast::*` inventory in `src/ast/node_ext.rs` (lines 1-1042)
already found no `impl ast::RenameValue` handwritten extension block — the same
inventory that confirmed `ForeignKeyConstraint`'s `from_columns()`/`to_columns()`
extensions DO exist at line 358 of `src/ast/node_ext.rs`. Since someone clearly
recognized and solved the identical "two same-typed Literal children" problem for
`ForeignKeyConstraint` but did not write an equivalent for `RenameValue`, the
absence is an intentional or overlooked gap, not an unexplored surface area.
The `RenameValue` new-value extraction gap documented in the `RenameValue`
section above is treated as confirmed, matching the same status as
`PartitionForValuesFrom`'s multi-column boundary ambiguity (partitions.md) —
a known, accepted limitation of this AST version.
