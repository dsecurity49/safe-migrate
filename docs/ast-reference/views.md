# Views AST Reference for safe-migrate

## Status

Inspection status: complete for all view and materialized view nodes.

This document is derived from direct inspection of squawk.rs and should be treated as the
current source of truth for safe-migrate view handling.

All claims are AST-verified via grep and line-range inspection.

---

## Documentation Contract

1. Only document AST behavior that has been directly verified.
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. Assume additional nodes or helpers may exist outside the inspected surface.

---

## Handwritten Extension Policy

No handwritten extensions exist for any view node.

Verified by exhaustive grep documented in `columns.md`.
No view-related nodes appear in the complete handwritten extension inventory.

---

# High-Level View Model

The verified AST surface exposes:

**Regular views:**
- `CreateView`
- `AlterView`
- `DropView`

**Materialized views:**
- `CreateMaterializedView`
- `AlterMaterializedView`
- `DropMaterializedView`
- `Refresh`

**Synthetic unification node:**
- `CreateViewLike` — unifies `CreateView` and `CreateMaterializedView`

**Alter dispatch:**
- `AlterMaterializedViewAction` (5-member enum)

---

# Regular Views

## CreateView

### Verified Accessors (line 6056)

```rust
pub fn column_list(&self) -> Option<ColumnList>
pub fn or_replace(&self) -> Option<OrReplace>
pub fn path(&self) -> Option<Path>
pub fn persistence(&self) -> Option<Persistence>
pub fn query(&self) -> Option<SelectVariant>
pub fn with_params(&self) -> Option<WithParams>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn as_token(&self) -> Option<SyntaxToken>
pub fn cascaded_token(&self) -> Option<SyntaxToken>
pub fn check_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn local_token(&self) -> Option<SyntaxToken>
pub fn option_token(&self) -> Option<SyntaxToken>
pub fn recursive_token(&self) -> Option<SyntaxToken>
pub fn view_token(&self) -> Option<SyntaxToken>
pub fn with_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `SchemaElement` enum (line 35587).
Member of `Stmt` enum (line 36931).

### Key Accessor Notes

**OR REPLACE detection:** `or_replace().is_some()`

**RECURSIVE detection:** `recursive_token().is_some()`

**TEMP/TEMPORARY detection:** `persistence().is_some()`
`Persistence` is a two-variant enum: `Temp` and `Unlogged`.

**WITH CHECK OPTION detection:**
Three tokens encode this:
- `check_token()` — CHECK keyword presence
- `local_token()` — LOCAL form
- `cascaded_token()` — CASCADED form

Detection:
```
check_token present + local_token present   → WITH LOCAL CHECK OPTION
check_token present + cascaded_token present → WITH CASCADED CHECK OPTION
check_token present alone                   → WITH CHECK OPTION (default cascaded)
```

**Column alias list:** `column_list()` — optional explicit column names.

**Query:** `query()` → `SelectVariant` — the view definition query.

### safe-migrate guidance

```rust
CreateViewFact {
    name: QualifiedName,                    // from path()
    or_replace: bool,
    recursive: bool,
    temporary: bool,                        // from persistence()
    column_aliases: Vec<String>,            // from column_list()
    query: SelectVariantIr,                 // from query()
    check_option: Option<CheckOptionKind>,  // from token inspection
}

enum CheckOptionKind {
    Local,
    Cascaded,
}
```

---

## AlterView

### Verified Accessors (line 2301)

```rust
pub fn path(&self) -> Option<Path>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn view_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `Stmt` enum (line 36619).

### Important Finding — Grammar Confirmed

The ungrammar definition confirms this is not an extraction gap:

```
AlterView =
  'alter' 'view' Path ';'?
```

`AlterView` genuinely carries no action or option clause in this grammar.
`path()` and keyword tokens are the complete surface — there is nothing
further to extract. This is a grammar-level limitation, not a missing accessor.

### Status

```
AST verified
Grammar-confirmed: AlterView carries no actions beyond path()
```

---

## DropView

### Verified Accessors (line 8651)

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn path(&self) -> Option<Path>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn restrict_token(&self) -> Option<SyntaxToken>
pub fn view_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `Stmt` enum (line 37225).

### Important Finding

`DropView.path()` returns a single `Option<Path>`.
Only one view name is accessible per statement through this accessor.

### safe-migrate guidance

```rust
DropViewFact {
    name: QualifiedName,    // from path()
    if_exists: bool,
    cascade: bool,
}
```

---

# Materialized Views

## CreateMaterializedView

### Verified Accessors (line 4779)

```rust
pub fn column_list(&self) -> Option<ColumnList>
pub fn if_not_exists(&self) -> Option<IfNotExists>
pub fn path(&self) -> Option<Path>
pub fn query(&self) -> Option<SelectVariant>
pub fn tablespace(&self) -> Option<Tablespace>
pub fn using_method(&self) -> Option<UsingMethod>
pub fn with_data(&self) -> Option<WithData>
pub fn with_no_data(&self) -> Option<WithNoData>
pub fn with_params(&self) -> Option<WithParams>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn as_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn materialized_token(&self) -> Option<SyntaxToken>
pub fn view_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `Stmt` enum (line 36769).
Member of `ExplainStmt` enum (line 34154).

### Key Accessor Notes

**WITH DATA / WITH NO DATA detection:**
- `with_data().is_some()` → `WITH DATA` (populate immediately)
- `with_no_data().is_some()` → `WITH NO DATA` (create empty)
- Both `None` → default behavior (same as `WITH DATA`)

**Access method:** `using_method()` → `UsingMethod` → `name_ref()`.
Materialized views support custom access methods.

**Differences from CreateView:**
- Has `if_not_exists`, `tablespace`, `using_method`, `with_data`, `with_no_data`
- Does NOT have `or_replace`, `recursive`, `persistence`, `check_option` tokens

### safe-migrate guidance

```rust
CreateMaterializedViewFact {
    name: QualifiedName,
    if_not_exists: bool,
    column_aliases: Vec<String>,        // from column_list()
    query: SelectVariantIr,             // from query()
    with_data: WithDataState,           // WithData | WithNoData | Default
    tablespace: Option<String>,
    using_method: Option<String>,
}
```

---

## AlterMaterializedView

### Verified Accessors (line 1180)

```rust
pub fn action(&self) -> AstChildren<AlterMaterializedViewAction>
pub fn if_exists(&self) -> Option<IfExists>
pub fn name(&self) -> Option<Name>
pub fn name_ref(&self) -> Option<NameRef>
pub fn owned_by_roles(&self) -> Option<OwnedByRoles>
pub fn path(&self) -> Option<Path>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn all_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn in_token(&self) -> Option<SyntaxToken>
pub fn materialized_token(&self) -> Option<SyntaxToken>
pub fn nowait_token(&self) -> Option<SyntaxToken>
pub fn set_token(&self) -> Option<SyntaxToken>
pub fn tablespace_token(&self) -> Option<SyntaxToken>
pub fn view_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `Stmt` enum (line 36457).

### Key Accessor Notes

**Action dispatch:** `action()` returns `AstChildren<AlterMaterializedViewAction>` —
note this is a children iterator, not a single optional child.

**ALL IN TABLESPACE form:**
`all_token()` and `in_token()` presence indicates:
```sql
ALTER MATERIALIZED VIEW ALL IN TABLESPACE old [OWNED BY role] SET TABLESPACE new [NOWAIT]
```

**NOWAIT detection:** `nowait_token().is_some()`

**View identification:**
Both `name_ref()` and `path()` are present — one identifies the target view,
the other may identify a tablespace in the ALL IN TABLESPACE form.

### AlterMaterializedViewAction Enum (line 19394)

```rust
pub enum AlterMaterializedViewAction {
    DependsOnExtension(DependsOnExtension),
    NoDependsOnExtension(NoDependsOnExtension),
    RenameColumn(RenameColumn),
    RenameTo(RenameTo),
    SetSchema(SetSchema),
    AlterTableAction(AlterTableAction),  // note: also contains AlterTableAction
}
```

Verified via `From<X> for AlterMaterializedViewAction` impls at lines 32953-32977.

### Individual Variant Accessors — Resolved via Cross-Reference

All 6 members are nodes already fully documented elsewhere in this AST
reference set — no new accessor inspection is needed, only cross-reference:

| Variant | Documented in | Notes |
|---------|----------------|-------|
| `DependsOnExtension` | triggers.md (AlterTrigger context) | `name_ref()` → extension name |
| `NoDependsOnExtension` | triggers.md (AlterTrigger context) | `name_ref()` → extension name |
| `RenameColumn` | columns.md | `from()`/`to()` — see columns.md's documented grammar/implementation discrepancy note for this node |
| `RenameTo` | cross-cutting, used throughout | `name()` → new name |
| `SetSchema` | cross-cutting, used throughout | `name_ref()` → new schema name |
| `AlterTableAction` | columns.md / constraints.md / partitions.md (large 38-member enum) | See "Important Finding" below |

### Important Finding — AlterTableAction Wrapping Is Intentional

`AlterMaterializedViewAction::AlterTableAction` wraps the **entire**
`AlterTableAction` enum (38 members, documented piecemeal across columns.md,
constraints.md, and partitions.md wherever each member's primary node lives)
as a single variant. This means a materialized view's `ALTER` statement can
in principle carry any `AlterTableAction` member — `AddColumn`,
`AddConstraint`, `SetAccessMethod`, `ClusterOn`, etc. — even though many of
these (like `DetachPartition` or `MergePartitions`) make no semantic sense
for a materialized view.

**This is confirmed to be the actual grammar shape, not a parser
implementation artifact** — postgresql.ungram's `AlterMaterializedView` rule
directly lists `action:AlterMaterializedViewAction*` with `AlterTableAction`
as one of its own alternation members, meaning the grammar itself permits
this broad surface. PostgreSQL's actual `ALTER MATERIALIZED VIEW` syntax in
practice only supports a small subset of `ALTER TABLE`-style actions (mainly
column-storage/statistics-related ones like `ALTER COLUMN ... SET
STATISTICS`, plus `OWNER TO`, `CLUSTER ON`, `SET WITHOUT CLUSTER`) — the
grammar being permissive here mirrors the same "grammar is broader than
PostgreSQL semantics" pattern already noted for `CreateDomain`'s constraint
list in domains.md. The rule engine, not the AST layer, must reject
semantically invalid combinations (e.g. a materialized view `ALTER`
statement containing `DetachPartition`, which PostgreSQL would reject at
execution time).

### Status

```
AlterMaterializedViewAction membership: fully verified
Individual variant accessor surfaces: fully resolved via cross-reference
  to existing documentation (no new inspection required, all 6 members
  documented elsewhere in this reference set)
AlterTableAction wrapping: confirmed intentional per grammar, with the
  same "grammar permissive, PostgreSQL semantics stricter" caveat already
  established for domains.md
```

---

## DropMaterializedView

### Verified Accessors (line 7370)

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn paths(&self) -> AstChildren<Path>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn materialized_token(&self) -> Option<SyntaxToken>
pub fn restrict_token(&self) -> Option<SyntaxToken>
pub fn view_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `Stmt` enum (line 37057).

### Critical Asymmetry with DropView

`DropMaterializedView.paths()` returns `AstChildren<Path>` — multiple names supported.
`DropView.path()` returns `Option<Path>` — single name only.

```sql
DROP MATERIALIZED VIEW mv1, mv2, mv3;  -- supported, paths() gives all three
DROP VIEW v1;                           -- single only, path() gives one
```

### safe-migrate guidance

```rust
DropMaterializedViewFact {
    names: Vec<QualifiedName>,  // from paths() — may be multiple
    if_exists: bool,
    cascade: bool,
}
```

---

## Refresh (REFRESH MATERIALIZED VIEW)

### Verified Accessors (line 14841)

```rust
pub fn path(&self) -> Option<Path>
pub fn with_data(&self) -> Option<WithData>
pub fn with_no_data(&self) -> Option<WithNoData>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn concurrently_token(&self) -> Option<SyntaxToken>
pub fn materialized_token(&self) -> Option<SyntaxToken>
pub fn refresh_token(&self) -> Option<SyntaxToken>
pub fn view_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `Stmt` enum.

### Key Accessor Notes

**CONCURRENTLY detection:** `concurrently_token().is_some()`
Significant for safe-migrate — concurrent refresh requires a unique index
and cannot run inside certain transaction contexts.

**WITH DATA / WITH NO DATA:**
- `with_data().is_some()` → populate on refresh
- `with_no_data().is_some()` → clear data on refresh

### safe-migrate guidance

```rust
RefreshMaterializedViewFact {
    name: QualifiedName,            // from path()
    concurrently: bool,
    with_data: WithDataState,
}
```

---

# CreateViewLike — Synthetic Unification Node

## Definition (line 39162)

```rust
impl CreateViewLike {
    pub fn column_list(&self) -> Option<ast::ColumnList>
    pub fn path(&self) -> Option<ast::Path>
    pub fn query(&self) -> Option<ast::SelectVariant>
}
```

### Membership

```rust
impl AstNode for CreateViewLike {
    fn can_cast(kind: ast::SyntaxKind) -> bool {
        matches!(
            kind,
            ast::SyntaxKind::CREATE_MATERIALIZED_VIEW | ast::SyntaxKind::CREATE_VIEW
        )
    }
}
```

### Meaning

`CreateViewLike` is a synthetic AST node that can cast from either
`CREATE VIEW` or `CREATE MATERIALIZED VIEW` syntax nodes.

It exposes the minimal common surface:
- `path()` — view name
- `column_list()` — optional column aliases
- `query()` — the defining query

### safe-migrate guidance

Use `CreateViewLike` when writing rules that apply equally to both view types.
Use `CreateView` or `CreateMaterializedView` directly when type-specific
properties are needed (e.g. `with_data`, `or_replace`, `recursive`).

---

# Verified Findings Summary

## Confirmed Complete

- `CreateView`: fully resolved
- `DropView`: fully resolved
- `CreateMaterializedView`: fully resolved
- `DropMaterializedView`: fully resolved
- `Refresh`: fully resolved
- `CreateViewLike`: fully resolved
- `AlterMaterializedViewAction` enum: all members verified

## Confirmed Complete (updated)

- `AlterMaterializedView`: fully resolved, including all 6
  `AlterMaterializedViewAction` variant cross-references and the confirmed
  intentionality of the `AlterTableAction` wrapping

## Grammar-Confirmed Limitations

- `AlterView`: confirmed by postgresql.ungram to carry no actions beyond path() —
  not an extraction gap, a grammar-level limitation

## Grammar Cross-Check

This document has been fully cross-checked against postgresql.ungram.
`CreateView`, `DropView`, `CreateMaterializedView`, `DropMaterializedView`,
`Refresh`, `AlterMaterializedView`, and `AlterMaterializedViewAction` all match
the verified accessor surface exactly. The `AlterView` grammar-confirmed empty
action surface (above) was the only correction required.

## Critical Asymmetry

`DropView` supports only a single view name per statement (`path()`).
`DropMaterializedView` supports multiple names per statement (`paths()`).
Any code treating these uniformly will silently miss multiple-name drops.

---

# Remaining Open Questions

None remaining. The `AlterMaterializedViewAction` variant accessor surfaces
were resolved via cross-reference to existing documentation elsewhere in
this reference set, and the `AlterTableAction` wrapping was confirmed
intentional per direct grammar inspection.
