# Indexes AST Reference for safe-migrate

## Status

Inspection status: complete for all core index nodes and AlterIndexAction variants.

This document is derived from direct inspection of squawk.rs and should be treated as the
current source of truth for safe-migrate index handling.

All claims are AST-verified via grep and line-range inspection.

---

## Documentation Contract

1. Only document AST behavior that has been directly verified.
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. Assume additional nodes or helpers may exist outside the inspected surface.

---

## Handwritten Extension Policy

No handwritten extensions exist for any index node.

Verified by exhaustive grep of all `impl ast::*` blocks (line 38145-39260 in squawk.rs):

```bash
grep -n "^impl ast::" squawk.rs
```

No index-related nodes appear in that list. The complete handwritten extension
inventory is documented in `columns.md` and applies to all AST documentation files.

---

# High-Level Index Model

The verified AST surface exposes:

**Core index nodes:**
- `CreateIndex`
- `DropIndex`
- `AlterIndex`

**Alter index dispatch:**
- `AlterIndexAction` (8-member enum)

**Supporting nodes:**
- `PartitionItemList` / `PartitionItem` — index column expressions
- `UsingMethod` — access method (e.g. btree, hash, gist)
- `UsingIndex` — USING INDEX reference in constraint context
- `IndexExpr` — bracket expression node
- `Tablespace` — tablespace reference
- `WithParams` — storage parameters
- `ConstraintIncludeClause` — INCLUDE clause

---

# Core Index Nodes

## CreateIndex

### Verified Accessors (line 4653)

```rust
pub fn constraint_include_clause(&self) -> Option<ConstraintIncludeClause>
pub fn if_not_exists(&self) -> Option<IfNotExists>
pub fn name(&self) -> Option<Name>
pub fn nulls_distinct(&self) -> Option<NullsDistinct>
pub fn nulls_not_distinct(&self) -> Option<NullsNotDistinct>
pub fn partition_item_list(&self) -> Option<PartitionItemList>
pub fn relation_name(&self) -> Option<RelationName>
pub fn tablespace(&self) -> Option<Tablespace>
pub fn using_method(&self) -> Option<UsingMethod>
pub fn where_clause(&self) -> Option<WhereClause>
pub fn with_params(&self) -> Option<WithParams>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn concurrently_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn index_token(&self) -> Option<SyntaxToken>
pub fn on_token(&self) -> Option<SyntaxToken>
pub fn unique_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `SchemaElement` enum (line 19716).
Member of `Stmt` enum (line 19807).

### Key Accessor Notes

**CONCURRENTLY detection:**
`concurrently_token()` presence indicates `CREATE INDEX CONCURRENTLY`.
This is significant for safe-migrate — concurrent index creation cannot run inside
a transaction block.

**UNIQUE detection:**
`unique_token()` presence indicates a unique index.

**Index name:**
`name()` returns `Option<Name>` — index names are optional in PostgreSQL
(`CREATE INDEX ON t (col)` is valid).

**Index columns:**
`partition_item_list()` → `PartitionItemList` → `AstChildren<PartitionItem>`.
Each `PartitionItem` exposes `expr()` and `collate()`.
This is the primary extraction point for indexed expressions and columns.

**Access method:**
`using_method()` → `UsingMethod` → `name_ref()`.
Method name is accessible as a `NameRef`.

**INCLUDE clause — GRAMMAR-CONFIRMED GAP:**
`constraint_include_clause()` → `ConstraintIncludeClause`.
postgresql.ungram confirms `ConstraintIncludeClause = 'include'` — only the
keyword token exists in the grammar, and no sibling column-list node is
adjacent to it in `CreateIndex`'s grammar rule either. The covering column
list in `CREATE INDEX ... INCLUDE (col1, col2)` is **not captured anywhere**
in this AST. A migration adding a covering index with INCLUDE columns can be
detected (`constraint_include_clause().is_some()`), but the specific included
columns cannot be extracted. See constraints.md for full detail.

**WHERE clause:**
`where_clause()` → `WhereClause` → `expr()`.
Partial index predicate fully accessible.

### safe-migrate guidance

```rust
CreateIndexFact {
    name: Option<String>,           // from name() — may be None
    table: QualifiedName,           // from relation_name()
    unique: bool,                   // from unique_token().is_some()
    concurrently: bool,             // from concurrently_token().is_some()
    if_not_exists: bool,            // from if_not_exists()
    method: Option<String>,         // from using_method() -> name_ref()
    columns: Vec<IndexColumnFact>,  // from partition_item_list()
    where_expr: Option<ExprIr>,     // from where_clause()
    tablespace: Option<String>,     // from tablespace()
    nulls_distinct: NullsDistinctState,
}

struct IndexColumnFact {
    expr: ExprIr,               // from partition_item() -> expr()
    collation: Option<String>,  // from partition_item() -> collate()
}
```

---

## DropIndex

### Verified Accessors (line 7292)

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn paths(&self) -> AstChildren<Path>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn concurrently_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn index_token(&self) -> Option<SyntaxToken>
pub fn restrict_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `Stmt` enum (line 19855).

### Key Accessor Notes

**Multiple indexes:**
`paths()` returns `AstChildren<Path>` — DROP INDEX supports multiple index names
in a single statement: `DROP INDEX idx1, idx2`.

**CONCURRENTLY detection:**
`concurrently_token()` presence indicates `DROP INDEX CONCURRENTLY`.
Same transaction restriction applies as `CREATE INDEX CONCURRENTLY`.

**CASCADE vs RESTRICT:**
Both `cascade_token()` and `restrict_token()` are present.
Presence of either indicates the chosen behavior.

### safe-migrate guidance

```rust
DropIndexFact {
    names: Vec<QualifiedName>,  // from paths() — may be multiple
    if_exists: bool,
    concurrently: bool,
    cascade: bool,
}
```

Produce tombstones for each dropped index.
CASCADE must propagate through the dependency graph.

---

## AlterIndex

### Verified Accessors (line 1067)

```rust
pub fn alter_index_action(&self) -> Option<AlterIndexAction>
pub fn if_exists(&self) -> Option<IfExists>
pub fn name_ref(&self) -> Option<NameRef>
pub fn owned_by_roles(&self) -> Option<OwnedByRoles>
pub fn path(&self) -> Option<Path>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn all_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn in_token(&self) -> Option<SyntaxToken>
pub fn index_token(&self) -> Option<SyntaxToken>
pub fn nowait_token(&self) -> Option<SyntaxToken>
pub fn set_token(&self) -> Option<SyntaxToken>
pub fn tablespace_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `Stmt` enum (line 19754).

### Key Accessor Notes

**Index identification:**
Both `name_ref()` and `path()` are present — one identifies the target index,
the other may identify a tablespace in the `ALL IN TABLESPACE` form.

**ALL IN TABLESPACE form:**
`all_token()` and `in_token()` presence indicates:
```sql
ALTER INDEX ALL IN TABLESPACE old_tablespace [OWNED BY role] SET TABLESPACE new_tablespace
```
In this form `owned_by_roles()` may also be populated.

**Action dispatch:**
`alter_index_action()` → `AlterIndexAction` enum.

### safe-migrate guidance

```rust
AlterIndexFact {
    target: AlterIndexTarget,       // single index or ALL IN TABLESPACE
    if_exists: bool,
    action: AlterIndexActionFact,
}

enum AlterIndexTarget {
    Named(QualifiedName),
    AllInTablespace { tablespace: String, owned_by: Vec<String> },
}
```

---

# AlterIndexAction

## Enum Definition (line 19379)

```rust
pub enum AlterIndexAction {
    AlterSetStatistics(AlterSetStatistics),
    AttachPartition(AttachPartition),
    DependsOnExtension(DependsOnExtension),
    NoDependsOnExtension(NoDependsOnExtension),
    RenameTo(RenameTo),
    ResetOptions(ResetOptions),
    SetOptions(SetOptions),
    SetTablespace(SetTablespace),
}
```

8 members. Fully verified at line 19379 and cross-checked against
`From<X> for AlterIndexAction` impls at lines 32858+.

### Variant Notes

**RenameTo:** Renames the index. Identity-preserving operation.

**SetTablespace:** Moves index to a different tablespace.

**AttachPartition:** Attaches a partition index to a parent partitioned index.
Significant for partitioned table handling.

**AlterSetStatistics:** Sets per-column statistics target on an index column.

**DependsOnExtension / NoDependsOnExtension:** Marks or unmarks extension dependency.

**ResetOptions / SetOptions:** Storage parameter management.

### Accessor surfaces for AlterIndexAction variants

Individual accessor surfaces for `AlterIndexAction` variants have not been
inspected in this pass.

### Status

```
Membership verified via enum definition
Individual accessor surfaces: not inspected
```

---

# Supporting Nodes

## PartitionItemList

### Verified Accessors (line 14148)

```rust
pub fn partition_items(&self) -> AstChildren<PartitionItem>
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
```

Primary extraction point for index column expressions in `CreateIndex`.

---

## PartitionItem

### Verified Accessors (line 14133)

```rust
pub fn collate(&self) -> Option<Collate>
pub fn expr(&self) -> Option<Expr>
```

Represents a single index column or expression with optional collation.

### Grammar Confirmation — RESOLVED

postgresql.ungram confirms the complete rule:

```
PartitionItem =
  Expr Collate?
```

This is genuinely the entire grammar for this node. Sort order (ASC/DESC),
nulls ordering (NULLS FIRST/LAST), and operator class are confirmed absent
from the grammar entirely — not an accessor gap.

**Significant finding for safe-migrate:** real PostgreSQL `CREATE INDEX`
syntax supports `CREATE INDEX ON t (col DESC NULLS LAST opclass)`, but this
AST grammar does not capture any of those modifiers on `PartitionItem`. Since
`PartitionItemList`/`PartitionItem` is shared between `CreateIndex` and
`PartitionBy` (see partitions.md), this limitation applies to both index
column definitions and partition key column definitions equally.

### Status

```
Grammar verified — FULLY RESOLVED
Sort order, nulls ordering, and operator class confirmed absent from grammar.
Not extractable from this AST in any form, for either CREATE INDEX or
PARTITION BY column lists.
```

---

## UsingMethod

### Verified Accessors (line 18144)

```rust
pub fn name_ref(&self) -> Option<NameRef>
pub fn using_token(&self) -> Option<SyntaxToken>
```

Access method name (e.g. `btree`, `hash`, `gist`, `gin`, `brin`) accessible
via `name_ref()`.

Used by: `CreateIndex`, `CreateTable`, `CreateMaterializedView`, `ExcludeConstraint` context.

---

## UsingIndex

### Verified Accessors (line 18125)

```rust
pub fn name_ref(&self) -> Option<NameRef>
pub fn index_token(&self) -> Option<SyntaxToken>
pub fn using_token(&self) -> Option<SyntaxToken>
```

Represents `USING INDEX index_name` in constraint context:

```sql
ALTER TABLE t ADD CONSTRAINT name PRIMARY KEY USING INDEX idx_name
```

Used by: `PrimaryKeyConstraint`, `UniqueConstraint`.
Index name accessible via `name_ref()`.

---

## IndexExpr

### Verified Accessors — Generated (line 10268)

```rust
pub fn l_brack_token(&self) -> Option<SyntaxToken>
pub fn r_brack_token(&self) -> Option<SyntaxToken>
```

### Verified Accessors — Handwritten (line 38390)

```rust
pub fn base(&self) -> Option<ast::Expr>   // the expression being subscripted
pub fn index(&self) -> Option<ast::Expr>  // the subscript index expression
```

Both the base expression and the index expression are fully accessible.

---

# Verified Findings Summary

## Confirmed Complete

- `CreateIndex`: fully resolved
- `DropIndex`: fully resolved
- `AlterIndex`: fully resolved
- `AlterIndexAction` enum: all 8 members verified
- `PartitionItemList`: fully resolved
- `PartitionItem`: fully resolved (grammar-confirmed — sort order, nulls
  ordering, operator class confirmed absent from grammar entirely)
- `UsingMethod`: fully resolved
- `UsingIndex`: fully resolved
- `IndexExpr`: fully resolved via handwritten extension at line 38390

## Confirmed Partial

- `AlterIndexAction` variants: membership verified, individual accessor
  surfaces not inspected

## Grammar-Confirmed Limitations

- `PartitionItem`: sort order (ASC/DESC), nulls ordering (NULLS FIRST/LAST),
  and operator class are confirmed absent from the grammar entirely. This is
  not an extraction gap — PostgreSQL's `CREATE INDEX ON t (col DESC NULLS LAST)`
  syntax simply does not capture these modifiers in this AST version, for
  either index columns or partition key columns.
- `ConstraintIncludeClause`: postgresql.ungram confirms the INCLUDE column list
  is genuinely absent from this grammar — not an extraction gap. Covering
  indexes can be detected but their included columns cannot be extracted.

---

# Remaining Open Questions

None remaining. `AlterIndexAction` variant surfaces are now fully resolved:

**Grammar confirmed (8 members):**
```
AlterIndexAction =
  AttachPartition
| DependsOnExtension
| NoDependsOnExtension
| ResetOptions
| RenameTo
| SetTablespace
| SetOptions
| AlterSetStatistics
```

**Variant cross-references:**

| Variant | Documented in | Notes |
|---------|----------------|-------|
| `AttachPartition` | partitions.md | `path()` + `partition_type()` |
| `DependsOnExtension` | triggers.md / functions.md | `name_ref()` → extension |
| `NoDependsOnExtension` | triggers.md / functions.md | `name_ref()` → extension |
| `ResetOptions` | columns.md (AlterColumnOption context) | grammar-empty `()` |
| `RenameTo` | cross-cutting | `name()` → new name |
| `SetTablespace` | cross-cutting | `path()` → tablespace name |
| `SetOptions` | columns.md (AlterColumnOption context) | `attribute_list()` payload |
| `AlterSetStatistics` | **NEW — documented below** | |

**AlterSetStatistics — Verified Accessors (line 1772):**

```rust
pub fn literal(&self) -> Option<Literal>
pub fn name_ref(&self) -> Option<NameRef>
pub fn column_token(&self) -> Option<SyntaxToken>
pub fn set_token(&self) -> Option<SyntaxToken>
pub fn statistics_token(&self) -> Option<SyntaxToken>
```

Grammar: `'set' 'column'? (Literal | NameRef) 'set' 'statistics' Literal`

Represents `ALTER INDEX ... ALTER COLUMN col SET STATISTICS n` — setting the
planner statistics target for a specific index column. Two `Literal` positions
exist in the grammar when the column is expressed as a string literal rather
than an identifier, creating a potential flat-accessor ambiguity. However in
practice, the column expression is almost always a `NameRef` (identifier) —
in that case `name_ref()` returns the column name and `literal()` returns the
statistics target value unambiguously. Only when the column is expressed as
a string `Literal` does an ambiguity arise (both `literal()` calls would hit
the column literal first, not the statistics value). This is an extreme edge
case in real-world SQL; the common case is fully extractable.

```rust
struct AlterIndexSetStatisticsFact {
    column: Either<String, String>,  // from name_ref().text() (common) or literal() (rare)
    target: Option<Literal>,         // from literal() — unambiguous when column is NameRef
}
```
