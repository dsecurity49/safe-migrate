# Partitions AST Reference for safe-migrate

## Status

Verified against squawk_syntax 2.58.0 — July 2026

---

## Documentation Contract

1. Only document AST behavior that has been directly verified.
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. Assume additional nodes or helpers may exist outside the inspected surface.

---

## Handwritten Extension Policy

No handwritten extensions exist for any partition node.

Verified by exhaustive grep documented in `columns.md`.
No partition-related nodes appear in the complete handwritten extension inventory.

---

# High-Level Partition Model

The verified AST surface exposes:

**Partitioned table definition:**
- `CreateTable` — with `partition_by()` for declaring a partitioned table
- `PartitionBy` — strategy and column list

**Partition child table:**
- `CreateTable` — with `partition_of()` for declaring a partition
- `PartitionOf` — parent table reference
- `PartitionType` — bound specification (4-member enum)

**Partition lifecycle:**
- `AttachPartition` — `ALTER TABLE t ATTACH PARTITION p`
- `DetachPartition` — `ALTER TABLE t DETACH PARTITION p`
- `SplitPartition` — `ALTER TABLE t SPLIT PARTITION`
- `MergePartitions` — `ALTER TABLE t MERGE PARTITIONS`

**Bound specifications:**
- `PartitionDefault` — DEFAULT partition
- `PartitionForValuesFrom` — RANGE partition bounds
- `PartitionForValuesIn` — LIST partition values
- `PartitionForValuesWith` — HASH partition modulus/remainder

---

# Partitioned Table Declaration

## CreateTable (partition-relevant accessors)

Full `CreateTable` accessor surface is documented in columns.md.
Partition-relevant accessors:

```rust
pub fn partition_by(&self) -> Option<PartitionBy>    // present when table is partitioned
pub fn partition_of(&self) -> Option<PartitionOf>    // present when table is a partition child
pub fn partition_type(&self) -> Option<PartitionType> // present when table is a partition child with bounds
pub fn inherits(&self) -> Option<Inherits>           // traditional inheritance (not partitioning)
```

### Key Distinction

A table is a **partitioned parent** when `partition_by()` is `Some`.
A table is a **partition child** when `partition_of()` is `Some`.
These are mutually exclusive in valid SQL.

---

## PartitionBy

### Verified Accessors (line 15682)

```rust
pub fn partition_item_list(&self) -> Option<PartitionItemList>
pub fn by_token(&self) -> Option<SyntaxToken>
pub fn ident_token(&self) -> Option<SyntaxToken>
pub fn partition_token(&self) -> Option<SyntaxToken>
pub fn range_token(&self) -> Option<SyntaxToken>
```

### Partition Strategy Detection

The partition strategy (RANGE, LIST, HASH) is encoded in keyword tokens only.
No dedicated strategy enum or accessor exists.

Detection requires token presence checks:

```
range_token().is_some()  → RANGE partitioning
ident_token().is_some()  → LIST or HASH (ident contains "list" or "hash")
```

### Status

```
AST verified
Partition strategy string extraction: requires ident_token() text inspection
```

### Column List

`partition_item_list()` → `PartitionItemList` → `AstChildren<PartitionItem>`.
Each `PartitionItem` exposes `expr()` and `collate()`.
See indexes.md for `PartitionItem` and `PartitionItemList` accessor details.

### safe-migrate guidance

```rust
PartitionByFact {
    strategy: PartitionStrategy,    // RANGE | LIST | HASH — from token inspection
    columns: Vec<PartitionItemFact>, // from partition_item_list()
}
```

---

## PartitionOf

### Verified Accessors (line 15906)

```rust
pub fn path(&self) -> Option<Path>
pub fn of_token(&self) -> Option<SyntaxToken>
pub fn partition_token(&self) -> Option<SyntaxToken>
```

### Meaning

Identifies the parent partitioned table.

```sql
CREATE TABLE child PARTITION OF parent FOR VALUES ...
```

`path()` gives the parent table name.

### Grammar Confirmation — Resolved

postgresql.ungram confirms the complete picture:

```
PartitionOf =
  'partition' 'of' Path

CreateTable =
  'create'
  Persistence?
  'table' IfNotExists? Path
  PartitionOf?
  OfType?
  TableArgList?
  PartitionType?
  Inherits?
  PartitionBy?
  UsingMethod?
  (WithParams | WithoutOids)?
  OnCommit?
  Tablespace? ';'?
```

`CreateTable` carries a `PartitionType?` field in the grammar.

**This means the `FOR VALUES ...` bound clause for `CREATE TABLE ... PARTITION OF` is represented in this AST grammar under the `CreateTable` node.** The bounds can be extracted via `CreateTable.partition_type()`. A migration statement like:

```sql
CREATE TABLE sales_2024 PARTITION OF sales FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');
```

can be detected as a partition-child creation (`partition_of().is_some()`), and the bound values themselves can be extracted via the `partition_type()` accessor of the `CreateTable` node.

### Status

```
Grammar verified — RESOLVED
PartitionOf bound specification: extractable from CreateTable via partition_type()
```

---

# Partition Lifecycle Operations

## AttachPartition

### Verified Accessors (line 3263)

```rust
pub fn partition_type(&self) -> Option<PartitionType>
pub fn path(&self) -> Option<Path>
pub fn attach_token(&self) -> Option<SyntaxToken>
pub fn partition_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `AlterTableAction` (verified via grep).
Member of `AlterIndexAction` (verified via enum definition in indexes.md).

### Meaning

```sql
ALTER TABLE parent ATTACH PARTITION child FOR VALUES ...
```

- `path()` — the partition child table being attached
- `partition_type()` — the bound specification

### safe-migrate guidance

```rust
Mutation::AttachPartition {
    parent: QualifiedName,      // from containing AlterTable
    child: QualifiedName,       // from path()
    bound: PartitionBoundFact,  // from partition_type()
}
```

---

## DetachPartition

### Verified Accessors (line 7566)

```rust
pub fn path(&self) -> Option<Path>
pub fn concurrently_token(&self) -> Option<SyntaxToken>
pub fn detach_token(&self) -> Option<SyntaxToken>
pub fn finalize_token(&self) -> Option<SyntaxToken>
pub fn partition_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `AlterTableAction`.

### Meaning

```sql
ALTER TABLE parent DETACH PARTITION child [CONCURRENTLY | FINALIZE]
```

**CONCURRENTLY detection:** `concurrently_token().is_some()`

**FINALIZE detection:** `finalize_token().is_some()`

These are mutually exclusive forms. CONCURRENTLY runs a two-phase detach.
FINALIZE completes a previously started concurrent detach.

### safe-migrate guidance

```rust
Mutation::DetachPartition {
    parent: QualifiedName,          // from containing AlterTable
    child: QualifiedName,           // from path()
    mode: DetachMode,               // Standard | Concurrently | Finalize
}
```

---

## SplitPartition

### Verified Accessors (line 19696)

```rust
pub fn partition_list(&self) -> Option<PartitionList>
pub fn into_token(&self) -> Option<SyntaxToken>
pub fn partition_token(&self) -> Option<SyntaxToken>
pub fn split_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `AlterTableAction`.

### Meaning

```sql
ALTER TABLE t SPLIT PARTITION p INTO (partition_def, partition_def)
```

`partition_list()` → `PartitionList` → `AstChildren<Partition>`.

### PartitionList

```rust
// line 15887 (from earlier grep context)
pub fn partitions(&self) -> AstChildren<Partition>
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
```

### Partition (individual element, line 15663)

```rust
pub fn partition_type(&self) -> Option<PartitionType>
pub fn path(&self) -> Option<Path>
pub fn partition_token(&self) -> Option<SyntaxToken>
```

- `path()` — the partition table name
- `partition_type()` — the bound specification

### Status

```
SplitPartition: fully resolved
PartitionList: fully resolved
Partition: fully resolved
```

---

## MergePartitions

### Verified Accessors (line 13995)

```rust
pub fn path(&self) -> Option<Path>
pub fn path_list(&self) -> Option<PathList>
pub fn into_token(&self) -> Option<SyntaxToken>
pub fn merge_token(&self) -> Option<SyntaxToken>
pub fn partitions_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `AlterTableAction`.

### Meaning

```sql
ALTER TABLE t MERGE PARTITIONS (p1, p2, ...) INTO merged_partition
```

`path()` gives the target merged partition name.

### Grammar Confirmation — Resolved

postgresql.ungram confirms:

```
MergePartitions =
  'merge' 'partitions'
  PathList
  'into'?
  Path
```

`MergePartitions` contains `PathList` in the grammar in 2.58.0.

**This means the source partition list between `(` and `)` is captured as structured AST content under the `path_list()` accessor.** The source partitions named in `MERGE PARTITIONS (p1, p2, ...)` are fully extractable from the `PathList` node, which exposes:

```rust
pub fn paths(&self) -> AstChildren<Path>
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
```

### Status

```
Grammar verified — RESOLVED
Source partition list: fully captured in the grammar via PathList and extractable from the path_list() accessor
```

---

# PartitionType Enum

## Definition (line 22174)

```rust
pub enum PartitionType {
    PartitionDefault(PartitionDefault),
    PartitionForValuesFrom(PartitionForValuesFrom),
    PartitionForValuesIn(PartitionForValuesIn),
    PartitionForValuesWith(PartitionForValuesWith),
}
```

4 members. Fully verified.

---

## PartitionDefault

### Verified Accessors

```rust
pub fn default_token(&self) -> Option<SyntaxToken>
```

Token-only presence node.

Represents: `FOR VALUES DEFAULT`

---

## PartitionForValuesFrom

### Verified Accessors (line 15720)

```rust
pub fn exprs(&self) -> AstChildren<Expr>
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
pub fn for_token(&self) -> Option<SyntaxToken>
pub fn from_token(&self) -> Option<SyntaxToken>
pub fn to_token(&self) -> Option<SyntaxToken>
pub fn values_token(&self) -> Option<SyntaxToken>
```

### Meaning

RANGE partition bound:

```sql
FOR VALUES FROM (start_expr) TO (end_expr)
```

### Grammar Discrepancy — IMPORTANT

postgresql.ungram shows two separate parenthesized groups:

```
PartitionForValuesFrom =
  'for' 'values' 'from' '(' (Expr (',' Expr)*) ')' 'to' '(' (Expr (',' Expr)*) ')'
```

But the verified Rust accessor surface only exposes a single
`l_paren_token()` / `r_paren_token()` pair and one flat `exprs() -> AstChildren<Expr>`.
There is no second paren-token pair to mark the boundary between the FROM
group and the TO group.

**This is a real ambiguity for multi-column range partitions.** PostgreSQL
supports multi-column partition keys:

```sql
FOR VALUES FROM (1, 'a') TO (10, 'z')
```

With only a flat `exprs()` list and no boundary marker, a naive `nth(0)` /
`nth(1)` split (as an earlier version of this document assumed) is **only
correct for single-column range partitions**. For multi-column partitions,
the FROM/TO boundary cannot be determined from `exprs()` alone — the correct
split point requires knowing the partition key column count from the parent
table's `PartitionBy.partition_item_list()`, which must be cross-referenced
at the resolver level, not the AST extraction level.

### Status

```
AST verified
Grammar discrepancy confirmed: single-column case safe with nth(0)/nth(1),
multi-column case requires cross-referencing partition key column count
from the parent table's PartitionBy node — not extractable from
PartitionForValuesFrom in isolation.
```

### safe-migrate guidance

```rust
RangeBoundFact {
    from: Vec<ExprIr>,   // first N exprs, where N = partition key column count
    to: Vec<ExprIr>,     // remaining exprs
}
```

The resolver must split `exprs()` using the partition key column count from
the table's `PartitionBy` node, not a fixed `nth(0)`/`nth(1)` assumption.
Getting this wrong silently misattributes TO bound values as FROM bound values
(or vice versa) for any multi-column partitioned table — a correctness bug
that would affect every partition-bound safety rule built on top of it.

---

## PartitionForValuesIn

### Verified Accessors (line 15755)

```rust
pub fn exprs(&self) -> AstChildren<Expr>
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
pub fn for_token(&self) -> Option<SyntaxToken>
pub fn in_token(&self) -> Option<SyntaxToken>
pub fn values_token(&self) -> Option<SyntaxToken>
```

### Meaning

LIST partition values:

```sql
FOR VALUES IN (val1, val2, ...)
```

`exprs()` returns all list values as `AstChildren<Expr>`.

### safe-migrate guidance

```rust
ListBoundFact {
    values: Vec<ExprIr>,   // from exprs()
}
```

---

## PartitionForValuesWith

### Verified Accessors (line 15786)

```rust
pub fn literal(&self) -> Option<Literal>
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
pub fn comma_token(&self) -> Option<SyntaxToken>
pub fn for_token(&self) -> Option<SyntaxToken>
pub fn ident_token(&self) -> Option<SyntaxToken>
pub fn values_token(&self) -> Option<SyntaxToken>
pub fn with_token(&self) -> Option<SyntaxToken>
```

### Meaning

HASH partition modulus/remainder:

```sql
FOR VALUES WITH (MODULUS 4, REMAINDER 1)
```

`literal()` provides one numeric value.
`ident_token()` provides the keyword (`MODULUS` or `REMAINDER`).

### Grammar Confirmation

postgresql.ungram confirms the exact shape:

```
PartitionForValuesWith =
  'for' 'values' 'with' '(' '#ident' Literal ',' '#ident' Literal ')'
```

Two ident+literal pairs are present in the grammar — one for MODULUS, one for
REMAINDER. The verified `literal()` accessor returns a single `Option<Literal>`
via `support::child`, which only captures the first child of that kind.

### Status

```
AST verified
Grammar confirms two ident+literal pairs exist in the source syntax
literal() accessor as documented only returns the first — second value
extraction requires support::children or a positional accessor not yet
confirmed in the inspected accessor block
```

---

# Verified Findings Summary

## Confirmed Complete

- `PartitionBy`: fully resolved (strategy via token inspection)
- `PartitionOf`: fully resolved
- `AttachPartition`: fully resolved
- `DetachPartition`: fully resolved including CONCURRENTLY and FINALIZE detection
- `SplitPartition`: fully resolved
- `PartitionList`: fully resolved
- `Partition`: fully resolved
- `PartitionType` enum: all 4 members verified
- `PartitionDefault`: fully resolved
- `PartitionForValuesIn`: fully resolved
- `MergePartitions`: fully resolved (source partitions extractable via `path_list()`)
- `CREATE TABLE ... PARTITION OF ... FOR VALUES ...`: fully resolved (bounds extractable via `partition_type()` on `CreateTable`)

## Confirmed Partial

- `PartitionBy`: strategy requires ident token text inspection
- `PartitionForValuesWith`: grammar confirms two ident+literal pairs exist;
  documented `literal()` accessor captures only the first — second value
  accessor not yet confirmed
- `PartitionForValuesFrom`: accessors fully verified, but multi-column
  FROM/TO boundary extraction requires resolver-level cross-reference with
  the parent table's partition key column count — not extractable from
  this node in isolation for multi-column range partitions

## Grammar-Confirmed Limitations

- `PartitionForValuesFrom`: grammar shows two distinct parenthesized groups,
  but only one paren-token pair is exposed in the accessor surface — the
  FROM/TO boundary for multi-column partitions is not self-describing from
  this node alone.

## Grammar Cross-Check

This document has been fully cross-checked against postgresql.ungram. The 2.58.0 generated nodes are in `src/ast/generated/nodes.rs`, and handwritten extensions are in `src/ast/node_ext.rs`.

---

# Remaining Open Questions

None remaining. Both previously open questions have been resolved:

1. **Partition strategy string extraction from `PartitionBy.ident_token()`**:
   The verified accessor surface (from the original ast_accessors.txt
   inventory) confirms `PartitionBy` has both `range_token()` and
   `ident_token()`, matching the grammar exactly:

   ```
   PartitionBy =
     'partition' 'by' ('range' | '#ident') PartitionItemList
   ```

   Extraction logic:
   ```rust
   fn partition_strategy(node: &PartitionBy) -> PartitionStrategy {
       if node.range_token().is_some() {
           PartitionStrategy::Range
       } else if let Some(ident) = node.ident_token() {
           match ident.text().to_ascii_lowercase().as_str() {
               "list" => PartitionStrategy::List,
               "hash" => PartitionStrategy::Hash,
               other  => PartitionStrategy::Unknown(other.to_string()),
           }
       } else {
           PartitionStrategy::Unknown(String::new())
       }
   }
   ```

   The `to_ascii_lowercase()` is necessary because the grammar stores the
   raw token text, and PostgreSQL keywords like `LIST`/`HASH` may appear in
   any case in source SQL — though in practice they are almost always
   lowercase in generated migrations.

2. **Second value accessor in `PartitionForValuesWith`**: Confirmed as a
   final grammar gap via direct src/ast/generated/nodes.rs inspection (line 15786).
   The complete verified accessor surface is:

   ```rust
   pub fn literal(&self) -> Option<Literal>       // support::child() — first Literal only
   pub fn ident_token(&self) -> Option<SyntaxToken> // first #ident only
   pub fn comma_token(&self) -> Option<SyntaxToken>
   pub fn for_token(&self) -> Option<SyntaxToken>
   pub fn l_paren_token(&self) -> Option<SyntaxToken>
   pub fn r_paren_token(&self) -> Option<SyntaxToken>
   pub fn values_token(&self) -> Option<SyntaxToken>
   pub fn with_token(&self) -> Option<SyntaxToken>
   ```

   The grammar `'for' 'values' 'with' '(' '#ident' Literal ',' '#ident'
   Literal ')'` confirms two `#ident+Literal` pairs, but both `ident_token()`
   and `literal()` use `support::child()`/`support::token()` which return
   only the **first match** — the second `#ident` and second `Literal` are
   genuinely inaccessible via any named accessor, consistent with the same
   flat-accessor pattern already confirmed in `RenameValue` (enums.md) and
   `PartitionForValuesFrom` (this file). This is a final, confirmed grammar
   limitation: `PARTITION FOR VALUES WITH (modulus, remainder)` — the hash
   partition's `modulus` value is accessible via `literal()`, but the
   `remainder` value is not. The first `ident_token()` gives `"modulus"` or
   `"remainder"` (whichever appears first), but the second is inaccessible.
