# Constraints AST Reference for safe-migrate

## Status

Inspection status: extensive and verified against squawk.rs source.

This document is derived from direct inspection of the generated and handwritten Squawk AST
in `squawk.rs` and should be treated as the current source of truth for safe-migrate constraint
handling.

This document records only behavior that has been AST-verified via grep and line-range inspection.

Where information is incomplete it is explicitly marked as unresolved rather than inferred.

---

## Documentation Contract

This document follows four rules:

1. Only document AST behavior that has been directly verified.
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. Assume additional nodes, helpers, or grammar constructs may exist outside the inspected surface.

Accordingly:

- findings in this document are AST-verified
- unresolved areas remain unresolved
- future AST archaeology may discover additional helpers or nodes
- this document may be extended but should not be contradicted without new AST evidence

---

## Handwritten Extension Policy

Only one handwritten extension exists for constraint types:

```
impl ast::ForeignKeyConstraint  (line 38440)
```

Verified by exhaustive grep documented in `columns.md`.
All other constraint types expose only generated accessors.

---

# High-Level Constraint Model

The verified AST surface exposes:

**Enums:**
- `Constraint`
- `ColumnConstraint`
- `TableConstraint`

**Identity:**
- `ConstraintName`

**Lifecycle operations:**
- `AddConstraint`
- `DropConstraint`
- `RenameConstraint`
- `ValidateConstraint`
- `AlterConstraint`

**Concrete constraint nodes:**
- `CheckConstraint`
- `PrimaryKeyConstraint`
- `UniqueConstraint`
- `ForeignKeyConstraint`
- `ReferencesConstraint`
- `ExcludeConstraint`
- `DefaultConstraint`
- `GeneratedConstraint`
- `NotNullConstraint`
- `NullConstraint`

**Supporting nodes:**
- `ConstraintExclusion`
- `ConstraintExclusionList`
- `ConstraintIndexMethod`
- `ConstraintIncludeClause`
- `ConstraintIndexTablespace`
- `ReferencesTable`
- `WhereConditionClause`

**Constraint-bearing structures:**
- `Column`
- `AddColumn`
- `DropColumn`

---

# Core Constraint Enums

## Constraint

### Verified Members

```rust
pub enum Constraint {
    CheckConstraint(CheckConstraint),
    DefaultConstraint(DefaultConstraint),
    ForeignKeyConstraint(ForeignKeyConstraint),
    GeneratedConstraint(GeneratedConstraint),
    NotNullConstraint(NotNullConstraint),
    NullConstraint(NullConstraint),
    PrimaryKeyConstraint(PrimaryKeyConstraint),
    ReferencesConstraint(ReferencesConstraint),
    UniqueConstraint(UniqueConstraint),
}
```

### Evidence

Verified via `From<X> for Constraint` impls in ast_accessors.txt.

### safe-migrate guidance

Normalize into an internal constraint model:

```rust
enum ConstraintKind {
    Check,
    Default,
    ForeignKey,
    Generated,
    NotNull,
    Null,
    PrimaryKey,
    References,
    Unique,
}
```

---

## ColumnConstraint

### Verified Members

```rust
pub enum ColumnConstraint {
    CheckConstraint(CheckConstraint),
    DefaultConstraint(DefaultConstraint),
    ExcludeConstraint(ExcludeConstraint),
    NotNullConstraint(NotNullConstraint),
    PrimaryKeyConstraint(PrimaryKeyConstraint),
    ReferencesConstraint(ReferencesConstraint),
    UniqueConstraint(UniqueConstraint),
}
```

### Evidence

Verified via grep line 19478 and `From<X> for ColumnConstraint` impls.

### Notes

- `ForeignKeyConstraint` is NOT a member of `ColumnConstraint`.
- `ExcludeConstraint` IS a member of both `ColumnConstraint` and `TableConstraint`.

### safe-migrate guidance

Column identity must not be discarded when extracting column constraints:

```rust
ColumnConstraintFact {
    column: String,
    constraint_kind: ConstraintKind,
    constraint_name: Option<String>,
    payload: ConstraintPayload,
}
```

---

## TableConstraint

### Verified Members

```rust
pub enum TableConstraint {
    CheckConstraint(CheckConstraint),
    ExcludeConstraint(ExcludeConstraint),
    ForeignKeyConstraint(ForeignKeyConstraint),
    PrimaryKeyConstraint(PrimaryKeyConstraint),
    UniqueConstraint(UniqueConstraint),
}
```

### Evidence

Verified via grep lines 19939 and 37578 and `From<X> for TableConstraint` impls.

### safe-migrate guidance

Primary extraction point for:

- multi-column primary keys
- multi-column unique constraints
- table-level check constraints
- table-level foreign keys
- exclusion constraints

---

# Constraint Identity

## ConstraintName

### Verified Accessors

```rust
// line 3961
pub fn name(&self) -> Option<Name>
pub fn constraint_token(&self) -> Option<SyntaxToken>
```

### safe-migrate guidance

Constraint names must be preserved as first-class identifiers:

```rust
struct ConstraintIdentity {
    name: Option<String>,
    kind: ConstraintKind,
}
```

Required for: DROP CONSTRAINT, RENAME CONSTRAINT, VALIDATE CONSTRAINT, ALTER CONSTRAINT.

---

# Constraint Lifecycle Operations

## AddConstraint

### Verified Accessors

```rust
pub fn constraint(&self) -> Option<Constraint>
pub fn deferrable_constraint_option(&self) -> Option<DeferrableConstraintOption>
pub fn enforced(&self) -> Option<Enforced>
pub fn initially_deferred_constraint_option(&self) -> Option<InitiallyDeferredConstraintOption>
pub fn initially_immediate_constraint_option(&self) -> Option<InitiallyImmediateConstraintOption>
pub fn no_inherit(&self) -> Option<NoInherit>
pub fn not_deferrable_constraint_option(&self) -> Option<NotDeferrableConstraintOption>
pub fn not_enforced(&self) -> Option<NotEnforced>
pub fn not_valid(&self) -> Option<NotValid>
pub fn add_token(&self) -> Option<SyntaxToken>
```

### Meaning

Represents:

```sql
ALTER TABLE t ADD CONSTRAINT name ...
```

### safe-migrate guidance

Resolve into:

```rust
Mutation::AddConstraint {
    constraint_identity: ConstraintIdentity,
    not_valid: bool,
    enforced: bool,
    deferrable: DeferrableState,
    no_inherit: bool,
}
```

---

## DropConstraint

### Verified Accessors

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn name_ref(&self) -> Option<NameRef>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn constraint_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn restrict_token(&self) -> Option<SyntaxToken>
```

### Meaning

Represents:

```sql
ALTER TABLE t DROP CONSTRAINT name [CASCADE | RESTRICT]
```

### safe-migrate guidance

```rust
Mutation::DropConstraint {
    name: String,
    if_exists: bool,
    cascade: bool,
}
```

Produce tombstones. Cascading drops must propagate through the dependency graph.

---

## RenameConstraint

### Verified Accessors

```rust
pub fn name(&self) -> Option<Name>       // new name
pub fn name_ref(&self) -> Option<NameRef> // old name
pub fn constraint_token(&self) -> Option<SyntaxToken>
pub fn rename_token(&self) -> Option<SyntaxToken>
pub fn to_token(&self) -> Option<SyntaxToken>
```

### Meaning

Represents:

```sql
ALTER TABLE t RENAME CONSTRAINT old TO new
```

### safe-migrate guidance

Treat as identity preservation. Do not model as drop + create.

---

## ValidateConstraint

### Verified Accessors

```rust
pub fn name_ref(&self) -> Option<NameRef>
pub fn constraint_token(&self) -> Option<SyntaxToken>
pub fn validate_token(&self) -> Option<SyntaxToken>
```

### Meaning

Represents:

```sql
ALTER TABLE t VALIDATE CONSTRAINT name
```

### safe-migrate guidance

Track validation as explicit state transition:

```
NotValid -> Validated
```

---

## AlterConstraint

### Verified Accessors

```rust
// line 615-638
pub fn option(&self) -> Option<AlterColumnOption>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn constraint_token(&self) -> Option<SyntaxToken>
```

### Findings

- Node exists and is a member of `AlterTableAction` (line 19419, 33170).
- Exposes `AlterColumnOption` via `option()`. No direct accessor for constraint
  name, deferrability, validation state, or enforcement state on this node itself.

### Grammar Confirmation — FULLY RESOLVED

postgresql.ungram confirms:

```
AlterConstraint =
  'alter' 'constraint' option:AlterColumnOption

AlterTableAction =
  ...
| RenameTo
| RenameConstraint
| RenameColumn
| AlterConstraint
  ...
```

This is structurally identical to `AlterColumn`'s dispatch pattern (see columns.md) —
both route through the same `AlterColumnOption` enum. The grammar confirms there
is genuinely no constraint-name field on this node. Additionally, `AlterConstraint`
sits as a flat, unwrapped alternative directly inside `AlterTableAction`'s own
alternation — the same structural pattern already confirmed to definitively rule
out a sibling-node workaround for the trigger enable/disable gap (see triggers.md).
There is no wrapping node anywhere in the grammar that could carry the constraint
name alongside `AlterConstraint`.

**This means PostgreSQL's `ALTER TABLE t ALTER CONSTRAINT constraint_name
option` cannot have its target constraint name extracted from this AST in
any form.** The operation (deferrability/enforcement change) can be detected
as occurring against table `t`, but which specific constraint is targeted
cannot be determined. This is now considered a final, confirmed grammar
limitation — not an open question requiring further squawk.rs inspection.

### Status

```
Grammar verified — FULLY RESOLVED
Constraint name confirmed absent from AlterConstraint and from every
grammar position reachable around it (including the parent AlterTableAction
alternation, which provides no wrapping node). This is a genuine, final
limitation analogous to the trigger enable/disable name gap in triggers.md.
```

---

# Concrete Constraint Nodes

## CheckConstraint

### Verified Accessors

```rust
pub fn constraint_name(&self) -> Option<ConstraintName>
pub fn expr(&self) -> Option<Expr>
pub fn no_inherit(&self) -> Option<NoInherit>
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
pub fn check_token(&self) -> Option<SyntaxToken>
```

### safe-migrate guidance

```rust
CheckConstraintFact {
    name: Option<String>,
    expression: ExprIr,
    no_inherit: bool,
}
```

Expression must flow into ExprIr for rule evaluation.

---

## NotNullConstraint

### Verified Accessors

```rust
pub fn name_ref(&self) -> Option<NameRef>
pub fn no_inherit(&self) -> Option<NoInherit>
pub fn constraint_token(&self) -> Option<SyntaxToken>
pub fn not_token(&self) -> Option<SyntaxToken>
pub fn null_token(&self) -> Option<SyntaxToken>
```

Verified against the original `ast_accessors.txt` reference document (this
session's project knowledge source). This node was a documentation gap in
earlier drafts — listed as an enum member but never given its own section.

### Grammar Confirmation

postgresql.ungram confirms:

```
NotNullConstraint =
  ('constraint' NameRef)
  'not' 'null'
  NoInherit
```

### Cardinality Note

The grammar shows `NoInherit` without a `?`, suggesting it is unconditionally
present in the parse tree for this rule. The Rust accessor nonetheless returns
`Option<NoInherit>` — this is standard for this AST style (rowan-pattern
accessors are `Option<T>` regardless of grammar-level required/optional
status, since the tree node may still be absent due to parse errors or
partial trees). This is not treated as a discrepancy requiring further
investigation; it is the normal pattern observed throughout this AST.

### Meaning

Represents:

```sql
col_name type NOT NULL [NO INHERIT]
[CONSTRAINT name] NOT NULL ... NO INHERIT  -- with explicit constraint name
```

`NO INHERIT` prevents the NOT NULL constraint from being inherited by child
tables in traditional table inheritance (not partitioning).

### safe-migrate guidance

```rust
NotNullConstraintFact {
    name: Option<String>,    // from name_ref()
    no_inherit: bool,        // from no_inherit().is_some()
}
```

---

## PrimaryKeyConstraint

### Verified Accessors

```rust
pub fn column_list(&self) -> Option<ColumnList>
pub fn constraint_name(&self) -> Option<ConstraintName>
pub fn partition_item_list(&self) -> Option<PartitionItemList>
pub fn using_index(&self) -> Option<UsingIndex>
pub fn key_token(&self) -> Option<SyntaxToken>
pub fn primary_token(&self) -> Option<SyntaxToken>
```

### safe-migrate guidance

```rust
PrimaryKeyFact {
    name: Option<String>,
    columns: Vec<String>,
    using_index: Option<String>,
}
```

---

## UniqueConstraint

### Verified Accessors

```rust
pub fn column_list(&self) -> Option<ColumnList>
pub fn constraint_name(&self) -> Option<ConstraintName>
pub fn nulls_distinct(&self) -> Option<NullsDistinct>
pub fn nulls_not_distinct(&self) -> Option<NullsNotDistinct>
pub fn using_index(&self) -> Option<UsingIndex>
pub fn unique_token(&self) -> Option<SyntaxToken>
```

### safe-migrate guidance

```rust
UniqueConstraintFact {
    name: Option<String>,
    columns: Vec<String>,
    nulls_distinct: NullsDistinctState,
    using_index: Option<String>,
}
```

`NullsDistinctState` should be a three-way enum: `Distinct`, `NotDistinct`, `Unspecified`.

---

# Foreign Key Constraints

## ForeignKeyConstraint

### Verified Accessors — Generated (line 9573)

```rust
pub fn constraint_name(&self) -> Option<ConstraintName>
pub fn match_type(&self) -> Option<MatchType>
pub fn on_delete_action(&self) -> Option<OnDeleteAction>
pub fn on_update_action(&self) -> Option<OnUpdateAction>
pub fn path(&self) -> Option<Path>           // referenced table
pub fn foreign_token(&self) -> Option<SyntaxToken>
pub fn key_token(&self) -> Option<SyntaxToken>
pub fn references_token(&self) -> Option<SyntaxToken>
```

### Verified Accessors — Handwritten (line 38440)

```rust
pub fn from_columns(&self) -> Option<ast::ColumnList>  // local columns, nth(0)
pub fn to_columns(&self) -> Option<ast::ColumnList>    // referenced columns, nth(1)
```

### Findings

Complete FK mapping is available:

- local table: from the containing `AlterTable` or `CreateTable` context
- local columns: `from_columns()`
- referenced table: `path()`
- referenced columns: `to_columns()`
- match type: `match_type()`
- on delete: `on_delete_action()`
- on update: `on_update_action()`

### safe-migrate guidance

```rust
ForeignKeyFact {
    name: Option<String>,
    local_columns: Vec<String>,
    referenced_table: QualifiedName,
    referenced_columns: Vec<String>,
    match_type: MatchType,
    on_delete: ReferentialAction,
    on_update: ReferentialAction,
}
```

---

## ReferencesConstraint

### Verified Accessors (line 14729)

```rust
pub fn column(&self) -> Option<NameRef>              // single referenced column
pub fn constraint_name(&self) -> Option<ConstraintName>
pub fn match_type(&self) -> Option<MatchType>
pub fn on_delete_action(&self) -> Option<OnDeleteAction>
pub fn on_update_action(&self) -> Option<OnUpdateAction>
pub fn table(&self) -> Option<Path>                  // referenced table
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
pub fn references_token(&self) -> Option<SyntaxToken>
```

### Meaning

Column-level inline references form:

```sql
user_id bigint REFERENCES users(id) ON DELETE CASCADE
```

### Important Distinction

`column()` returns a single `NameRef`, not a list.
This is the inline column-level form only.
Table-level multi-column FKs use `ForeignKeyConstraint`.

### safe-migrate guidance

Normalize into the same `ForeignKeyFact` representation used by `ForeignKeyConstraint`.
Local column comes from the containing `Column` node.
Referenced column comes from `column()`.

---

## ReferencesTable

### Verified Accessors (line 14765)

```rust
pub fn column_list(&self) -> Option<ColumnList>
pub fn name_ref(&self) -> Option<NameRef>
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
pub fn references_token(&self) -> Option<SyntaxToken>
```

### Meaning

Standalone references-to-table node appearing in edge table definitions
(property graph context).

### Grammar Confirmation — RESOLVED

postgresql.ungram confirms:

```
ReferencesTable =
  'references' NameRef '(' ColumnList ')'

SourceVertexTable =
  'source' NameRef
| 'source' 'key' '(' ColumnList ')' ReferencesTable

DestVertexTable =
  'destination' NameRef
| 'destination' 'key' '(' ColumnList ')' ReferencesTable
```

`ReferencesTable` is exclusively used by `SourceVertexTable` and `DestVertexTable`
in the SQL/PGQ property graph grammar (`CREATE PROPERTY GRAPH`). It has no
relationship to `ForeignKeyConstraint` or `ReferencesConstraint` whatsoever —
these are entirely separate grammar features that happen to share similar
naming. Property graphs are out of scope for safe-migrate's table/column/index
safety analysis.

### Status

```
Grammar verified — RESOLVED
Confirmed unrelated to ForeignKeyConstraint/ReferencesConstraint.
Used exclusively in CREATE PROPERTY GRAPH vertex/edge table definitions.
```

---

# ExcludeConstraint

## ExcludeConstraint

### Verified Accessors (line 9112)

```rust
pub fn constraint_exclusion_list(&self) -> Option<ConstraintExclusionList>
pub fn constraint_index_method(&self) -> Option<ConstraintIndexMethod>
pub fn constraint_name(&self) -> Option<ConstraintName>
pub fn where_condition_clause(&self) -> Option<WhereConditionClause>
pub fn exclude_token(&self) -> Option<SyntaxToken>
```

### Membership

- Member of `ColumnConstraint` (line 19478)
- Member of `TableConstraint` (line 19939)

### Child: ConstraintExclusionList

```rust
// line 3897
pub fn constraint_exclusions(&self) -> AstChildren<ConstraintExclusion>
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
```

### Child: ConstraintExclusion (individual element, line 3878)

```rust
pub fn expr(&self) -> Option<Expr>    // the excluded expression
pub fn op(&self) -> Option<Op>        // the WITH operator
pub fn with_token(&self) -> Option<SyntaxToken>
```

### Child: ConstraintIndexMethod (line 3927)

```rust
pub fn using_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation — RESOLVED

postgresql.ungram confirms:

```
ConstraintIndexMethod =
  'using'
```

This is the complete grammar rule — only the `USING` keyword token exists.
The index method name (e.g. `gist`, `btree`) genuinely is not part of this
node's grammar at all. This is not an accessor gap; it is confirmed that
`EXCLUDE USING method (...)` does not capture `method` as structured content
on `ConstraintIndexMethod` in this grammar version.

### Child: WhereConditionClause (line 18507)

```rust
pub fn expr(&self) -> Option<Expr>
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
pub fn where_token(&self) -> Option<SyntaxToken>
```

WHERE predicate expression is fully accessible.

### safe-migrate guidance

```rust
ExcludeConstraintFact {
    name: Option<String>,
    exclusions: Vec<ExclusionElement>,
    index_method: Option<String>,   // NOT extractable — ConstraintIndexMethod is grammar-confirmed empty
    where_expr: Option<ExprIr>,
}

struct ExclusionElement {
    expr: ExprIr,
    operator: OpIr,
}
```

---

# Additional Constraint Supporting Nodes

## ConstraintIncludeClause

### Verified Accessors (line 3916)

```rust
pub fn include_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation — RESOLVED

postgresql.ungram confirms:

```
ConstraintIncludeClause =
  'include'
```

This is the complete grammar rule — only the `INCLUDE` keyword token exists.
The included column list genuinely is not part of this node's grammar.
This is not an accessor gap; `INCLUDE (col1, col2)` does not capture the
column list as structured content on `ConstraintIncludeClause` in this
grammar version. If the column list is captured anywhere, it would need to
be a sibling node, not a child of `ConstraintIncludeClause` itself — not
confirmed in this pass.

### Status

```
Grammar verified — FULLY RESOLVED
INCLUDE column list confirmed absent from the grammar entirely.
CreateIndex grammar: 'create' ... PartitionItemList ConstraintIncludeClause? ...
No sibling column-list node exists adjacent to ConstraintIncludeClause in
CreateIndex either. The INCLUDE column list in CREATE INDEX ... INCLUDE (cols)
is not captured anywhere in this AST grammar.
```
```

---

## ConstraintIndexTablespace

### Verified Accessors (line 3938)

```rust
pub fn name_ref(&self) -> Option<NameRef>
pub fn index_token(&self) -> Option<SyntaxToken>
pub fn tablespace_token(&self) -> Option<SyntaxToken>
pub fn using_token(&self) -> Option<SyntaxToken>
```

---

# DefaultConstraint

### Verified Membership

- Member of `Constraint` enum
- Member of `ColumnConstraint` enum

### Verified Accessors (line 6292)

```rust
pub fn expr(&self) -> Option<Expr>
pub fn name_ref(&self) -> Option<NameRef>
pub fn constraint_token(&self) -> Option<SyntaxToken>
pub fn default_token(&self) -> Option<SyntaxToken>
```

### safe-migrate guidance

```rust
DefaultConstraintFact {
    name: Option<String>,   // from name_ref()
    expression: ExprIr,     // from expr()
}
```

Expression must flow into ExprIr for rule evaluation.

---

# GeneratedConstraint

### Verified Membership

- Member of `Constraint` enum only

### Verified Accessors (line 9785)

```rust
pub fn expr(&self) -> Option<Expr>
pub fn name_ref(&self) -> Option<NameRef>
pub fn sequence_option_list(&self) -> Option<SequenceOptionList>
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
pub fn always_token(&self) -> Option<SyntaxToken>
pub fn as_token(&self) -> Option<SyntaxToken>
pub fn by_token(&self) -> Option<SyntaxToken>
pub fn constraint_token(&self) -> Option<SyntaxToken>
pub fn default_token(&self) -> Option<SyntaxToken>
pub fn generated_token(&self) -> Option<SyntaxToken>
pub fn identity_token(&self) -> Option<SyntaxToken>
pub fn stored_token(&self) -> Option<SyntaxToken>
```

### Meaning

Covers two PostgreSQL forms:

```sql
-- computed column
col type GENERATED ALWAYS AS (expr) STORED

-- identity column
col type GENERATED ALWAYS AS IDENTITY (sequence_options)
col type GENERATED BY DEFAULT AS IDENTITY (sequence_options)
```

Distinguishing between these two forms requires checking:
- `stored_token()` present → computed column form
- `identity_token()` present → identity column form
- `always_token()` vs `default_token()` → ALWAYS vs BY DEFAULT

### safe-migrate guidance

```rust
GeneratedConstraintFact {
    name: Option<String>,
    kind: GeneratedKind,    // Computed | IdentityAlways | IdentityByDefault
    expr: Option<ExprIr>,   // present for computed form
    sequence_options: Option<SequenceOptionsFact>, // present for identity form
}
```

---

# Column Constraint Sources

## Column

### Verified Accessors

```rust
pub fn constraints(&self) -> AstChildren<ColumnConstraint>
pub fn name(&self) -> Option<Name>
pub fn name_ref(&self) -> Option<NameRef>
pub fn ty(&self) -> Option<Type>
pub fn field_expr(&self) -> Option<FieldExpr>
pub fn index_expr(&self) -> Option<IndexExpr>
pub fn collate(&self) -> Option<Collate>
pub fn compression_method(&self) -> Option<CompressionMethod>
pub fn storage(&self) -> Option<Storage>
pub fn with_options(&self) -> Option<WithOptions>
pub fn period_token(&self) -> Option<SyntaxToken>
```

### safe-migrate guidance

```rust
ColumnFact {
    name: String,
    type_name: TypeIr,
    constraints: Vec<ColumnConstraintFact>,
}
```

Column identity must be preserved when extracting inline constraints.

---

## AddColumn

### Verified Accessors

```rust
pub fn constraints(&self) -> AstChildren<Constraint>
pub fn if_not_exists(&self) -> Option<IfNotExists>
pub fn name(&self) -> Option<Name>
pub fn ty(&self) -> Option<Type>
pub fn add_token(&self) -> Option<SyntaxToken>
pub fn column_token(&self) -> Option<SyntaxToken>
```

### Note

`AddColumn.constraints()` returns `AstChildren<Constraint>` not `AstChildren<ColumnConstraint>`.
This is a verified difference from `Column.constraints()`.

---

## DropColumn

### Verified Accessors

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn name_ref(&self) -> Option<NameRef>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn column_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn restrict_token(&self) -> Option<SyntaxToken>
```

### safe-migrate guidance

Dependency-aware column removal. CASCADE must propagate through the dependency graph
to all constraints referencing the dropped column.

---

# Verified Findings Summary

## Confirmed Complete

- `Constraint` enum: all 9 members verified
- `ColumnConstraint` enum: all 7 members verified
- `TableConstraint` enum: all 5 members verified
- `ForeignKeyConstraint`: fully resolved including handwritten `from_columns()` / `to_columns()`
- `ReferencesConstraint`: fully resolved
- `ExcludeConstraint`: fully resolved including child nodes
- `PrimaryKeyConstraint`: fully resolved
- `UniqueConstraint`: fully resolved
- `CheckConstraint`: fully resolved
- `DefaultConstraint`: fully resolved
- `GeneratedConstraint`: fully resolved
- `AddConstraint`: fully resolved
- `DropConstraint`: fully resolved
- `RenameConstraint`: fully resolved
- `ValidateConstraint`: fully resolved
- `Column`: fully resolved
- `AddColumn`: fully resolved
- `DropColumn`: fully resolved

## Confirmed Partial

- `AlterConstraint`: grammar-confirmed dispatch through AlterColumnOption, constraint name not on this node
- `ConstraintIncludeClause`: node verified, column list inaccessible through verified accessors
- `ConstraintIndexMethod`: node verified, method name string inaccessible through verified accessors
- `ReferencesTable`: grammar-confirmed, unrelated to FK nodes — property graph only

---

# Remaining Open Questions

None remaining. All four previously listed questions have been resolved:

1. The `AlterConstraint` constraint-name location has been confirmed as a
   final grammar limitation (no sibling node anywhere carries it) — see the
   AlterConstraint section above.
2. `ConstraintIncludeClause`'s column list has been confirmed grammar-empty
   — see the ConstraintIncludeClause section above.
3. `ConstraintIndexMethod`'s method name has been confirmed grammar-empty
   — see the ConstraintIndexMethod section above.
4. The standing caveat about additional handwritten extensions is addressed
   by the exhaustive `impl ast::*` inventory established in columns.md
   (lines 38145-39260 of squawk.rs), which covers the full handwritten
   extension surface for every node type, including all constraint nodes.
   No additional handwritten extensions beyond that inventory were found
   for any constraint type.
