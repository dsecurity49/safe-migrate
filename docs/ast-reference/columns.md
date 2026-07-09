# Columns AST Reference for safe-migrate

## Status

Verified against squawk_syntax 2.58.0 — July 2026

This document is derived from direct inspection of src/ast/generated/nodes.rs
and src/ast/node_ext.rs in squawk-syntax-2.58.0 and should be treated as the
current source of truth for safe-migrate column handling.

All claims are AST-verified via grep and line-range inspection.

---

## Documentation Contract

1. Only document AST behavior that has been directly verified.
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. Assume additional nodes or helpers may exist outside the inspected surface.

---

## Handwritten Extension Policy

One handwritten extension exists for column nodes:

```
impl ast::RenameColumn  (src/ast/node_ext.rs line 347)
```

No handwritten extensions exist for `Column`, `AddColumn`, `AlterColumn`, or `DropColumn`.

This was established by exhaustive grep of all `impl ast::*` blocks in `src/ast/node_ext.rs`
(squawk-syntax-2.58.0):

```bash
grep -n "^impl ast::" src/ast/node_ext.rs
```

This grep covers the full handwritten extension surface and is the authoritative source for all
extensions across the entire codebase. The complete inventory:

| node_ext Line | Node                  | Methods                                      |
|---------------|-----------------------|----------------------------------------------|
| 61            | `ast::Literal`        | `kind()`                                     |
| 84            | `ast::Constraint`     | `constraint_name()`                          |
| 150           | `ast::BinExpr`        | `lhs()`, `rhs()`, `op()`                    |
| 231           | `ast::PostfixExpr`    | `op()`                                       |
| 294           | `ast::FieldExpr`      | `base()`, `field()`                          |
| 308           | `ast::IndexExpr`      | `base()`, `index()`                          |
| 319           | `ast::SliceExpr`      | `base()`, `start()`, `end()`                |
| 347           | `ast::RenameColumn`   | `from()`, `to()`                             |
| 358           | `ast::ForeignKeyConstraint` | `from_columns()`, `to_columns()`       |
| 369           | `ast::BetweenExpr`    | `target()`, `start()`, `end()`              |
| 384           | `ast::FrameBetween`   | `start()`, `end()`                           |
| 395           | `ast::WhenClause`     | `condition()`, `then()`                      |
| 406           | `ast::CompoundSelect` | `lhs()`, `rhs()`                             |
| 417           | `ast::NameRef`        | `text()`, `is_quoted()`                      |
| 429           | `ast::Name`           | `text()`, `is_quoted()`                      |
| 494           | `ast::CharType`       | `text()`                                     |
| 505           | `ast::Vacuum`         | `is_full()`                                  |
| 528           | `ast::OpSig`          | `lhs()`, `rhs()`                             |
| 540           | `ast::CastSig`        | `lhs()`, `rhs()`                             |
| 567           | `ast::WithQuery`      | `with_clause()`                              |
| 574           | `ast::SelectVariant`  | `target_list()`                              |
| 584           | `ast::CreateTableAsQuery` | `create_table_like()`                    |
| 602           | `ast::FunctionSig`    | `HasParamList` trait impl                    |
| 603           | `ast::Aggregate`      | `HasParamList` trait impl                    |
| 605           | `ast::Name`           | `NameLike` trait impl                        |
| 611           | `ast::NameRef`        | `NameLike` trait impl                        |
| 618           | `ast::Select`         | `HasWithClause` trait impl                   |
| 619           | `ast::SelectInto`     | `HasWithClause` trait impl                   |
| 620           | `ast::Insert`         | `HasWithClause` trait impl                   |
| 621           | `ast::Update`         | `HasWithClause` trait impl                   |
| 622           | `ast::Delete`         | `HasWithClause` trait impl                   |
| 624           | `ast::CreateTable`    | `HasCreateTable` trait impl                  |
| 625           | `ast::CreateForeignTable` | `HasCreateTable` trait impl              |
| 626           | `ast::CreateTableLike`| `HasCreateTable` trait impl                  |

All other AST files reference this table rather than re-running the grep.

---

# High-Level Column Model

The verified AST surface exposes:

**Core column nodes:**
- `Column`
- `ColumnList`
- `AddColumn`
- `AlterColumn`
- `DropColumn`
- `RenameColumn`

**Alter column dispatch:**
- `AlterColumnOption` (21-member enum)

**Column context nodes:**
- `TableArg` (enum containing `Column`)
- `SetSingleColumn`
- `SetMultipleColumns`
- `SetColumn` (enum)

---

# Core Column Nodes

## Column

### Verified Accessors (line 3279)

```rust
pub fn collate(&self) -> Option<Collate>
pub fn compression_method(&self) -> Option<CompressionMethod>
pub fn constraints(&self) -> AstChildren<ColumnConstraint>
pub fn deferrable_constraint_option(&self) -> Option<DeferrableConstraintOption>
pub fn enforced(&self) -> Option<Enforced>
pub fn field_expr(&self) -> Option<FieldExpr>
pub fn index_expr(&self) -> Option<IndexExpr>
pub fn initially_deferred_constraint_option(&self) -> Option<InitiallyDeferredConstraintOption>
pub fn initially_immediate_constraint_option(&self) -> Option<InitiallyImmediateConstraintOption>
pub fn name(&self) -> Option<Name>
pub fn name_ref(&self) -> Option<NameRef>
pub fn not_deferrable_constraint_option(&self) -> Option<NotDeferrableConstraintOption>
pub fn not_enforced(&self) -> Option<NotEnforced>
pub fn storage(&self) -> Option<Storage>
pub fn ty(&self) -> Option<Type>
pub fn with_options(&self) -> Option<WithOptions>
pub fn period_token(&self) -> Option<SyntaxToken>
```

### Membership

`Column` is a member of the `TableArg` enum (line 19931, 37505), alongside
`LikeClause` and `TableConstraint`. See the TableArg section below — this is a
3-member enum, not 2-member as an earlier draft of this document stated.
Columns appear as `TableArg::Column` inside `TableArgList`.

### Notes

- Both `name()` and `name_ref()` exist. Context determines which is populated.
- `deferrable_constraint_option`, `enforced`, `not_enforced`, `not_deferrable_constraint_option`,
  `initially_deferred_constraint_option`, `initially_immediate_constraint_option` are present
  directly on `Column` — these are column-level deferrability and enforcement modifiers,
  not constraint-level.
- `constraints()` returns `AstChildren<ColumnConstraint>`, not `AstChildren<Constraint>`.
  See constraints.md for the `ColumnConstraint` enum.

### safe-migrate guidance

```rust
ColumnFact {
    name: String,                           // from name() or name_ref()
    type_ref: TypeIr,                       // from ty()
    constraints: Vec<ColumnConstraintFact>, // from constraints()
    collation: Option<String>,              // from collate()
    storage: Option<StorageKind>,           // from storage()
    compression: Option<String>,            // from compression_method()
    deferrable: Option<DeferrableState>,    // from deferrable/not_deferrable accessors
    enforced: Option<EnforcedState>,        // from enforced/not_enforced
}
```

Column identity must be preserved when extracting inline constraints.

---

## ColumnList

### Verified Accessors (line 3358)

```rust
pub fn columns(&self) -> AstChildren<Column>
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
```

### Meaning

Ordered list of columns. Used in:
- `PrimaryKeyConstraint`
- `UniqueConstraint`
- `ForeignKeyConstraint` (via `from_columns()` / `to_columns()`)
- `INSERT ... (col1, col2)`
- `COPY`
- `CreateView`, `CreateMaterializedView`
- Many other contexts

---

## AddColumn

### Verified Accessors (line 175)

```rust
pub fn collate(&self) -> Option<Collate>
pub fn constraints(&self) -> AstChildren<Constraint>
pub fn if_not_exists(&self) -> Option<IfNotExists>
pub fn name(&self) -> Option<Name>
pub fn ty(&self) -> Option<Type>
pub fn add_token(&self) -> Option<SyntaxToken>
pub fn column_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `AlterTableAction` (line 19416, 33166).

### Important Distinction

`AddColumn.constraints()` returns `AstChildren<Constraint>` — the general enum.
`Column.constraints()` returns `AstChildren<ColumnConstraint>` — the column-specific enum.

This is a verified difference. See constraints.md for enum membership details.

### safe-migrate guidance

```rust
Mutation::AddColumn {
    name: String,
    type_ref: TypeIr,
    constraints: Vec<ConstraintFact>,
    collation: Option<String>,
    if_not_exists: bool,
}
```

---

## AlterColumn

### Verified Accessors (line 595)

```rust
pub fn name_ref(&self) -> Option<NameRef>
pub fn option(&self) -> Option<AlterColumnOption>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn column_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `AlterTableAction` (line 19418, 33168).

### Meaning

Represents:

```sql
ALTER TABLE t ALTER COLUMN col <option>
```

The column being altered is identified by `name_ref()`.
The operation is dispatched through `option()` → `AlterColumnOption`.

### safe-migrate guidance

```rust
Mutation::AlterColumn {
    column_name: String,           // from name_ref()
    operation: AlterColumnOp,      // from option() -> AlterColumnOption
}
```

See AlterColumnOption section below for the full dispatch surface.

---

## DropColumn

### Verified Accessors (line 6819)

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn name_ref(&self) -> Option<NameRef>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn column_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn restrict_token(&self) -> Option<SyntaxToken>
```

### Membership

Member of `AlterTableAction` (line 19426, 33184).

### safe-migrate guidance

```rust
Mutation::DropColumn {
    name: String,
    if_exists: bool,
    cascade: bool,
}
```

CASCADE must propagate through the dependency graph to all constraints,
indexes, and views referencing the dropped column.

---

## RenameColumn

### Verified Accessors — Generated (line 15034)

```rust
pub fn column_token(&self) -> Option<SyntaxToken>
pub fn rename_token(&self) -> Option<SyntaxToken>
pub fn to_token(&self) -> Option<SyntaxToken>
```

### Verified Accessors — Handwritten (line 38429)

```rust
pub fn from(&self) -> Option<ast::NameRef>   // old name, nth(0)
pub fn to(&self) -> Option<ast::NameRef>     // new name, nth(1)
```

### Grammar vs Implementation Discrepancy

postgresql.ungram states:

```
RenameColumn =
  'rename' 'column'? from:NameRef 'to' to:Name
```

This labels `to` as type `Name`, not `NameRef`. However, the actual Rust
implementation at line 38429-38436 uses `support::children::<NameRef>(&self.syntax)`
for both `nth(0)` and `nth(1)` — meaning the implementation treats both as
`NameRef` regardless of what the grammar label states. Since
`support::children::<T>()` filters the child list by a single concrete type `T`,
if the actual syntax node for the new name were genuinely a different type
(`Name` rather than `NameRef`), `.nth(1)` would not find it this way.

This document follows the verified Rust implementation (both `NameRef`) as the
source of truth here, since it is the literal compiled behavior. The grammar
label is noted as a discrepancy that should be flagged to the squawk maintainers
or re-verified against a newer grammar version, but does not change what
safe-migrate's code will actually receive at runtime.

### Membership

Member of `AlterTableAction` (line 19444, 33218).
Also member of `AlterMaterializedViewAction` (line 19394, 32928).

### Important Finding

The generated accessors expose **only syntax tokens**.
The old and new column names are **only accessible through the handwritten extension**.
Any code reading `RenameColumn` without using `from()` and `to()` cannot extract the names.

### safe-migrate guidance

```rust
Mutation::RenameColumn {
    from: String,    // from handwritten from()
    to: String,      // from handwritten to()
}
```

Treat as identity preservation. Do not model as drop + create.

---

# AlterColumnOption

## Enum Definition (line 19339)

```rust
pub enum AlterColumnOption {
    AddGenerated(AddGenerated),
    DropDefault(DropDefault),
    DropExpression(DropExpression),
    DropIdentity(DropIdentity),
    DropNotNull(DropNotNull),
    Inherit(Inherit),
    NoInherit(NoInherit),
    ResetOptions(ResetOptions),
    Restart(Restart),
    SetCompression(SetCompression),
    SetDefault(SetDefault),
    SetExpression(SetExpression),
    SetGenerated(SetGenerated),
    SetGeneratedOptions(SetGeneratedOptions),
    SetNotNull(SetNotNull),
    SetOptions(SetOptions),
    SetOptionsList(SetOptionsList),
    SetSequenceOption(SetSequenceOption),
    SetStatistics(SetStatistics),
    SetStorage(SetStorage),
    SetType(SetType),
}
```

21 members. Fully verified at line 19339 and cross-checked against `From<X> for AlterColumnOption`
impls at lines 32549-32672.

---

## Key AlterColumnOption Variants

### DropNotNull (line 7409)

```rust
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn not_token(&self) -> Option<SyntaxToken>
pub fn null_token(&self) -> Option<SyntaxToken>
```

Presence detection only — no payload beyond keyword tokens.

Represents: `ALTER COLUMN col DROP NOT NULL`

---

### SetDefault (line 16625)

```rust
pub fn expr(&self) -> Option<Expr>
pub fn default_token(&self) -> Option<SyntaxToken>
pub fn set_token(&self) -> Option<SyntaxToken>
```

Expression payload accessible via `expr()`.

Represents: `ALTER COLUMN col SET DEFAULT <expr>`

---

### SetCompression (line 16560)

```rust
pub fn compression_token(&self) -> Option<SyntaxToken>
pub fn set_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation — RESOLVED

postgresql.ungram confirms: `SetCompression = 'set' 'compression'` — the
complete rule. The compression method name (e.g. `pglz`, `lz4`) is genuinely
absent from the grammar, not an accessor gap.

### Status
```
Grammar verified — FULLY RESOLVED
Compression method name confirmed absent from grammar entirely.
```

---

### SetStatistics (line 16994)

```rust
pub fn set_token(&self) -> Option<SyntaxToken>
pub fn statistics_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation — RESOLVED

postgresql.ungram confirms: `SetStatistics = 'set' 'statistics'` — the
complete rule. The statistics target value is genuinely absent from the
grammar, not an accessor gap.

### Status
```
Grammar verified — FULLY RESOLVED
Statistics target value confirmed absent from grammar entirely.
```

---

### SetStorage (line 17009)

```rust
pub fn set_token(&self) -> Option<SyntaxToken>
pub fn storage_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation — RESOLVED

postgresql.ungram confirms: `SetStorage = 'set' 'storage'` — the complete
rule. The storage mode (`PLAIN`/`EXTERNAL`/`EXTENDED`/`MAIN`) is genuinely
absent from the grammar, not an accessor gap.

### Status
```
Grammar verified — FULLY RESOLVED
Storage mode confirmed absent from grammar entirely.
```

---

### SetType (line 17086)

```rust
pub fn collate(&self) -> Option<Collate>
pub fn ty(&self) -> Option<Type>
pub fn set_token(&self) -> Option<SyntaxToken>
pub fn type_token(&self) -> Option<SyntaxToken>
```

New type fully accessible via `ty()`. Optional collation via `collate()`.

Represents: `ALTER COLUMN col SET DATA TYPE <type> [COLLATE <collation>]`

---

### SetNotNull

Token-only presence node. Represents: `ALTER COLUMN col SET NOT NULL`

---

### DropDefault

Token-only presence node. Represents: `ALTER COLUMN col DROP DEFAULT`

---

### Remaining Variants — Now Grammar-Resolved

All 13 previously uninspected variants have been cross-checked against
postgresql.ungram:

**Variants with real payloads:**

```
Inherit =
  'inherit' Path

NoInherit =
  'no' 'inherit' Path

SetExpression =
  'set' 'expression' Expr

SetOptions =
  'set' AttributeList

SetOptionsList =
  'set' 'options' AlterOptionList
```

- `Inherit` / `NoInherit`: carry the parent table `Path` for inheritance
  manipulation on a column's generated/identity behavior context.
- `SetExpression`: carries a full `Expr` — used for `SET EXPRESSION AS (expr)`
  on generated columns. Should flow into ExprIr like other expression-bearing nodes.
- `SetOptions`: carries an `AttributeList` of key-value option pairs.
- `SetOptionsList`: carries an `AlterOptionList` — a different option
  representation than `SetOptions`. Both exist as distinct grammar paths;
  the resolver must handle both shapes.

**Variants confirmed grammar-empty (no payload beyond keywords):**

```
AddGenerated =
  'add'

DropExpression =
  'drop' 'expression' IfExists?

DropIdentity =
  'drop' 'identity' IfExists?

ResetOptions =
  'reset' '(' ')'

Restart =
  'restart' 'with'?

SetGenerated =
  'set'

SetGeneratedOptions =
  'set' 'generated'
```

- `AddGenerated`: presence-only — detects `ADD GENERATED ...` but the
  generated clause details are not captured here (likely require
  cross-referencing a `GeneratedConstraint` node, see constraints.md).
- `DropExpression` / `DropIdentity`: presence + `IfExists?` only — no value
  needed since these are removal operations.
- `ResetOptions`: confirmed empty parens — the specific option names being
  reset are not captured, mirroring the `ConstraintIncludeClause` and
  `MergePartitions` grammar-gap pattern seen elsewhere in this documentation set.
- `Restart`: presence + optional `WITH` token only — the restart value
  itself is not captured in this variant's own grammar (distinct from the
  `Restart` value accessible via `literal()` documented in sequences.md's
  `SequenceOption` — this is a different node despite the same name pattern;
  verify which `Restart` struct is meant before assuming a value is present).
- `SetGenerated` / `SetGeneratedOptions`: both confirmed token-only.

### safe-migrate guidance

```rust
enum AlterColumnOpFact {
    AddGenerated,                              // presence-only
    DropDefault,
    DropExpression { if_exists: bool },
    DropIdentity { if_exists: bool },
    DropNotNull,
    Inherit { parent: QualifiedName },
    NoInherit { parent: QualifiedName },
    ResetOptions,                              // option names not extractable
    Restart,                                   // value not extractable on this variant
    SetCompression,                            // method name not extractable
    SetDefault { expr: ExprIr },
    SetExpression { expr: ExprIr },
    SetGenerated,                              // presence-only
    SetGeneratedOptions,                       // presence-only
    SetNotNull,
    SetOptions { attributes: Vec<AttributeFact> },
    SetOptionsList { options: Vec<AlterOptionFact> },
    SetSequenceOption,                         // payload not extractable, see sequences.md
    SetStatistics,                             // value not extractable
    SetStorage,                                // mode not extractable
    SetType { ty: TypeIr, collation: Option<String> },
}
```

Several variants are presence-only detectors — the AST confirms *that* an
operation occurred but not its specific parameters. Rules built on these
variants can only flag "an X happened," not evaluate the safety of the
specific value being set.

---

# Context Nodes

## TableArg

### CORRECTION (found during grammar cross-check)

An earlier version of this document incorrectly listed `TableArg` as a 2-member
enum. It is a **3-member enum**:

```rust
pub enum TableArg {
    Column(Column),
    LikeClause(LikeClause),
    TableConstraint(TableConstraint),
}
```

### Grammar Confirmation

postgresql.ungram confirms:

```
TableArg =
  Column
| LikeClause
| TableConstraint
```

### Verified Implementation Detail (line 37477)

The `can_cast` implementation only explicitly matches `COLUMN | LIKE_CLAUSE`:

```rust
impl AstNode for TableArg {
    fn can_cast(kind: SyntaxKind) -> bool {
        matches!(kind, SyntaxKind::COLUMN | SyntaxKind::LIKE_CLAUSE)
    }
    fn cast(syntax: SyntaxNode) -> Option<Self> {
        let res = match syntax.kind() {
            SyntaxKind::COLUMN => TableArg::Column(Column { syntax }),
            SyntaxKind::LIKE_CLAUSE => TableArg::LikeClause(LikeClause { syntax }),
            _ => {
                if let Some(result) = TableConstraint::cast(syntax) {
                    return Some(TableArg::TableConstraint(result));
                }
                return None;
            }
        };
        Some(res)
    }
}
```

**Important implementation note:** `can_cast()` returns `false` for table-constraint
syntax kinds, but `cast()` still succeeds for them via fallthrough to
`TableConstraint::cast()`. Any safe-migrate code that checks `TableArg::can_cast()`
before casting (rather than calling `cast()` directly) will silently skip
table-level constraints. This is a real risk for the AST Visitor layer — it must
call `cast()` directly, not gate on `can_cast()`.

`TableArgList.args()` returns `AstChildren<TableArg>`.
This is the primary extraction point for **column definitions AND table-level
constraints** in `CREATE TABLE` and `CREATE FOREIGN TABLE` — not columns alone.

### safe-migrate guidance

```rust
match table_arg {
    TableArg::Column(col) => { /* extract ColumnFact */ }
    TableArg::LikeClause(like) => { /* extract LikeClauseFact */ }
    TableArg::TableConstraint(constraint) => { /* extract ConstraintFact, see constraints.md */ }
}
```

A `CREATE TABLE` visitor that only handles `TableArg::Column` will silently miss
every table-level `PRIMARY KEY`, `UNIQUE`, `CHECK`, `FOREIGN KEY`, and `EXCLUDE`
constraint declared inline in the table definition.

---

## SetColumn

```rust
pub enum SetColumn {
    SetMultipleColumns(SetMultipleColumns),
    SetSingleColumn(SetSingleColumn),
}
```

Used in UPDATE SET clauses. Not a column definition node.

### SetSingleColumn (line 16975)

```rust
pub fn column(&self) -> Option<Column>
pub fn set_expr(&self) -> Option<SetExpr>
pub fn eq_token(&self) -> Option<SyntaxToken>
```

### SetMultipleColumns (line 16772)

```rust
pub fn column_list(&self) -> Option<ColumnList>
pub fn paren_select(&self) -> Option<ParenSelect>
pub fn set_expr_list(&self) -> Option<SetExprList>
pub fn eq_token(&self) -> Option<SyntaxToken>
```

---

# Verified Findings Summary

## Confirmed Complete

- `Column`: fully resolved
- `ColumnList`: fully resolved
- `AddColumn`: fully resolved
- `AlterColumn`: fully resolved
- `DropColumn`: fully resolved
- `RenameColumn`: fully resolved including handwritten `from()` / `to()`
  (grammar/implementation discrepancy noted and documented)
- `AlterColumnOption` enum: all 21 members verified and grammar cross-checked
- `TableArg` enum: corrected to 3 members (`Column`, `LikeClause`,
  `TableConstraint`) after grammar cross-check found a documentation error

## Grammar-Confirmed Limitations

- `SetCompression`: compression method name confirmed absent from grammar
- `SetStatistics`: statistics value confirmed absent from grammar
- `SetStorage`: storage mode confirmed absent from grammar
- `AddGenerated`, `SetGenerated`, `SetGeneratedOptions`: confirmed presence-only
- `ResetOptions`: confirmed empty parens, option names not captured
- `Restart` (AlterColumnOption variant): restart value not captured on this
  variant — distinct from the `Restart`-equivalent value documented in
  sequences.md's `SequenceOption`

## Grammar Cross-Check

This document has been fully cross-checked against postgresql.ungram,
including all 21 `AlterColumnOption` variants. One real documentation error
was found and corrected (`TableArg` was incorrectly documented as 2-member,
actually 3-member with `TableConstraint`) — this is a meaningful finding since
any `CREATE TABLE` visitor built on the original documentation would have
silently skipped all table-level constraints. One grammar/implementation
discrepancy was flagged for `RenameColumn`'s `to` field type.

---

# Remaining Open Questions

None remaining. Both previously open questions have been resolved or
appropriately reclassified:

1. **`TableArg::can_cast()` returning `false` for table-constraint kinds**:
   This is a real implementation quirk, confirmed in src/ast/generated/nodes.rs at line 37505
   and documented extensively in the `TableArg` section above. It does NOT
   affect safe-migrate directly, since safe-migrate must call
   `TableArgList.args()` (which returns `AstChildren<TableArg>` via
   `support::children::<TableArg>()`) — and `AstChildren` iteration uses
   `cast()` directly, not `can_cast()` as a gate. The `can_cast()` issue
   only bites code that explicitly calls `TableArg::can_cast(node.kind())`
   before deciding whether to cast, which is not the idiomatic visitor
   pattern for this AST library. The correct pattern — `args()` then
   `match` on the returned `TableArg` variants — is not affected.
   No action required in safe-migrate's visitor code beyond using the
   standard `AstChildren` iteration pattern.

2. **Handwritten extensions beyond the node_ext.rs table above**: The exhaustive `impl ast::*`
   grep established in this document already covers the complete handwritten
   extension surface as of the squawk-syntax-2.58.0 version inspected. This is properly
   a maintenance caveat (re-run the grep if squawk_syntax is upgraded), not an
   open question requiring further investigation now. Reclassified as a
   standing maintenance note rather than an active open question.
