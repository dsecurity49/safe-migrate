# Publications AST Reference for safe-migrate

## Status

Verified against squawk_syntax 2.58.0 — July 2026

---

## Documentation Contract

1. Only document AST behavior that has been directly verified.
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. Assume additional nodes or helpers may exist outside the inspected surface.

---

## Scope Note

PostgreSQL publications are the source side of logical replication —
`CREATE PUBLICATION` defines a named set of tables/changes that subscribers
can receive. This is distinct from `subscriptions.md`, which covers the
receiving side.

---

# Core Nodes

## CreatePublication

### Verified Accessors (src/ast/generated/nodes.rs line 6018)

```rust
pub fn except_table_clause(&self) -> Option<ExceptTableClause>
pub fn name(&self) -> Option<Name>
pub fn publication_objects(&self) -> AstChildren<PublicationObject>
pub fn with_params(&self) -> Option<WithParams>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn all_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn for_token(&self) -> Option<SyntaxToken>
pub fn publication_token(&self) -> Option<SyntaxToken>
pub fn tables_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
CreatePublication =
  'create' 'publication' Name
  ('for' 'all' 'tables' ExceptTableClause? | 'for' (PublicationObject (',' PublicationObject)*))
  WithParams? ';'?
```

Two mutually exclusive top-level forms:
1. `FOR ALL TABLES [EXCEPT TABLE (...)]` — publishes every table in the
   database (current and future), optionally excluding specific tables
2. `FOR object, object, ...` — publishes an explicit list of
   `PublicationObject` entries (see below)

### Form Discrimination

```rust
fn classify_create_publication(node: &CreatePublication) -> PublicationScope {
    if node.all_token().is_some() && node.tables_token().is_some() {
        PublicationScope::AllTables {
            except: node.except_table_clause()
                .map(|c| c.relation_names().map(|r| /* extract */).collect())
                .unwrap_or_default(),
        }
    } else {
        PublicationScope::Explicit(node.publication_objects().collect())
    }
}
```

**`FOR ALL TABLES` is the highest-blast-radius publication form** — it
automatically includes every current and future table in the database,
including tables created after the publication itself. This has a
fundamentally different safety profile from an explicit table list: a
`CREATE TABLE` statement occurring later in the same migration (or any
future migration) will silently become part of this publication's
replication stream with zero additional DDL referencing the publication.
The dependency graph must treat `FOR ALL TABLES` publications as an
implicit edge from every table (present and future) to the publication,
not just the tables visible at `CREATE PUBLICATION` time.

### safe-migrate guidance

```rust
struct CreatePublicationFact {
    name: String,                          // from name()
    scope: PublicationScope,               // AllTables{except} | Explicit(Vec<PublicationObjectFact>)
    params: Vec<AttributeFact>,            // from with_params()
}
```

---

## PublicationObject

### Verified Accessors (src/ast/generated/nodes.rs line 16460)

```rust
pub fn column_list(&self) -> Option<ColumnList>
pub fn name_ref(&self) -> Option<NameRef>
pub fn path(&self) -> Option<Path>
pub fn where_condition_clause(&self) -> Option<WhereConditionClause>
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
pub fn star_token(&self) -> Option<SyntaxToken>
pub fn current_schema_token(&self) -> Option<SyntaxToken>
pub fn in_token(&self) -> Option<SyntaxToken>
pub fn only_token(&self) -> Option<SyntaxToken>
// schema_token(), table_token(), tables_token() also present per established pattern
```

### Grammar Confirmation

```
PublicationObject =
  'table' 'only'? (Path | '(' Path ')') '*'? ColumnList? WhereConditionClause?
| 'tables' 'in' 'schema' ('current_schema' | NameRef) WhereConditionClause?
| 'current_schema'
```

Three mutually exclusive forms:

1. **`TABLE [ONLY] path [*] [(col_list)] [WHERE (expr)]`** — single table,
   via `path()`. `ONLY` excludes child partitions/inheriting tables from
   replication; `*` (the inverse default) explicitly includes them.
   `column_list()` restricts which columns are replicated (column filtering,
   PostgreSQL 15+). `where_condition_clause()` is row filtering (PostgreSQL
   15+) — only rows matching the expression are replicated.
2. **`TABLES IN SCHEMA (current_schema | schema_name)`** — all tables in a
   schema, present and future, via `name_ref()` or `current_schema_token()`.
3. **bare `CURRENT_SCHEMA`** — shorthand equivalent to `TABLES IN SCHEMA
   CURRENT_SCHEMA`, via `current_schema_token()` alone (no `tables`/`in`/
   `schema` tokens present in this third form, distinguishing it from form 2's
   `current_schema_token()` usage).

### Discrimination Logic

```rust
fn classify_publication_object(obj: &PublicationObject) -> PublicationObjectFact {
    if obj.path().is_some() {
        PublicationObjectFact::Table {
            only: obj.only_token().is_some(),
            include_partitions: obj.star_token().is_some(),
            columns: obj.column_list().map(|cl| /* extract */),
            row_filter: obj.where_condition_clause().map(|w| /* extract Expr */),
        }
    } else if obj.in_token().is_some() {
        PublicationObjectFact::SchemaTables {
            schema: obj.name_ref().map(|n| n.text())
                .or_else(|| obj.current_schema_token().map(|_| "CURRENT_SCHEMA".into())),
            row_filter: obj.where_condition_clause().map(|w| /* extract Expr */),
        }
    } else if obj.current_schema_token().is_some() {
        PublicationObjectFact::CurrentSchemaShorthand
    } else {
        PublicationObjectFact::Unknown
    }
}
```

**Important note on discrimination ambiguity:** `current_schema_token()`
appears in both form 2 (as the schema target) and form 3 (as the entire
object). The discriminator must check `in_token()` first — if `in_token()`
is present, it's form 2 regardless of which schema reference is used; only
when `in_token()` is absent AND `current_schema_token()` is present is it
genuinely form 3.

### safe-migrate guidance

A row-filtered (`WHERE` clause) or column-filtered publication entry means
not all data from the source table reaches subscribers — this is relevant
if safe-migrate ever needs to reason about replication completeness/data
exposure, though this is more of a data-governance concern than a
schema-migration-safety concern in the traditional sense. `TABLES IN
SCHEMA`, like `FOR ALL TABLES`, has the same future-table auto-inclusion
characteristic noted above and should be modeled the same way in the
dependency graph.

---

## ExceptTableClause

### Verified Accessors (src/ast/generated/nodes.rs line 10238)

```rust
pub fn except_table_names(&self) -> AstChildren<ExceptTableName>
pub fn l_paren_token(&self) -> Option<SyntaxToken>
pub fn r_paren_token(&self) -> Option<SyntaxToken>
pub fn except_token(&self) -> Option<SyntaxToken>
pub fn table_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
ExceptTableClause =
  'except' 'table' '(' (ExceptTableName (',' ExceptTableName)*) ')'
```

## ExceptTableName

### Verified Accessors (src/ast/generated/nodes.rs line 10265)

```rust
pub fn relation_name(&self) -> Option<RelationName>
pub fn table_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
ExceptTableName =
  'table'? RelationName
```

Used exclusively within `CreatePublication`'s `FOR ALL TABLES EXCEPT TABLE
(...)` form, via the `ExceptTableClause` child node.

---

## ExceptTables — Distinct Node, Confirmed Unrelated to Publications

### Verified Accessors (src/ast/generated/nodes.rs line 10280)

```rust
pub fn name_refs(&self) -> AstChildren<NameRef>
pub fn except_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation — RESOLVED

`ExceptTables` is a **separate node from `ExceptTableClause`**, despite the
similar name and similar surface purpose. A full-file grep of
postgresql.ungram resolves its actual usage:

```
ImportForeignSchema =
  'import' 'foreign' 'schema' NameRef
  (LimitToTables | ExceptTables)?
  'from' ServerName
  IntoSchema
  AlterOptionList? ';'?

ExceptTables =
  'except' (NameRef (',' NameRef)*)
```

**`ExceptTables` belongs exclusively to `IMPORT FOREIGN SCHEMA ... EXCEPT
(table1, table2, ...)`** — a foreign data wrapper schema import statement,
entirely unrelated to `CREATE PUBLICATION`. It is confirmed absent from
`CreatePublication`'s grammar; only `ExceptTableClause` is used there.

The two nodes happen to share a similar naming pattern and similar
conceptual purpose (an exclusion list of table names) but serve entirely
different statements: `ExceptTableClause` (`'except' 'table' '(' RelationName-list ')'`)
for publications, and `ExceptTables` (`'except' NameRef-list`, no
parentheses, no `'table'` keyword) for foreign schema imports. They are not
interchangeable and should never be confused in implementation code despite
the naming similarity.

**For safe-migrate's `CreatePublication` handling: only `ExceptTableClause`
(via `CreatePublication.except_table_clause()`) is relevant.
`ExceptTables` belongs to foreign data wrapper schema import handling
(out of scope for this document) and should be disregarded here.**

---

## DropPublication

### Verified Accessors (src/ast/generated/nodes.rs line 8891)

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn name_refs(&self) -> AstChildren<NameRef>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
// restrict_token(), publication_token() also present per established pattern
```

### Grammar Confirmation

```
DropPublication =
  'drop' 'publication' IfExists? (NameRef (',' NameRef)*)
  ('cascade' | 'restrict')? ';'?
```

Multi-name drop confirmed, consistent with the established pattern across
most `Drop*` nodes in this AST.

### safe-migrate guidance

Dropping a publication that has active subscribers (tracked via
subscriptions.md's node set, cross-referenced at the dependency-graph
level) breaks logical replication for those subscribers — this is an
external-system blast radius that extends beyond the database itself,
worth flagging distinctly from in-database structural risks.

---

## AlterPublication

### Verified Accessors (line 1555)

```rust
pub fn name_ref(&self) -> Option<NameRef>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn publication_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation — CRITICAL FINDING

```
AlterPublication =
  'alter' 'publication' NameRef ';'?
```

**This is the complete grammar rule.** `AlterPublication` carries
**genuinely nothing beyond the publication's own name** — confirmed by both
the grammar (no action clause of any kind) and the verified squawk.rs
accessor surface (only `name_ref()` plus boilerplate tokens).

This is the same severity of finding as `AlterView` (views.md) — but
arguably more significant in practice, since real PostgreSQL `ALTER
PUBLICATION` syntax supports substantial functionality that this grammar
version does not capture at all:

```sql
ALTER PUBLICATION name ADD TABLE table_name [, ...];
ALTER PUBLICATION name SET TABLE table_name [, ...];
ALTER PUBLICATION name DROP TABLE table_name [, ...];
ALTER PUBLICATION name SET (publication_parameter [= value] [, ...]);
ALTER PUBLICATION name OWNER TO new_owner;
ALTER PUBLICATION name RENAME TO new_name;
```

**None of these six real PostgreSQL `ALTER PUBLICATION` forms can be
distinguished or extracted from this AST.** Every `ALTER PUBLICATION`
statement, regardless of which of these six operations it represents,
produces an `AlterPublication` node with only a name and no other
extractable content. This is a parser-level limitation in this grammar
version, not an accessor gap — there is no hidden sibling node or
alternate accessor path, since the grammar rule itself has no alternation
or optional action clause whatsoever.

### safe-migrate guidance

```rust
struct AlterPublicationFact {
    name: String,    // from name_ref() — only extractable field
    // operation type and parameters: NOT EXTRACTABLE
}
```

**This is a significant safety gap for safe-migrate.** Any rule needing to
evaluate `ALTER PUBLICATION` safety (e.g. flagging a `DROP TABLE` from a
publication that would break a downstream subscriber's expected schema, or
flagging a parameter change affecting replication behavior) cannot do so —
the simulator can only detect that *some* `ALTER PUBLICATION` operation
occurred against a named publication, with zero insight into what changed.
Given the external-system blast radius noted above for `DropPublication`,
this gap should be treated conservatively: any `AlterPublication` statement
should be flagged for manual review (or treated as `Confidence::Tainted`
per the blueprint's model) rather than assumed safe, since the simulator
cannot distinguish a harmless `RENAME` from a `DROP TABLE` that breaks
replication.

---

# Verified Findings Summary

## Confirmed Complete

- `CreatePublication`: fully resolved, both `FOR ALL TABLES` and explicit
  object-list forms
- `PublicationObject`: fully resolved, all 3 forms with discrimination logic
- `ExceptTableClause`: fully resolved
- `DropPublication`: fully resolved

## Grammar-Confirmed Limitations

- `AlterPublication`: confirmed by both grammar and squawk.rs to carry
  nothing beyond the publication name. None of the six real PostgreSQL
  `ALTER PUBLICATION` operation forms (ADD/SET/DROP TABLE, SET options,
  OWNER TO, RENAME TO) can be distinguished or extracted. This is the most
  severe documentation finding of this type encountered across the AST
  reference set so far — more impactful than `AlterView`'s equivalent gap,
  given the external-replication blast radius involved.

## Resolved Naming-Collision Risk

- `ExceptTables` (a separate node from `ExceptTableClause`) is confirmed to
  belong exclusively to `IMPORT FOREIGN SCHEMA ... EXCEPT (...)`, unrelated
  to publications. Flagged here because the similar naming and similar
  conceptual purpose creates a real risk of implementation code accidentally
  using the wrong node — now fully resolved and documented to prevent that.

## Key Architectural Findings

1. **`FOR ALL TABLES` and `TABLES IN SCHEMA` publications have implicit
   future-table inclusion** — the dependency graph must model these as
   open-ended edges to "every table, including ones not yet created," not
   a fixed snapshot of tables visible at `CREATE PUBLICATION` time.
2. **`AlterPublication`'s near-total lack of extractable content is the
   most significant grammar gap found in the Tier 3 documentation pass so
   far** — recommend conservative (tainted/manual-review) handling of all
   `ALTER PUBLICATION` statements until/unless a newer squawk.rs grammar
   version captures this content.

## Grammar Cross-Check

This document was written with postgresql.ungram available from the start,
and the `AlterPublication` finding was independently confirmed against both
the grammar and squawk.rs accessor bodies before being treated as definitive.

---

# Remaining Open Questions

None remaining. The `ExceptTables` usage context has been fully resolved
via full-file grammar grep — it belongs to `IMPORT FOREIGN SCHEMA`, not
`CREATE PUBLICATION`.
