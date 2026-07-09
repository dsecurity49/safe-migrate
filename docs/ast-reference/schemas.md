# Schemas AST Reference for safe-migrate

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

From the blueprint, section 7 (IDENTIFIER SYSTEM — CRITICAL):

```
7.1 AST form
QualifiedName { schema: Option<String>, name: String }

7.2 Canonical form
ObjectId { schema: String, name: String }

7.3 RULE
AST names are NEVER used for lookup
Only ObjectId is used in state/cache
```

This document establishes exactly how `Path` (the AST form) is structured and
how identifier text is normalized, which is the foundation for the
`Path → QualifiedName → ObjectId` resolution pipeline the resolver must
implement. This is the single most foundational document for `analysis/symbols.rs`
and `analysis/resolver.rs`.

---

## Handwritten Extension Policy

Two handwritten extensions are directly relevant to this document:

```
impl ast::NameRef  (src/ast/node_ext.rs, line 417) — text(), is_quoted()
impl ast::Name     (src/ast/node_ext.rs, line 429) — text(), is_quoted()
```

Both documented fully below. No handwritten extension exists for `Path`,
`PathSegment`, `CreateSchema`, `AlterSchema`, or `DropSchema` — verified by
the exhaustive grep documented in `columns.md`.

---

# High-Level Schema and Identifier Model

The verified AST surface exposes:

**Schema nodes:**
- `CreateSchema`
- `AlterSchema`
- `DropSchema`
- `SchemaElement` (6-member enum)

**Identifier resolution foundation:**
- `Path` — recursive qualified name structure
- `PathSegment` — single path component
- `Name` — a name being declared
- `NameRef` — a reference to an existing name
- `Role` / `RoleRef` — role identifier variants used in `AUTHORIZATION` clauses

---

# Identifier Resolution Foundation

## Path

### Verified Accessors (src/ast/generated/nodes.rs, line 15925)

```rust
pub fn qualifier(&self) -> Option<Path>
pub fn segment(&self) -> Option<PathSegment>
pub fn dot_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

postgresql.ungram confirms:

```
Path =
  qualifier:Path?
  '.'
  segment:PathSegment?
```

### Critical Architectural Finding: Path Is Recursive

`Path` is a **recursive, left-nested structure**, not a flat list. A
schema-qualified table reference like `public.users` is represented as:

```
Path {
    qualifier: Some(Path {
        qualifier: None,
        segment: Some(PathSegment("public")),
    }),
    segment: Some(PathSegment("users")),
}
```

For an unqualified reference like `users`, `qualifier` is `None` and `segment`
holds the single component.

**The grammar permits arbitrary nesting depth** (`qualifier:Path?` is
self-referential), even though PostgreSQL itself only meaningfully uses two
levels (`schema.object`) or rarely three (`database.schema.object`, not
typically valid in modern PostgreSQL cross-database contexts). The resolver
must walk the `qualifier` chain to its root rather than assuming a fixed depth.

### safe-migrate guidance — Fully General Recursive Implementation

```rust
struct QualifiedName {
    schema: Option<String>,
    name: String,
}

/// Flattens a Path of arbitrary nesting depth into an ordered list of
/// segment strings, root-first. For `public.users` this yields
/// ["public", "users"]. For an unqualified `users` it yields ["users"].
/// For a hypothetical deeper nesting `db.schema.table` it yields
/// ["db", "schema", "table"], even though this case has no real meaning
/// in standard PostgreSQL single-database connections.
fn flatten_path(path: &Path) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = Some(path.clone());
    while let Some(p) = current {
        if let Some(seg) = p.segment() {
            if let Some(text) = extract_segment_text(&seg) {
                segments.push(text);
            }
        }
        current = p.qualifier();
    }
    segments.reverse();  // we walked qualifier-first (innermost to outermost),
                          // so reverse to get root-first order
    segments
}

fn extract_segment_text(segment: &PathSegment) -> Option<String> {
    if let Some(name) = segment.name() {
        Some(name.text())          // declaration position — handwritten text()
    } else if let Some(name_ref) = segment.name_ref() {
        Some(name_ref.text())      // reference position — handwritten text()
    } else {
        None
    }
}

/// Resolves a flattened Path into the QualifiedName the resolver expects.
/// For the standard PostgreSQL case (0 or 1 qualifying segments), this is
/// unambiguous. For 3+ segments (deeper than schema.object), this document
/// makes no claim about which segment is "the schema" versus an outer
/// qualifier PostgreSQL doesn't support — that interpretation is a
/// PostgreSQL-semantics question for the resolver to apply explicitly,
/// not something flatten_path() itself decides.
fn resolve_path(path: &Path) -> QualifiedName {
    let mut segments = flatten_path(path);
    let name = segments.pop().unwrap_or_default();
    let schema = segments.pop();  // None if unqualified; the immediate qualifier if present
    // Any further segments beyond schema+name (3+ total) are silently
    // dropped here in the common case — the resolver should explicitly
    // decide whether to treat this as an error/Tainted-confidence case,
    // since standard PostgreSQL has no use for it.
    QualifiedName { schema, name }
}
```

**This fully resolves the previously open question about the general
recursive-walk pattern.** `flatten_path()` correctly handles any nesting
depth the grammar permits by walking `qualifier()` until it returns `None`
and collecting every `segment()` encountered along the way, then reversing
to root-first order (since the walk proceeds from the innermost/rightmost
segment outward, due to `Path`'s left-nested structure). The previous
one-level-only implementation shown in earlier drafts of this document is
superseded by this general version.

---

## PathSegment

### Verified Accessors (src/ast/generated/nodes.rs, line 16004)

```rust
pub fn name(&self) -> Option<Name>
pub fn name_ref(&self) -> Option<NameRef>
```

### Grammar Confirmation

```
PathSegment =
  NameRef?
  Name?
```

### Meaning

A `PathSegment` holds either a `Name` (declaration context, e.g. the target
of `CREATE TABLE schema.name`) or a `NameRef` (reference context, e.g. the
target of `DROP TABLE schema.name` or any read reference). Both accessors
exist on every `PathSegment`, but only one is populated depending on whether
the segment represents a declaration or a reference — this mirrors the
`Name`/`NameRef` duality seen throughout this entire AST (e.g. `Column.name()`
vs `Column.name_ref()`, documented in columns.md).

### safe-migrate guidance

```rust
fn extract_text(segment: &PathSegment) -> Option<String> {
    if let Some(name) = segment.name() {
        Some(name.text())
    } else if let Some(name_ref) = segment.name_ref() {
        Some(name_ref.text())
    } else {
        None
    }
}
```

---

## Identifier Normalization — `Name.text()` / `NameRef.text()`

### Verified Implementation (src/ast/node_ext.rs, line 417-493, handwritten)

```rust
impl ast::NameRef {
    pub fn text(&self) -> String {
        normalize_name_node(self.syntax())
    }
    pub fn is_quoted(&self) -> bool {
        is_quoted(self.syntax())
    }
}

impl ast::Name {
    pub fn text(&self) -> String {
        normalize_name_node(self.syntax())
    }
    pub fn is_quoted(&self) -> bool {
        is_quoted(self.syntax())
    }
}
```

### Critical Finding: Full Normalization Logic Is Implemented

This is the single most important piece of verified code for safe-migrate's
identifier resolution, because it is the **exact logic that determines
whether two identifiers refer to the same database object**.

**`is_quoted()` logic:**

```rust
fn is_quoted(node: &SyntaxNode) -> bool {
    let text = node.text();
    let first = text.char_at(0.into());
    let second = text.char_at(1.into());
    matches!(
        (first, second),
        (Some('u' | 'U'), Some('"')) | (Some('"'), Some(_))
    )
}
```

Detects both standard double-quoted identifiers (`"Foo"`) and Unicode-escaped
quoted identifiers (`U&"Foo"` / `u&"Foo"`).

**`normalize_name_node()` logic:**

1. Takes the first non-trivia token of the name node.
2. If the raw text matches the Unicode-escape quoted form (`U&"..."` or
   `u&"..."`), it strips the prefix/suffix, processes an optional `UESCAPE`
   clause (defaulting escape character to `\`), unescapes doubled quotes
   (`""` → `"`), and resolves Unicode escape sequences via
   `escape_unicode_esc_str`.
3. Otherwise, if the raw text is a standard double-quoted identifier, it
   strips the surrounding quotes and unescapes doubled quotes (`""` → `"`),
   **preserving case exactly as written**.
4. Otherwise (a bare, unquoted identifier), it is **lowercased**
   (`to_ascii_lowercase()`), matching PostgreSQL's standard unquoted
   identifier folding behavior.

### safe-migrate guidance

This is the canonical normalization the resolver must use for every identifier
comparison — table names, column names, constraint names, schema names,
sequence names, everything. **Do not reimplement this logic; call
`Name::text()` / `NameRef::text()` directly**, since this handwritten
extension already correctly implements PostgreSQL's full identifier folding
rules including the Unicode-escape edge case.

```rust
struct ObjectId {
    schema: String,   // always normalized via text(), defaulted if None
    name: String,      // always normalized via text()
}
```

**This single piece of logic is what makes blueprint rule 7.3 enforceable**
("AST names are NEVER used for lookup, only ObjectId is used") — `ObjectId`
construction must always route identifier text through `text()`, never
through raw token text, or two differently-quoted references to the same
object (`Users` vs `"Users"` vs `users`) will be treated as different objects
when they may or may not actually be the same PostgreSQL object depending on
quoting.

**Important semantic note:** `users` (unquoted) and `"users"` (quoted) refer
to the **same** PostgreSQL object (both normalize to `users`), but `Users`
(unquoted) and `"Users"` (quoted) refer to **different** objects — the
unquoted form normalizes to `users` while the quoted form preserves `Users`.
This asymmetry is exactly what `is_quoted()` + the conditional lowercasing in
`normalize_name_node()` captures, and the resolver must never short-circuit
this logic with a naive `.to_lowercase()` call.

---

## NameRef (token-level)

### Verified Accessors — Generated (src/ast/generated/nodes.rs, line 14236)

```rust
pub fn ident_token(&self) -> Option<SyntaxToken>
```

The generated accessor only exposes the raw token. Always prefer the
handwritten `text()` extension (above) over reading `ident_token()` directly,
since `text()` performs the full normalization while `ident_token()` gives
raw, unnormalized source text.

---

# Schema Nodes

## CreateSchema

### Verified Accessors (src/ast/generated/nodes.rs, line 6135)

```rust
pub fn if_not_exists(&self) -> Option<IfNotExists>
pub fn name(&self) -> Option<Name>
pub fn role(&self) -> Option<Role>
pub fn role_ref(&self) -> Option<RoleRef>
pub fn schema_elements(&self) -> AstChildren<SchemaElement>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn authorization_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn schema_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

postgresql.ungram confirms four distinct forms:

```
CreateSchema =
  'create' 'schema' Name ('authorization' RoleRef)? SchemaElement* ';'?
| 'create' 'schema' 'authorization' Role SchemaElement* ';'?
| 'create' 'schema' IfNotExists Name ('authorization' RoleRef)? ';'?
| 'create' 'schema' IfNotExists 'authorization' Role ';'?
```

### Form Detection

| Form | Detection |
|------|-----------|
| Named schema | `name().is_some()` |
| Authorization-only (schema named after role) | `name().is_none()` + `authorization_token().is_some()` |
| With explicit role reference | `role_ref().is_some()` |
| With role expression (CURRENT_USER etc.) | `role().is_some()` |

**Important distinction:** `role()` returns `Role` (which can be a bare
`Name`, or `CURRENT_ROLE`/`CURRENT_USER`/`SESSION_USER` keyword forms — see
`Role` section below), while `role_ref()` returns `RoleRef` (a reference to
an existing role by name). These are two different grammar branches: the
`'authorization' Role` standalone form versus the `('authorization' RoleRef)?`
suffix form.

### Schema Elements

`schema_elements()` returns `AstChildren<SchemaElement>` — PostgreSQL allows
bundling `CREATE TABLE`, `CREATE VIEW`, `CREATE INDEX`, `CREATE SEQUENCE`,
`CREATE TRIGGER`, and `GRANT` statements inside a single `CREATE SCHEMA`
statement. The grammar confirms exactly these 6 members (see `SchemaElement`
below) — no other statement types are permitted inside `CREATE SCHEMA`.

### safe-migrate guidance

```rust
CreateSchemaFact {
    name: Option<String>,              // from name() — None in authorization-only form
    if_not_exists: bool,
    authorization: Option<AuthorizationFact>,
    nested_elements: Vec<SchemaElementFact>,  // recursively extracted
}

enum AuthorizationFact {
    Role(RoleFact),
    RoleRef(String),
}
```

**Significant for safe-migrate:** a `CREATE SCHEMA` statement can contain
nested `CREATE TABLE`/`CREATE INDEX`/etc. statements. The AST Visitor must
recurse into `schema_elements()` and feed each nested element through the
same extraction pipeline as a top-level statement, or these nested mutations
will be silently invisible to the simulator.

---

## AlterSchema

### Verified Accessors (src/ast/generated/nodes.rs, line 2045)

```rust
pub fn name_ref(&self) -> Option<NameRef>
pub fn owner_to(&self) -> Option<OwnerTo>
pub fn rename_to(&self) -> Option<RenameTo>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn schema_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
AlterSchema =
  'alter' 'schema' NameRef
  (RenameTo
  | OwnerTo) ';'?
```

Exactly two action forms — confirmed complete, no other `ALTER SCHEMA` actions
exist in this grammar (e.g. no `SET` options for schemas).

### safe-migrate guidance

```rust
enum AlterSchemaAction {
    Rename { to: String },
    ChangeOwner { new_owner: String },
}
```

`RenameTo` on a schema is significant for the resolver — every `ObjectId`
with that schema as its `schema` field must be re-keyed, and `search_path`
entries referencing the old schema name become stale (see search_path.md).

---

## DropSchema

### Verified Accessors (src/ast/generated/nodes.rs, line 9027)

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn name_refs(&self) -> AstChildren<NameRef>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn restrict_token(&self) -> Option<SyntaxToken>
pub fn schema_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
DropSchema =
  'drop' 'schema' IfExists? (NameRef (',' NameRef)*)
  ('cascade' | 'restrict')? ';'?
```

Multiple schema names supported per statement, matching the `DropSequence`/
`DropMaterializedView` multi-name pattern documented elsewhere.

### safe-migrate guidance

```rust
DropSchemaFact {
    names: Vec<String>,   // from name_refs()
    if_exists: bool,
    cascade: bool,
}
```

**Critical for the simulator:** `DROP SCHEMA ... CASCADE` is one of the most
destructive operations possible — it recursively drops every object owned by
that schema. The dependency graph must be walked to tombstone every
`ObjectId` whose `schema` field matches any dropped schema name. This is a
strong candidate for tier-1 (block) classification in the rule engine when
the schema is non-empty, since the blast radius cannot be fully known
without querying the live database (`DbCache`).

---

## SchemaElement

### Enum Definition

```rust
pub enum SchemaElement {
    CreateTable(CreateTable),
    CreateView(CreateView),
    CreateIndex(CreateIndex),
    CreateSequence(CreateSequence),
    CreateTrigger(CreateTrigger),
    Grant(Grant),
}
```

6 members, confirmed via grammar:

```
SchemaElement =
  CreateTable
| CreateView
| CreateIndex
| CreateSequence
| CreateTrigger
| Grant
```

---

# Role Identifier Variants

## Role

### Verified Accessors (src/ast/generated/nodes.rs, line 17688)

```rust
pub fn name(&self) -> Option<Name>
pub fn current_role_token(&self) -> Option<SyntaxToken>
pub fn current_user_token(&self) -> Option<SyntaxToken>
pub fn group_token(&self) -> Option<SyntaxToken>
pub fn session_user_token(&self) -> Option<SyntaxToken>
```

### Meaning

Used in `AUTHORIZATION` clauses and similar contexts where a role can be
specified either by name or by one of PostgreSQL's special role-reference
keywords (`CURRENT_ROLE`, `CURRENT_USER`, `SESSION_USER`).

### Grammar Confirmation — RESOLVED

postgresql.ungram confirms:

```
Role =
  'group'? Name
| 'current_role'
| 'current_user'
| 'session_user'
```

`group_token()` is **not dead surface or shared-grammar noise** — it
represents PostgreSQL's legacy `GROUP role_name` syntax, a deprecated
synonym for a plain role name retained for backward compatibility (from
PostgreSQL versions prior to 8.1, where the role/group distinction was more
formalized). It is grammatically valid in any context using `Role`,
including `CREATE SCHEMA AUTHORIZATION GROUP rolename` — uncommon in
practice, but real and parseable, not vestigial.

```rust
fn extract_role(role: &Role) -> RoleFact {
    if let Some(name) = role.name() {
        RoleFact::Named {
            name: name.text(),
            via_legacy_group_syntax: role.group_token().is_some(),
        }
    } else if role.current_role_token().is_some() {
        RoleFact::CurrentRole
    } else if role.current_user_token().is_some() {
        RoleFact::CurrentUser
    } else if role.session_user_token().is_some() {
        RoleFact::SessionUser
    } else {
        RoleFact::Unknown
    }
}
```

`group_token()`'s presence has no semantic effect on the resolved role
identity — `GROUP myrole` and plain `myrole` resolve to the exact same role.
It is safe to ignore for `ObjectId`/role-resolution purposes and only worth
tracking if safe-migrate ever wants to flag deprecated-syntax usage as a
style/modernization suggestion.

`CurrentRole`/`CurrentUser`/`SessionUser` cannot be resolved to a concrete
name at static-analysis time — the simulator must either downgrade confidence
(per blueprint's `Confidence::Tainted`) or require the caller to supply the
executing role context.

---

# Verified Findings Summary

## Confirmed Complete

- `Path`: fully resolved, recursive structure documented
- `PathSegment`: fully resolved
- `Name` / `NameRef` identifier normalization: fully resolved via handwritten
  `text()` / `is_quoted()` extensions — this is the canonical resolution
  logic for the entire `ObjectId` system
- `CreateSchema`: fully resolved, all four grammar forms documented
- `AlterSchema`: fully resolved, confirmed only 2 actions exist
- `DropSchema`: fully resolved, multi-name support confirmed
- `SchemaElement` enum: all 6 members verified
- `Role`: fully resolved

## Confirmed Partial

None remaining — both previously partial findings have been grammar-resolved.

## Grammar-Confirmed Findings

- `Role.group_token()`: confirmed to represent PostgreSQL's legacy `GROUP
  role_name` syntax (deprecated synonym, no semantic effect on resolved
  role identity), not dead grammar surface.
- `Path.qualifier()` recursion: a fully general recursive flattening
  implementation is now documented above, superseding the earlier
  one-level-only version.

## Architectural Significance

This document is the foundation for blueprint rule 7 (IDENTIFIER SYSTEM).
The `Name.text()` / `NameRef.text()` handwritten extensions are the single
most safety-critical piece of verified logic in the entire AST surface
reviewed so far — every `ObjectId` comparison in the resolver, dependency
graph, and rule engine depends on routing through this exact normalization
logic rather than raw token text or naive case-folding.

---

# Remaining Open Questions

None remaining. Both previously open questions have been resolved through
direct grammar cross-check: `Role.group_token()` represents real, intentional
legacy `GROUP role_name` syntax (not dead surface), and a fully general
recursive `Path.qualifier()` flattening implementation is now documented.
