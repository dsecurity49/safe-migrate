# Subscriptions AST Reference for safe-migrate

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

PostgreSQL subscriptions are the receiving side of logical replication —
`CREATE SUBSCRIPTION` connects to a remote publisher and replicates its
publication(s) locally. This is the counterpart to publications.md.

---

# Core Nodes

## CreateSubscription

### Verified Accessors (line 5401)

```rust
pub fn literal(&self) -> Option<Literal>
pub fn name(&self) -> Option<Name>
pub fn name_ref(&self) -> Option<NameRef>
pub fn name_refs(&self) -> AstChildren<NameRef>
pub fn with_params(&self) -> Option<WithParams>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn connection_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn publication_token(&self) -> Option<SyntaxToken>
pub fn server_token(&self) -> Option<SyntaxToken>
pub fn subscription_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
CreateSubscription =
  'create' 'subscription' Name
  ('connection' Literal | 'server' NameRef)
  'publication' (NameRef (',' NameRef)*)
  WithParams? ';'?
```

### PostgreSQL Semantics Caveat

This document's analysis of the `SERVER name` form is based purely on what
the grammar parses, not on independent confirmation that `CREATE
SUBSCRIPTION ... SERVER name ...` is valid real-world PostgreSQL syntax.
Standard PostgreSQL `CREATE SUBSCRIPTION` documentation describes only the
`CONNECTION 'conninfo'` form for specifying the publisher connection — a
`SERVER name` alternative (referencing a foreign server object, similar to
foreign data wrapper syntax) was not independently verified against
PostgreSQL's own documentation in this pass. It's possible this grammar
alternative exists for a non-standard extension, a different PostgreSQL
version, or was added speculatively/defensively by the parser author. This
document treats it as parseable per the grammar regardless of its
real-world applicability, but the disambiguation risk discussed below is
only practically relevant if this form is ever actually encountered in real
migration SQL — worth flagging as a question for the user's own PostgreSQL
version/knowledge rather than asserting as definitely-real syntax.

### Critical Finding — Ambiguous NameRef Disambiguation

The grammar shows **two separate `NameRef`-bearing positions**:
1. The `SERVER name` connection target (single `NameRef`, only present in
   the `SERVER` form, mutually exclusive with `CONNECTION 'literal'`)
2. The `PUBLICATION name, name, ...` list (one or more `NameRef`, always present)

The verified accessor surface exposes **both** `name_ref()` (singular,
`support::child()` — returns the *first* matching `NameRef` child) and
`name_refs()` (plural, `support::children()` — returns *all* matching
`NameRef` children).

**This creates a genuine disambiguation risk identical in pattern to the
`RenameValue` (enums.md) and `AsFuncOption` (functions.md) flat-accessor
findings:**

- If the statement uses `CONNECTION 'literal'` (not `SERVER`), there is only
  one group of `NameRef` children in the subtree — the publication list.
  In this case, `name_ref()` returns the *first publication name* (not a
  server name, since none exists), and `name_refs()` returns the full
  publication list correctly. No ambiguity in this case.

- If the statement uses `SERVER name` instead of `CONNECTION`, there are
  now **two distinct groups of `NameRef` children**: the server name (one)
  and the publication list (one or more). In this case:
  - `name_ref()` returns the *first* `NameRef` in document order, which
    is the **server name** (since `'server' NameRef` appears before
    `'publication' (NameRef...)` in the grammar sequence).
  - `name_refs()` returns **all** `NameRef` children, meaning it would
    include the server name **mixed in with** the publication list — there
    is no accessor that isolates just the publication list when the
    `SERVER` form is used, since both groups share the same underlying
    `NameRef` type and `support::children()` does not distinguish by
    grammar position, only by type.

**This is a confirmed, real extraction ambiguity specific to the `SERVER`
connection-target form.** The `CONNECTION 'literal'` form is unambiguous;
the `SERVER name` form is not, because the flat `name_refs()` accessor
cannot separate "the server name" from "the publication list" — both are
just `NameRef` children of the same node, and `support::children::<NameRef>()`
does not know about grammar-level positional semantics.

### Discrimination Strategy

```rust
fn extract_create_subscription(node: &CreateSubscription) -> CreateSubscriptionFact {
    let uses_server = node.server_token().is_some();
    let uses_connection = node.connection_token().is_some();

    let all_name_refs: Vec<String> = node.name_refs().map(|n| n.text()).collect();

    let (server_name, publications) = if uses_server {
        // First NameRef is the server name; remaining are publications.
        // This relies on document order matching grammar declaration order,
        // which is true for support::children() but should be verified
        // empirically against real parsed output before relying on it,
        // since this is an inferred ordering assumption, not something
        // separately confirmed via a dedicated accessor.
        let mut iter = all_name_refs.into_iter();
        let server = iter.next();
        let pubs: Vec<String> = iter.collect();
        (server, pubs)
    } else {
        // CONNECTION form: no server NameRef exists, all NameRefs are publications.
        (None, all_name_refs)
    };

    CreateSubscriptionFact {
        name: node.name().map(|n| n.text()),
        connection: if uses_connection {
            ConnectionTarget::Literal(node.literal().map(|l| /* extract string */))
        } else {
            ConnectionTarget::Server(server_name)
        },
        publications,
        params: node.with_params().map(|p| /* extract */),
    }
}
```

**This positional-splitting approach (first `NameRef` = server, rest =
publications) is an inference based on grammar declaration order, not a
separately verified guarantee.** Unlike `ForeignKeyConstraint`'s
`from_columns()`/`to_columns()` (which are genuine handwritten accessors
verified directly in squawk.rs to do exactly this kind of positional split),
no equivalent handwritten extension exists for `CreateSubscription` per the
exhaustive `impl ast::*` inventory established in columns.md. This means the
positional-split approach above is the best available strategy but has NOT
been verified against actual parsed output in this pass — it should be
tested against a real `CREATE SUBSCRIPTION ... SERVER ... PUBLICATION ...`
statement before being trusted in production code.

### safe-migrate guidance

```rust
struct CreateSubscriptionFact {
    name: Option<String>,
    connection: ConnectionTarget,        // Literal(conn_string) | Server(name)
    publications: Vec<String>,
    params: Option<Vec<AttributeFact>>,  // includes e.g. enabled, slot_name, copy_data
}
```

A new subscription immediately begins replicating data from the publisher,
including an initial data copy (`copy_data = true` by default) unless
explicitly disabled via `with_params()`. This can be a substantial
operation against the source database depending on table sizes — relevant
context for safe-migrate if cross-database operational impact is ever part
of its risk model, though this is more of an operational/performance
concern than a schema-correctness one.

---

## DropSubscription

### Verified Accessors (line 8030)

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn name_ref(&self) -> Option<NameRef>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn restrict_token(&self) -> Option<SyntaxToken>
pub fn subscription_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
DropSubscription =
  'drop' 'subscription' IfExists? NameRef
  ('cascade' | 'restrict')? ';'?
```

Single subscription name only — unambiguous, no disambiguation risk (unlike
`CreateSubscription`, only one `NameRef`-bearing position exists here).

### safe-migrate guidance

```rust
struct DropSubscriptionFact {
    name: String,
    if_exists: bool,
}
```

`DROP SUBSCRIPTION` stops replication and (by default) drops the replication
slot on the publisher side too — an external-system side effect similar to
the one noted for `DropPublication`. Worth flagging as having impact beyond
the local database.

---

## AlterSubscription

### Verified Accessors (line 1822)

```rust
pub fn name_ref(&self) -> Option<NameRef>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn subscription_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation — CRITICAL FINDING

```
AlterSubscription =
  'alter' 'subscription' NameRef ';'?
```

**This is the complete grammar rule.** Identical severity finding to
`AlterPublication` (publications.md) and `AlterView` (views.md):
`AlterSubscription` carries genuinely nothing beyond the subscription's own
name. Confirmed by both grammar and squawk.rs accessor surface.

Real PostgreSQL `ALTER SUBSCRIPTION` syntax supports substantial
functionality not captured here at all:

```sql
ALTER SUBSCRIPTION name CONNECTION 'conninfo';
ALTER SUBSCRIPTION name SET PUBLICATION publication_name [, ...] [WITH (...)];
ALTER SUBSCRIPTION name ADD PUBLICATION publication_name [, ...] [WITH (...)];
ALTER SUBSCRIPTION name DROP PUBLICATION publication_name [, ...] [WITH (...)];
ALTER SUBSCRIPTION name REFRESH PUBLICATION [WITH (...)];
ALTER SUBSCRIPTION name ENABLE;
ALTER SUBSCRIPTION name DISABLE;
ALTER SUBSCRIPTION name SET (subscription_parameter [= value] [, ...]);
ALTER SUBSCRIPTION name SKIP (skip_option = value);
ALTER SUBSCRIPTION name OWNER TO new_owner;
ALTER SUBSCRIPTION name RENAME TO new_name;
```

**None of these eleven real PostgreSQL `ALTER SUBSCRIPTION` forms can be
distinguished or extracted from this AST.** This is a parser-level
limitation, not an accessor gap.

### safe-migrate guidance

```rust
struct AlterSubscriptionFact {
    name: String,    // from name_ref() — only extractable field
    // operation type and parameters: NOT EXTRACTABLE
}
```

This gap is particularly significant because `ENABLE`/`DISABLE` and
`DROP PUBLICATION` operations directly control whether replication is
actively running and what data flows — exactly the kind of operationally
critical state change safe-migrate would want to flag, and exactly what
cannot be distinguished here. As with `AlterPublication`, recommend treating
all `AlterSubscription` statements as `Confidence::Tainted` and/or flagged
for manual review by default, since the simulator cannot determine whether
a given statement disables replication, changes the connection target,
adds/removes published tables, or merely renames the subscription.

---

# Verified Findings Summary

## Confirmed Complete

- `CreateSubscription`: accessor surface fully resolved, though see the
  critical disambiguation finding below for the `SERVER` form
- `DropSubscription`: fully resolved, unambiguous

## Confirmed Partial — Genuine Extraction Ambiguity

- `CreateSubscription` using the `SERVER name` connection form: the server
  name and the publication list cannot be cleanly separated using only the
  generated accessors (`name_ref()` returns the first `NameRef`, which would
  be the server name in this form; `name_refs()` returns all `NameRef`
  children, mixing server name and publication list together). A
  positional-splitting strategy is proposed in this document but has not
  been empirically verified against real parsed output, since no handwritten
  accessor extension exists to do this disambiguation reliably (unlike the
  analogous `ForeignKeyConstraint.from_columns()`/`to_columns()` case). The
  `CONNECTION 'literal'` form does not have this ambiguity.

## Grammar-Confirmed Limitations

- `AlterSubscription`: confirmed by both grammar and squawk.rs to carry
  nothing beyond the subscription name. None of the eleven real PostgreSQL
  `ALTER SUBSCRIPTION` operation forms can be distinguished or extracted.
  Same severity as the `AlterPublication` finding in publications.md —
  together these represent the two most significant grammar gaps found
  across the entire Tier 3 documentation pass, both involving operationally
  critical replication state changes that cannot be analyzed.

## Key Architectural Findings

1. **`CreateSubscription`'s `SERVER` form has a confirmed, real
   disambiguation ambiguity** that has no clean resolution via existing
   accessors — this should be flagged for empirical testing against actual
   parsed output before any safe-migrate code relies on the proposed
   positional-splitting workaround.
2. **`AlterSubscription`, like `AlterPublication`, is functionally a
   black box** beyond the target object's name — both should be treated
   conservatively (tainted confidence / manual review) given the
   operational criticality of what they can represent (enabling/disabling
   replication, changing data flow) versus what can actually be detected
   (nothing beyond "an alter happened to this object").

## Grammar Cross-Check

This document was written with postgresql.ungram available from the start.
All nodes cross-checked in this single pass; the `AlterSubscription` finding
was independently confirmed against both the grammar and squawk.rs accessor
bodies, matching the same pattern already established for `AlterPublication`.

---

# Remaining Open Questions

1. Whether the positional-splitting strategy for `CreateSubscription`'s
   `SERVER` form (first `NameRef` = server name, remainder = publication
   list) is empirically reliable against real parsed output.

   **Current status: reasonably well-supported but not empirically verified.**

   Supporting evidence: `support::children()` in rowan-based ASTs iterates
   in source-text document order, since the underlying CST preserves the
   complete source text with all tokens. This is confirmed as a reliable
   property by the `ForeignKeyConstraint.from_columns()`/`to_columns()`
   handwritten extension (squawk.rs line 38440), which uses exactly this
   positional ordering guarantee (`nth(0)` = first `ColumnList` = FROM
   columns, `nth(1)` = second `ColumnList` = TO columns). An equivalent
   positional split for `CreateSubscription`'s `NameRef` children follows
   the identical logic.

   The caveat about the `SERVER` form's real-world PostgreSQL validity
   (noted in the `CreateSubscription` section above — standard PostgreSQL
   `CREATE SUBSCRIPTION` may only support `CONNECTION`, not `SERVER`) means
   this disambiguation may never be exercised in practice regardless. It is
   retained as a documented open question because:
   (a) the grammar explicitly supports it, and
   (b) it would be a subtle, silent correctness bug if the `SERVER` form
       ever is encountered and the positional split is wrong.

   Resolution path: run `SourceFile::parse("CREATE SUBSCRIPTION s SERVER
   srv PUBLICATION pub1, pub2")` and inspect the resulting syntax tree's
   `NameRef` children order. This requires a live squawk.rs test environment,
   not static analysis of source text.
