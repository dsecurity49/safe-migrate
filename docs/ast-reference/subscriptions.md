# Subscriptions AST Reference for safe-migrate

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

### Verified Accessors (line 2249)

```rust
pub fn attribute_list(&self) -> Option<AttributeList>
pub fn literal(&self) -> Option<Literal>
pub fn name_ref(&self) -> Option<NameRef>
pub fn name_refs(&self) -> AstChildren<NameRef>
pub fn names(&self) -> AstChildren<Name>
pub fn owner_to(&self) -> Option<OwnerTo>
pub fn rename_to(&self) -> Option<RenameTo>
pub fn set_options(&self) -> Option<SetOptions>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn add_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn connection_token(&self) -> Option<SyntaxToken>
pub fn disable_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn enable_token(&self) -> Option<SyntaxToken>
pub fn publication_token(&self) -> Option<SyntaxToken>
pub fn refresh_token(&self) -> Option<SyntaxToken>
pub fn server_token(&self) -> Option<SyntaxToken>
pub fn set_token(&self) -> Option<SyntaxToken>
pub fn skip_token(&self) -> Option<SyntaxToken>
pub fn subscription_token(&self) -> Option<SyntaxToken>
pub fn with_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation — CORRECTION

```
AlterSubscription =
  'alter' 'subscription' NameRef
  ( ConnectionTarget            # connection_token() / server_token() + literal()/name_ref()
  | SetPublication              # set_token()/add_token()/drop_token() + publication_token() + name_refs()
  | RefreshPublication          # refresh_token()
  | Enable                      # enable_token()
  | Disable                     # disable_token()
  | SetOptions                  # set_token() + set_options()/attribute_list()
  | Skip                        # skip_token()
  | OwnerTo                     # owner_to()
  | RenameTo                    # rename_to()
  )? ';'?
```

**Correction:** An earlier draft claimed `AlterSubscription` was a black
box carrying "genuinely nothing beyond the subscription's own name." That
was incorrect. The actual node (line 2249) exposes a full set of token
accessors (`enable_token()`, `disable_token()`, `refresh_token()`,
`set_token()`, `skip_token()`, `add_token()`, `drop_token()`,
`connection_token()`, `server_token()`, `publication_token()`) plus child
accessors (`owner_to()`, `rename_to()`, `set_options()`, `attribute_list()`,
`name_refs()`, `literal()`). The operation type CAN be inferred from which
token/child accessors return `Some(...)`:

| Operation | Detecting accessor(s) |
|-----------|----------------------|
| `CONNECTION 'conninfo'` | `connection_token()` + `literal()` |
| `SERVER name` | `server_token()` + `name_ref()` |
| `SET PUBLICATION ...` | `set_token()` + `publication_token()` + `name_refs()` |
| `ADD PUBLICATION ...` | `add_token()` + `publication_token()` + `name_refs()` |
| `DROP PUBLICATION ...` | `drop_token()` + `publication_token()` + `name_refs()` |
| `REFRESH PUBLICATION` | `refresh_token()` |
| `ENABLE` | `enable_token()` |
| `DISABLE` | `disable_token()` |
| `SET (param = value)` | `set_token()` + `set_options()` / `attribute_list()` |
| `SKIP (...)` | `skip_token()` |
| `OWNER TO new_owner` | `owner_to()` |
| `RENAME TO new_name` | `rename_to()` |

The publication/table list for the SET/ADD/DROP PUBLICATION forms is
extractable via `name_refs()` (all `NameRef` children under those forms).
This matches the same rich extraction available for `CreateSubscription`.

Real PostgreSQL `ALTER SUBSCRIPTION` operations are therefore distinguishable
**at the operation-type level** via the token accessors above. (Fine-grained
parameter payloads may still require descending into `set_options()` /
`attribute_list()` / `literal()` — verified available.)

### safe-migrate guidance

```rust
enum AlterSubscriptionOp {
    Connection { conn: Option<Literal> },
    Server { server: Option<NameRef> },
    SetPublication { pubs: Vec<String> },   // via name_refs()
    AddPublication { pubs: Vec<String> },
    DropPublication { pubs: Vec<String> },
    Refresh,
    Enable,
    Disable,
    SetOptions { opts: Option<SetOptions> }, // via set_options()/attribute_list()
    Skip,
    OwnerTo { owner: Option<OwnerTo> },
    RenameTo { to: Option<RenameTo> },
}

struct AlterSubscriptionFact {
    name: String,                  // from name_ref()
    operation: AlterSubscriptionOp, // inferred from token/child accessors
}
```

Because the operation type IS extractable, safe-migrate should branch on the
detected `AlterSubscriptionOp` rather than blanket-tainting every statement.
`ENABLE`/`DISABLE`/`DROP PUBLICATION` remain operationally critical (they
control whether replication is running and what data flows) and should still
be flagged for review — but now the simulator knows *which* operation
occurred, not just that "an alter happened."

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

- `AlterSubscription`: earlier draft claimed it carried "nothing beyond the
  subscription name" (black box). **Corrected** — the node (line 2249)
  exposes a full operation-distinguishing accessor surface: token accessors
  (`enable_token()`, `disable_token()`, `refresh_token()`, `set_token()`,
  `skip_token()`, `add_token()`, `drop_token()`, `connection_token()`,
  `server_token()`, `publication_token()`) and child accessors
  (`owner_to()`, `rename_to()`, `set_options()`, `attribute_list()`,
  `name_refs()`, `literal()`). The operation type IS extractable, and the
  publication/table list for SET/ADD/DROP PUBLICATION is extractable via
  `name_refs()`. The only genuine limitation is that fine-grained parameter
  payloads require descending into `set_options()`/`attribute_list()`.

## Key Architectural Findings

1. **`CreateSubscription`'s `SERVER` form has a confirmed, real
   disambiguation ambiguity** that has no clean resolution via existing
   accessors — this should be flagged for empirical testing against actual
   parsed output before any safe-migrate code relies on the proposed
   positional-splitting workaround.
2. **`AlterSubscription` is a structured node, not a black box** — its
   operation type is inferable from token/child accessors (see the
   AlterSubscription section). `ENABLE`/`DISABLE`/`DROP PUBLICATION` remain
   operationally critical and should still be flagged for review, but the
   simulator can now branch on the detected operation rather than
   blanket-tainting every statement. (The `AlterPublication` finding in
   publications.md is a separate, still-valid black-box finding.)

## Grammar Cross-Check

This document was written with postgresql.ungram available from the start.
All nodes cross-checked in this single pass. The `AlterSubscription` finding
was re-verified against the actual node (line 2249) and corrected: it is
structured, not a black box.

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
