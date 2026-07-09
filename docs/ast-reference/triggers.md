# Triggers AST Reference for safe-migrate

## Status

Verified against squawk_syntax 2.58.0 — July 2026

---

## Documentation Contract

1. Only document AST behavior that has been directly verified.
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. Assume additional nodes or helpers may exist outside the inspected surface.

---

# Core Nodes

## CreateTrigger

### Verified Accessors (line 6762)

```rust
pub fn call_expr(&self) -> Option<CallExpr>
pub fn deferrable_constraint_option(&self) -> Option<DeferrableConstraintOption>
pub fn from_table(&self) -> Option<FromTable>
pub fn initially_deferred_constraint_option(&self) -> Option<InitiallyDeferredConstraintOption>
pub fn initially_immediate_constraint_option(&self) -> Option<InitiallyImmediateConstraintOption>
pub fn name(&self) -> Option<Name>
pub fn not_deferrable_constraint_option(&self) -> Option<NotDeferrableConstraintOption>
pub fn on_table(&self) -> Option<OnTable>
pub fn or_replace(&self) -> Option<OrReplace>
pub fn referencing(&self) -> Option<Referencing>
pub fn timing(&self) -> Option<Timing>
pub fn trigger_event_list(&self) -> Option<TriggerEventList>
pub fn when_condition(&self) -> Option<WhenCondition>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn constraint_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn each_token(&self) -> Option<SyntaxToken>
pub fn execute_token(&self) -> Option<SyntaxToken>
pub fn for_token(&self) -> Option<SyntaxToken>
pub fn function_token(&self) -> Option<SyntaxToken>
pub fn procedure_token(&self) -> Option<SyntaxToken>
pub fn row_token(&self) -> Option<SyntaxToken>
pub fn statement_token(&self) -> Option<SyntaxToken>
pub fn trigger_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
CreateTrigger =
  'create' OrReplace? 'constraint'? 'trigger' Name
  Timing
  TriggerEventList
  OnTable
  FromTable?
  DeferrableConstraintOption?
  NotDeferrableConstraintOption?
  InitiallyDeferredConstraintOption?
  InitiallyImmediateConstraintOption?
  Referencing?
  ('for' 'each'? ('row' | 'statement'))?
  WhenCondition?
  'execute' ('function' | 'procedure') CallExpr ';'?
```

Fully populated — every grammar field has a corresponding accessor. This is
one of the most completely extractable nodes in the entire AST surface
reviewed so far.

### Constraint Trigger Detection

`constraint_token().is_some()` distinguishes a `CREATE CONSTRAINT TRIGGER`
from a regular `CREATE TRIGGER`. Constraint triggers support deferred firing
via `DeferrableConstraintOption` / `NotDeferrableConstraintOption` /
`InitiallyDeferredConstraintOption` / `InitiallyImmediateConstraintOption` —
these four accessors (reusing the same constraint-deferral nodes documented
in constraints.md) are only meaningful when `constraint_token()` is present;
regular (non-constraint) triggers do not support deferred firing in
PostgreSQL even though the grammar does not structurally forbid parsing
these fields on a non-constraint trigger.

### FOR EACH ROW/STATEMENT Extraction

```rust
let for_each_row = row_token().is_some();
let for_each_statement = statement_token().is_some();
```

Neither token is on a dedicated wrapper node — both are flat tokens directly
on `CreateTrigger`, mutually exclusive per the grammar's `('row' |
'statement')` alternation. If `for_token()` is absent entirely, PostgreSQL
defaults to `FOR EACH STATEMENT`.

### Function vs Procedure Detection

```rust
let uses_function = function_token().is_some();  // EXECUTE FUNCTION
let uses_procedure = procedure_token().is_some(); // EXECUTE PROCEDURE (legacy alias)
```

`EXECUTE PROCEDURE` is a deprecated legacy spelling of `EXECUTE FUNCTION`
retained for backward compatibility — both invoke the same kind of object
(a trigger function), the keyword choice has no semantic effect.

### Event Detection

`trigger_event_list()` → `TriggerEventList.trigger_events()` →
`AstChildren<TriggerEvent>`. Multiple events combinable via `OR`:
`CREATE TRIGGER ... BEFORE INSERT OR UPDATE OR DELETE ON t ...`.

See `TriggerEvent` / `TriggerEventUpdate` sections below for the
column-specific `UPDATE OF col1, col2` extraction.

### Timing Extraction

`timing()` → `Timing`, a token-only node:
```rust
pub fn before_token(&self) -> Option<SyntaxToken>
pub fn after_token(&self) -> Option<SyntaxToken>
pub fn instead_token(&self) -> Option<SyntaxToken>
pub fn of_token(&self) -> Option<SyntaxToken>
```
`INSTEAD OF` is represented as two tokens (`instead_token()` +
`of_token()`), both must be checked together to confirm this timing variant
specifically (as opposed to `instead_token()` appearing in some other
unrelated context, though none exists for `Timing` itself since its grammar
only has the 3 alternatives shown).

### safe-migrate guidance

```rust
struct CreateTriggerFact {
    name: String,                          // from name()
    or_replace: bool,
    is_constraint_trigger: bool,           // from constraint_token()
    timing: TimingFact,                    // Before | After | InsteadOf
    events: Vec<TriggerEventFact>,         // from trigger_event_list()
    table: QualifiedName,                  // from on_table()
    from_table: Option<QualifiedName>,     // constraint trigger only, from from_table()
    for_each: ForEachFact,                 // Row | Statement (default Statement)
    when_condition: Option<ExprIr>,        // from when_condition()
    function: QualifiedName,               // from call_expr()
    referencing: Vec<ReferencingTableFact>, // from referencing()
}
```

**INSTEAD OF triggers are view-only** in PostgreSQL — they can only be
created on views, not tables. A rule validating `CreateTrigger` against the
target's kind (table vs view, tracked via `LocalState.relations`) should
flag `INSTEAD OF` triggers targeting a base table as a guaranteed PostgreSQL
failure.

---

## TriggerEvent (enum)

### Verified Members

```rust
pub enum TriggerEvent {
    TriggerEventUpdate(TriggerEventUpdate),
    // INSERT, DELETE, TRUNCATE represented as flat tokens, not enum variants
}
```

### Verified Accessors (line 20196)

```rust
pub fn trigger_event_update(&self) -> Option<TriggerEventUpdate>
pub fn delete_token(&self) -> Option<SyntaxToken>
pub fn insert_token(&self) -> Option<SyntaxToken>
pub fn truncate_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
TriggerEvent =
  'insert'
| 'delete'
| 'truncate'
| TriggerEventUpdate
```

**Important structural note:** `TriggerEvent` is not a 4-way Rust enum the
way `PartitionType` or `Constraint` are — `INSERT`/`DELETE`/`TRUNCATE` are
flat presence tokens directly on the `TriggerEvent` node itself, while
`UPDATE` is the only variant that wraps a real child node
(`TriggerEventUpdate`), because only `UPDATE` supports the `OF column_list`
qualifier.

### safe-migrate guidance

```rust
fn classify_trigger_event(event: &TriggerEvent) -> TriggerEventFact {
    if event.insert_token().is_some() {
        TriggerEventFact::Insert
    } else if event.delete_token().is_some() {
        TriggerEventFact::Delete
    } else if event.truncate_token().is_some() {
        TriggerEventFact::Truncate
    } else if let Some(update) = event.trigger_event_update() {
        TriggerEventFact::Update {
            columns: update.name_refs().map(|n| n.text()).collect(),
        }
    } else {
        TriggerEventFact::Unknown
    }
}
```

---

## TriggerEventUpdate

### Verified Accessors (line 20230)

```rust
pub fn name_refs(&self) -> AstChildren<NameRef>
pub fn of_token(&self) -> Option<SyntaxToken>
pub fn update_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
TriggerEventUpdate =
  'update'
  ('of' (NameRef (',' NameRef)*))?
```

`UPDATE OF col1, col2` is fully extractable via `name_refs()`. When
`of_token()` is absent, the trigger fires on `UPDATE` of any column —
`name_refs()` will be empty in that case, and this must be distinguished
from "trigger fires on update of zero columns" (which is not a real
PostgreSQL state) by checking `of_token().is_some()` first.

### safe-migrate guidance

A column-specific `UPDATE OF` trigger is relevant to safe-migrate's
column-rename and column-drop safety analysis: renaming or dropping a column
referenced in a trigger's `OF column_list` should be flagged, since the
trigger definition becomes stale or references a now-nonexistent column.

---

## Timing, Referencing, ReferencingTable

### Timing — Verified Accessors (line 20074)

```rust
pub fn after_token(&self) -> Option<SyntaxToken>
pub fn before_token(&self) -> Option<SyntaxToken>
pub fn instead_token(&self) -> Option<SyntaxToken>
pub fn of_token(&self) -> Option<SyntaxToken>
```

Already covered above under `CreateTrigger`'s Timing Extraction section.

### Referencing — Verified Accessors (line 16700)

```rust
pub fn referencing_tables(&self) -> AstChildren<ReferencingTable>
pub fn referencing_token(&self) -> Option<SyntaxToken>
```

### ReferencingTable — Verified Accessors (line 16715)

```rust
pub fn name_ref(&self) -> Option<NameRef>
pub fn as_token(&self) -> Option<SyntaxToken>
pub fn new_token(&self) -> Option<SyntaxToken>
pub fn old_token(&self) -> Option<SyntaxToken>
pub fn table_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
Referencing =
  'referencing' ReferencingTable*

ReferencingTable =
  ('old' | 'new') 'table' 'as'? NameRef
```

Represents `REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows` —
PostgreSQL's transition table feature for statement-level triggers, allowing
the trigger function to see the full set of rows affected by the triggering
statement, not just one row at a time.

### safe-migrate guidance

```rust
struct ReferencingTableFact {
    is_old: bool,        // from old_token().is_some()
    is_new: bool,         // from new_token().is_some() (mutually exclusive with is_old)
    alias: String,        // from name_ref().text()
}
```

---

## DropTrigger

### Verified Accessors (line 9483)

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn on_table(&self) -> Option<OnTable>
pub fn path(&self) -> Option<Path>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn restrict_token(&self) -> Option<SyntaxToken>
pub fn trigger_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
DropTrigger =
  'drop' 'trigger' IfExists? Path OnTable
  ('cascade' | 'restrict')? ';'?
```

Single trigger name only (`path()`, not plural) — unlike most other `Drop*`
nodes in this AST surface (`DropSequence`, `DropType`, `DropSchema`,
`DropMaterializedView`, `DropDomain`), `DropTrigger` does **not** support
multiple trigger names per statement, matching real PostgreSQL syntax
(`DROP TRIGGER` only ever takes one trigger name, since trigger names are
scoped per-table and `ON table_name` is a required singular clause).

---

## AlterTrigger

### Verified Accessors (line 2680)

```rust
pub fn depends_on_extension(&self) -> Option<DependsOnExtension>
pub fn name_ref(&self) -> Option<NameRef>
pub fn no_depends_on_extension(&self) -> Option<NoDependsOnExtension>
pub fn on_table(&self) -> Option<OnTable>
pub fn rename_to(&self) -> Option<RenameTo>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn trigger_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
AlterTrigger =
  'alter' 'trigger' NameRef OnTable
  (
    RenameTo
  | DependsOnExtension
  | NoDependsOnExtension
  ) ';'?
```

3 mutually exclusive forms confirmed, all with direct accessors. Fully resolved.

### safe-migrate guidance

```rust
enum AlterTriggerFact {
    Rename { table: QualifiedName, from: String, to: String },
    DependsOnExtension { table: QualifiedName, trigger: String, extension: String },
    NoDependsOnExtension { table: QualifiedName, trigger: String, extension: String },
}
```

`DEPENDS ON EXTENSION` marks the trigger as an internal dependency of an
extension — if that extension is later dropped, the trigger drops with it
automatically. This is relevant to the dependency graph: a trigger with this
marking should be linked to its owning extension as an additional edge, not
treated as an independent object.

---

## ALTER TABLE ... ENABLE/DISABLE TRIGGER

These appear as `AlterTableAction` variants (documented as such in the
original AST inventory used to bootstrap this documentation set), not as
standalone top-level statements. PostgreSQL syntax:

```sql
ALTER TABLE t ENABLE TRIGGER trigger_name;
ALTER TABLE t ENABLE TRIGGER ALL;
ALTER TABLE t ENABLE TRIGGER USER;
ALTER TABLE t ENABLE ALWAYS TRIGGER trigger_name;
ALTER TABLE t ENABLE REPLICA TRIGGER trigger_name;
ALTER TABLE t DISABLE TRIGGER trigger_name;
```

### Verified Accessors

```rust
// EnableTrigger (line 10158)
pub fn name_ref(&self) -> Option<NameRef>      // target trigger name
pub fn all_token(&self) -> Option<SyntaxToken> // ALL indicator
pub fn enable_token(&self) -> Option<SyntaxToken>
pub fn trigger_token(&self) -> Option<SyntaxToken>

// DisableTrigger (line 7635)
pub fn name_ref(&self) -> Option<NameRef>      // target trigger name
pub fn all_token(&self) -> Option<SyntaxToken> // ALL indicator
pub fn user_token(&self) -> Option<SyntaxToken> // USER indicator
pub fn disable_token(&self) -> Option<SyntaxToken>
pub fn trigger_token(&self) -> Option<SyntaxToken>

// EnableAlwaysTrigger (line 10047)
pub fn name_ref(&self) -> Option<NameRef>      // target trigger name
pub fn always_token(&self) -> Option<SyntaxToken>
pub fn enable_token(&self) -> Option<SyntaxToken>
pub fn trigger_token(&self) -> Option<SyntaxToken>

// EnableReplicaTrigger (line 10093)
pub fn name_ref(&self) -> Option<NameRef>      // target trigger name
pub fn enable_token(&self) -> Option<SyntaxToken>
pub fn replica_token(&self) -> Option<SyntaxToken>
pub fn trigger_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
EnableTrigger =
  'enable' 'trigger' NameRef ('all' | 'user')?

EnableReplicaTrigger =
  'enable' 'replica' 'trigger' NameRef ('all' | 'user')?

EnableAlwaysTrigger =
  'enable' 'always' 'trigger' NameRef ('all' | 'user')?

DisableTrigger =
  'disable' 'trigger' NameRef ('all' | 'user')?
```

### Target Trigger Name & ALL/USER Extraction (Verified)

Contrary to earlier assumptions, all four variants are **not** token-only.
Each carries a `name_ref()` child node that yields the target trigger name,
plus optional `all_token()` / `user_token()` presence flags. This was verified
directly against `src/ast/generated/nodes.rs` (lines 7635, 10047, 10093,
10158) for all four node types — every node exposes `name_ref()` returning an
`Option<NameRef>`, and `DisableTrigger` additionally exposes both `all_token()`
and `user_token()`.

**This means: `ALTER TABLE t ENABLE TRIGGER trigger_name` can be fully
resolved** — the `name_ref()` accessor provides the specific trigger being
toggled, and `all_token()` / `user_token()` indicate the `ALL` / `USER`
special forms. A rule evaluating trigger enable/disable safety can therefore
distinguish disabling a specific critical audit trigger from a harmless
logging trigger, and can confirm whether `ALL` triggers (including
constraint-enforcing ones) were targeted.

### safe-migrate guidance

```rust
enum TriggerToggleFact {
    Enable      { trigger: String, scope: ToggleScope },
    EnableAlways{ trigger: String, scope: ToggleScope },
    EnableReplica { trigger: String, scope: ToggleScope },
    Disable     { trigger: String, scope: ToggleScope },
}

enum ToggleScope { Named, All, User }
// scope derived from name_ref() + all_token()/user_token() presence
```

A trigger toggle can now be evaluated precisely: `Disable { trigger, scope: All }`
is the highest-risk form (disables every trigger including integrity-enforcing
ones) and should be flagged at minimum tier-2 (warning). A named disable of a
specific trigger can be cross-referenced against the dependency graph to assess
whether an integrity-critical trigger is affected.

---

# Verified Findings Summary

## Confirmed Complete

- `CreateTrigger`: fully resolved, fully populated accessor surface
- `TriggerEvent` / `TriggerEventList` / `TriggerEventUpdate`: fully resolved
- `Timing`: fully resolved
- `Referencing` / `ReferencingTable`: fully resolved
- `DropTrigger`: fully resolved, single-name-only confirmed correct per
  PostgreSQL semantics (not a gap, matches real SQL grammar)
- `AlterTrigger`: fully resolved, all 3 forms verified

## Grammar-Confirmed Capabilities

- `EnableTrigger`, `DisableTrigger`, `EnableAlwaysTrigger`,
  `EnableReplicaTrigger`: each carries a `name_ref()` child node (target
  trigger name) plus optional `all_token()` / `user_token()` presence flags.
  The specific trigger being toggled (and whether `ALL`/`USER` is targeted)
  is fully extractable. Cross-referencing the named trigger against the
  dependency graph allows precise safety evaluation of enable/disable
  operations. Significant safety-relevant capability for safe-migrate.

## Grammar Cross-Check

This document was cross-checked against `src/ast/generated/nodes.rs` and `src/ast/node_ext.rs` from `squawk-syntax-2.58.0`. All generated trigger-related node accessors (such as `CreateTrigger` at line 6762 and `AlterTrigger` at line 2680) have been verified against these source files alongside `postgresql.ungram`, including a follow-up check of `AlterTableAction`'s grammar shape that fully resolved the enable/disable trigger name question as a confirmed, final limitation rather than an open accessor-location question.

---

# Remaining Open Questions

None remaining. The earlier assumption that `EnableTrigger` (and the other
three variants) were flat, token-only alternatives inside `AlterTableAction`
has been corrected: `src/ast/generated/nodes.rs` confirms each variant carries
a `name_ref()` child node for the target trigger name. The trigger name and
`ALL`/`USER` scope are fully extractable, so no grammar-level gap remains for
trigger enable/disable name resolution.
