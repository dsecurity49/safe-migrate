# Non-Schema Side Effects Reference for safe-migrate

## Status

Verified against squawk_syntax 2.58.0 — July 2026


Cross-references: search_path.md, transactions.md, functions.md,
triggers.md, sequences.md, materialized_views.md, database.md,
roles.md, grant_revoke.md, security_model.md.

---

## The Core Distinction

Safe-migrate's `LocalState` models **schema structure** — what objects exist,
their shapes, their constraints, their dependencies. But many PostgreSQL DDL
and configuration statements affect **runtime behavior** without changing
schema structure at all. These are non-schema side effects.

```
Schema-structural mutation:
  ALTER TABLE t DROP COLUMN c
  → LocalState changes: column c removed from relation t's ColumnSet
  → Detectable as structural risk: existing queries SELECT c FROM t break

Non-schema side effect:
  ALTER DATABASE db SET search_path = ''
  → LocalState changes: none to schema structure
  → Runtime behavioral change: all new connections resolve names differently
  → Detectable: yes (database.md) | Value extractable: YES (via literals())
```

The simulator's job for non-schema effects is different: rather than
computing "will this break existing schema consumers," it must detect "did
this change runtime behavior in a way that affects migration safety or
subsequent statement interpretation."

---

## Taxonomy of Non-Schema Side Effects

### Category 1: Session/Connection Context Changes

These change the environment in which subsequent SQL executes. They directly
affect the simulator's sequential model.

| Operation | AST Node | Value Extractable? | Scope |
|-----------|----------|-------------------|-------|
| `SET search_path` | `Set` (search_path.md) | YES | Session or LOCAL |
| `SET LOCAL search_path` | `Set` | YES | Transaction-local |
| `RESET search_path` | `Reset` | N/A (removal) | Session |
| `SET ROLE role` | `SetRole` (roles.md) | YES | Session or LOCAL |
| `SET SESSION AUTHORIZATION` | `SetSessionAuth` | YES | Session |
| `RESET SESSION AUTHORIZATION` | `ResetSessionAuth` | N/A | Session |
| `ALTER DATABASE db SET search_path` | `SetConfigParam` (database.md) | YES (via literals()) | Future sessions only |
| `ALTER ROLE r SET search_path` | `SetConfigParam` via `AlterRole` | NOT EXTRACTABLE (AlterRole black box) | Future sessions for role |

**Simulator handling:** SESSION-scope changes apply immediately and persist
for the rest of the migration. LOCAL-scope changes apply within the current
`TransactionFrame` and must be recorded in the undo log (transactions.md)
for rollback on transaction abort. Future-session changes (ALTER DATABASE,
ALTER ROLE) affect sessions not yet started — they do not affect the current
simulation but should be flagged for documentation.

### Category 2: Replication State Changes

These affect the logical replication stream — what data reaches subscribers
and whether replication is active at all.

| Operation | AST Node | Extractable? | Notes |
|-----------|----------|-------------|-------|
| `CREATE PUBLICATION` | `CreatePublication` (publications.md) | YES | Starts publishing |
| `DROP PUBLICATION` | `DropPublication` | YES | Stops publishing; breaks subscribers |
| `ALTER PUBLICATION` | `AlterPublication` | NAME ONLY (grammar gap) | Cannot determine which tables added/dropped |
| `CREATE SUBSCRIPTION` | `CreateSubscription` | YES | Starts replication; initial data copy |
| `DROP SUBSCRIPTION` | `DropSubscription` | YES | Stops replication; drops replication slot |
| `ALTER SUBSCRIPTION` | `AlterSubscription` | NAME ONLY (grammar gap) | Cannot determine if ENABLE/DISABLE/table change |

**Simulator handling:** Replication changes have external-system blast
radius — they affect the remote publisher or subscriber, not just the
local schema. Flag all `AlterPublication`/`AlterSubscription` statements
as `Confidence::Tainted` + manual review required. Track `CreatePublication`
scope (FOR ALL TABLES vs explicit list) since it has forward-in-time effects
on tables created later in the same migration.

### Category 3: Configuration Parameter Changes

These change PostgreSQL's runtime configuration, affecting query planning,
execution behavior, and connection policies.

| Operation | AST Node | Param Extractable? | Value Extractable? |
|-----------|----------|-------------------|-------------------|
| `SET param = value` | `Set` (search_path.md) | YES (via path()) | YES (via config_values()) |
| `RESET param` | `Reset` | YES | N/A |
| `ALTER DATABASE db SET param` | `SetConfigParam` (database.md) | YES | YES (via literals()) |
| `ALTER ROLE r SET param` | inside `AlterRole` black box | NO | NO |
| `CREATE FUNCTION ... SET param` | `SetFuncOption` (functions.md) | NO | NO (grammar gap) |

**Simulator handling:** `SET` statement-level changes are fully extractable
and must update `LocalState` (particularly for `search_path`). Grammar-gap
cases (`ALTER DATABASE SET`, function-body `SET`) should be flagged as
context-changing unknowns.

### Category 4: Trigger Enable/Disable

Enabling or disabling a trigger changes runtime data-modification behavior
without touching schema structure. This is distinct from dropping a trigger
(which is structural).

| Operation | AST Node | Target Extractable? | Notes |
|-----------|----------|---------------------|-------|
| `ALTER TABLE t ENABLE TRIGGER name` | `EnableTrigger` (triggers.md) | NO (grammar gap) | Trigger name not captured |
| `ALTER TABLE t DISABLE TRIGGER name` | `DisableTrigger` | NO (grammar gap) | Trigger name not captured |
| `ALTER TABLE t ENABLE ALWAYS TRIGGER name` | `EnableAlwaysTrigger` | NO (grammar gap) | |
| `ALTER TABLE t ENABLE REPLICA TRIGGER name` | `EnableReplicaTrigger` | NO (grammar gap) | |

**This is the most safety-relevant non-schema category** after replication.
Disabling a trigger that enforces a data integrity invariant (e.g. an audit
trigger, a denormalization-sync trigger, a cross-table consistency trigger)
while performing writes is a known risky migration pattern. The simulator
cannot determine which trigger was disabled — it can only detect that *some*
trigger was toggled on table T.

**Simulator handling:** Any `DisableTrigger` action should be flagged as
tier-2 (warning) minimum. If `LocalState` tracks which triggers exist on a
table (populated during `CreateTrigger` processing), and the table is then
written to within the same migration after a `DisableTrigger` action, this
should escalate to tier-1 (block) — the simulator knows triggers exist but
cannot confirm which ones were disabled.

### Category 5: Sequence State Changes

Sequences are structural objects but their *current value* is runtime state
not captured in the schema. Two non-schema side effects are relevant:

| Operation | AST Node | Notes |
|-----------|----------|-------|
| `ALTER SEQUENCE ... RESTART` | via `AlterSequence` (sequences.md) | Resets next value; `AlterSequence` carries no options (grammar gap) |
| `ALTER COLUMN ... RESTART` | `Restart` as `AlterColumnOption` (columns.md) | YES (via literal()) |

**Simulator handling:** Sequence restarts can cause duplicate-key violations
if the restarted value overlaps with existing data. This is a runtime
concern, not structural. For `ALTER COLUMN ... RESTART`, the restart target
IS available via `Restart.literal()` (the AST provides it). For
`ALTER SEQUENCE ... RESTART`, `AlterSequence` carries no options (grammar
gap), so the restart target is not extractable. In both cases the simulator
still needs the current max value in the table (from pg_catalog, which
DbCache can provide) to confirm whether an overlap risk exists.

### Category 6: Materialized View Population State

Documented in detail in materialized_views.md. Summary:

| Operation | Effect |
|-----------|--------|
| `CREATE MATERIALIZED VIEW ... WITH NO DATA` | Creates unscannable object |
| `REFRESH MATERIALIZED VIEW ... WITH NO DATA` | Returns populated view to unscannable state |
| `REFRESH MATERIALIZED VIEW` | Populates or re-populates |

**Simulator handling:** `LocalState` must track `population_state:
PopulationState` per materialized view and update it on every `Refresh`
statement. A query against an unpopulated materialized view is a guaranteed
runtime failure — detectable through sequential simulation.

### Category 7: Transaction Control Side Effects

Documented in detail in transactions.md. Summary of non-schema effects:

| Operation | Effect |
|-----------|--------|
| `BEGIN READ ONLY` | Any DDL within this transaction will fail |
| `SET CONSTRAINTS DEFERRED` | Defers constraint validation to commit time |
| `SAVEPOINT` / `ROLLBACK TO SAVEPOINT` | Partial undo within transaction |
| `PREPARE TRANSACTION` | Two-phase commit — transaction persists across sessions |

**Simulator handling:** `TransactionFrame` must record isolation level and
read/write mode on `BEGIN`. DDL statements inside a `READ ONLY` transaction
are guaranteed failures — tier-1 block. `PREPARE TRANSACTION` is an opaque
two-phase commit entry point — the simulator cannot follow the subsequent
`COMMIT PREPARED` / `ROLLBACK PREPARED` from a different session.

### Category 8: Lock Acquisition

`LOCK TABLE t IN ACCESS EXCLUSIVE MODE` is the canonical migration
pattern — takes an exclusive lock that blocks all readers and writers.
Not a schema change, but a runtime-behavioral event with operational impact.

The `Lock` node (`lock()` → `table_list()` → `relation_names()`) is fully
extractable from the AST (not documented separately since it has no
safe-migrate-specific safety implications beyond noting lock acquisition).
Safe-migrate may want to flag explicit `LOCK TABLE` statements as indicative
of a migration that will cause application downtime proportional to the
lock duration — operational concern, not schema concern.

---

## The "Opaque Mutation" Category

The blueprint defines `OpaqueMutation` for operations safe-migrate
fundamentally cannot simulate:

```rust
pub enum OpaqueMutation {
    DoBlock,        // DO $$ ... $$ — anonymous code block, body not parsed
    Execute,        // EXECUTE stmt — dynamic SQL, target unknown
    DynamicSql,     // any statement where the SQL itself is a runtime value
}
```

Non-schema side effects that fall into `OpaqueMutation` territory:

- **`DO $$ BEGIN ... END $$`** — the body is an opaque string literal. Any
  DDL, privilege change, or configuration change inside the body is
  completely invisible to the simulator. This is the highest-risk opaque
  pattern in migrations — a `DO` block can perform arbitrary schema changes
  that the simulator's sequential model cannot see.
- **`EXECUTE format('ALTER TABLE %I ...')`** — dynamic SQL where the actual
  statement is constructed at runtime. Target object and operation are both
  unknown.
- **Function bodies in non-SQL languages** — `plpgsql`, `python3`, `c`, etc.
  function bodies are opaque strings in this AST (unless using `BEGIN ATOMIC`
  — see functions.md). Any schema changes inside a plpgsql function cannot
  be analyzed.

**Simulator handling:** All `OpaqueMutation` variants must downgrade
`Confidence` to `Tainted` for the remainder of the migration simulation,
since the simulator cannot know what state changes occurred inside the
opaque block.

---

## Integration with LocalState

Non-schema effects that require `LocalState` tracking:

```rust
// Add to LocalState or AnalysisState:
struct RuntimeContext {
    // Category 1: Active search_path (updated by SET/RESET)
    search_path: Vec<String>,           // current effective search_path

    // Category 1: Active role context (updated by SET ROLE)
    effective_role: Option<RoleFact>,   // None = original login role

    // Category 3: Known config param changes (session-level only)
    config_params: HashMap<String, ConfigValue>,

    // Category 4: Per-table trigger state (presence, not which was toggled)
    trigger_activity: HashMap<ObjectId, TriggerActivityState>,

    // Category 6: Materialized view population state
    mv_population: HashMap<ObjectId, PopulationState>,

    // Replication state
    publications: HashMap<String, PublicationFact>,
    subscriptions: HashMap<String, SubscriptionFact>,
}

enum TriggerActivityState {
    Unknown,          // no enable/disable seen yet
    MaybeDisabled,    // a DisableTrigger action was seen; specific trigger unknown
}
```

These are tracked in addition to (not instead of) the main schema-structural
`relations` HashMap — they are runtime context, not schema definitions.

---

## Summary Table — Non-Schema Effects by Priority

| Effect | Detectable? | Value Known? | Priority for Safe-Migrate |
|--------|------------|-------------|--------------------------|
| `SET search_path` (session) | YES | YES | Critical — affects all subsequent resolution |
| `DisableTrigger` (any) | Partial (table only) | NO (which trigger) | High — integrity risk |
| `AlterPublication`/`AlterSubscription` | Name only | NO (operation) | High — replication blast radius |
| `AlterRole`/`AlterUser` | Name only | NO (operation) | High — auth/privilege unknown change |
| `DO $$ ... $$` | YES (presence) | NO (body) | High — all state unknown after this |
| `SET ROLE` / role context | YES | YES | Medium — affects ownership resolution |
| `RefreshMV WITH NO DATA` | YES | N/A | Medium — next query against this MV fails |
| `ALTER DATABASE SET search_path` | YES (param + value via literals()) | YES (via literals()) | Medium — future sessions affected |
| `LOCK TABLE` | YES | YES (table) | Low — operational, not correctness |
| `SEQUENCE RESTART` | YES (presence) | NO (restart value) | Low — duplicate-key risk only if overlapping |
| `PREPARE TRANSACTION` | YES | YES (XID) | Low — cross-session, not in current migration |

---

## AST Reference: Expressions, Operators, and Call Nodes

### 1. The `Expr` Enum

The `Expr` enum represents all SQL expressions parsed by `squawk_syntax`. Every variant of `Expr` wraps a corresponding AST node structure of the same name. In safe-migrate's [expr_visitor.rs](file:///data/data/com.termux/files/home/safe-migrate/src/analysis/expr_visitor.rs), the [ExprVisitor](file:///data/data/com.termux/files/home/safe-migrate/src/analysis/expr_visitor.rs#L5)'s [convert](file:///data/data/com.termux/files/home/safe-migrate/src/analysis/expr_visitor.rs#L8) method maps these to intermediate representation.

| Variant | Wrapped AST Node | Description | Handled in [expr_visitor.rs](file:///data/data/com.termux/files/home/safe-migrate/src/analysis/expr_visitor.rs)? |
|---------|------------------|-------------|------------------------------|
| `ArrayExpr` | `ArrayExpr` | Array literal or constructor (e.g., `ARRAY[1, 2]`) | Yes |
| `BetweenExpr` | `BetweenExpr` | Range comparison expression (e.g., `x BETWEEN y AND z`) | Yes |
| `BinExpr` | `BinExpr` | Binary operator expression (e.g., `x + y`) | Yes |
| `CallExpr` | `CallExpr` | Function or operator call expression (e.g., `func(x, y)`) | Yes (via [convert_call_expr](file:///data/data/com.termux/files/home/safe-migrate/src/analysis/expr_visitor.rs#L43)) |
| `CaseExpr` | `CaseExpr` | Conditional CASE expression | Yes |
| `CastExpr` | `CastExpr` | Type cast expression (e.g., `x::type` or `CAST(x AS type)`) | Yes |
| `FieldExpr` | `FieldExpr` | Composite field selection (e.g., `(composite_val).field`) | Yes |
| `IndexExpr` | `IndexExpr` | Array/container indexing (e.g., `arr[i]`) | Yes |
| `Literal` | `Literal` | Constant literal value (e.g., `'text'`, `42`, `NULL`) | Yes |
| `NameRef` | `NameRef` | Identifier reference to a column or variable | Yes |
| `ParenExpr` | `ParenExpr` | Parenthesized expression (e.g., `(expr)`) | Yes |
| `PostfixExpr` | `PostfixExpr` | Postfix operator expression (e.g., `expr IS NULL`) | Yes |
| `PrefixExpr` | `PrefixExpr` | Prefix operator expression (e.g., `-expr` or `NOT expr`) | Yes |
| `SliceExpr` | `SliceExpr` | Array slicing expression (e.g., `arr[i:j]`) | Yes |
| `TupleExpr` | `TupleExpr` | Row/tuple constructor expression (e.g., `(x, y, z)`) | **No** (Falls back to `_` wildcard mapping to `ExprIr::Literal("<complex>")`) |

> [!NOTE]
> `TupleExpr` is the only variant not explicitly handled by [ExprVisitor](file:///data/data/com.termux/files/home/safe-migrate/src/analysis/expr_visitor.rs#L5)'s [convert](file:///data/data/com.termux/files/home/safe-migrate/src/analysis/expr_visitor.rs#L8) method. It falls back to `_` mapping to `ExprIr::Literal("<complex>".into())`.

---

### 2. CallExpr and Arg Nodes

In `squawk_syntax` >= 2.58.0, function call syntax is structured to support complex argument clauses (such as named arguments, order-by specifications, and variadic keyword prefixes).

* **`CallExpr`** represents function/procedure call expressions. Calling `arg_list()` on a `CallExpr` returns an `Option<ArgList>` rather than direct expressions.
* **`ArgList`** acts as the container for call arguments and optional modifier tokens. It exposes:
  * `args() -> AstChildren<Arg>`: An iterator over the argument wrapper nodes.
  * `distinct_token() -> Option<SyntaxToken>`: Captures the `DISTINCT` keyword if present (e.g., `count(DISTINCT x)`).
  * `all_token() -> Option<SyntaxToken>`: Captures the `ALL` keyword.
  * `star_token() -> Option<SyntaxToken>`: Captures a star argument (e.g., `count(*)`).
* **`Arg`** is a wrapper node that encapsulates the expression itself along with positional or semantic decorators:
  * `expr() -> Option<Expr>`: Retrieves the underlying expression node being passed.
  * `named_arg() -> Option<NamedArg>`: Retrieves the `NamedArg` node if the argument is named (e.g., `argname => expression`).
  * `order_by_clause() -> Option<OrderByClause>`: Retrieves the `OrderByClause` node if the argument contains a local ordering (e.g., `string_agg(name ORDER BY name)`).
  * `variadic_token() -> Option<SyntaxToken>`: Retrieves the `VARIADIC` keyword token if present (e.g., `func(VARIADIC arr)`).

---

### 3. The BinOp Enum

The `BinOp` enum lists all binary operators that can appear within a `BinExpr`. 

#### The Escape Operator
In `squawk_syntax` 2.58.0, the **`Escape`** variant was added to represent the `ESCAPE` clause in pattern matches (e.g., `col LIKE 'pattern' ESCAPE '!'`). It wraps a `SyntaxToken`. This variant is handled in [convert_bin_expr](file:///data/data/com.termux/files/home/safe-migrate/src/analysis/expr_visitor.rs#L66).

#### Full List of Variants
Below is the complete catalog of `BinOp` enum variants and their corresponding inner structures in `squawk_syntax` 2.58.0:

1. **`And(SyntaxToken)`**: Logical AND (`AND`)
2. **`AtTimeZone(AtTimeZone)`**: Time zone conversion (`AT TIME ZONE`)
3. **`Caret(SyntaxToken)`**: Exponentiation operator (`^`)
4. **`Collate(SyntaxToken)`**: Collation override operator (`COLLATE`)
5. **`ColonColon(ColonColon)`**: Type cast operator (`::`)
6. **`ColonEq(SyntaxToken)`**: Variable assignment operator (`:=`)
7. **`CustomOp(CustomOp)`**: User-defined/custom operator (e.g., `@@`, `|/`)
8. **`Eq(SyntaxToken)`**: Equality operator (`=`)
9. **`Escape(SyntaxToken)`**: Escape character clause operator (`ESCAPE`) *(added in 2.58.0)*
10. **`FatArrow(SyntaxToken)`**: Named argument bind operator (`=>`)
11. **`Gteq(SyntaxToken)`**: Greater than or equal operator (`>=`)
12. **`Ilike(SyntaxToken)`**: Case-insensitive pattern match operator (`ILIKE`)
13. **`In(SyntaxToken)`**: Set membership operator (`IN`)
14. **`Is(SyntaxToken)`**: Identity comparison operator (`IS`)
15. **`IsDistinctFrom(IsDistinctFrom)`**: Distinct comparison operator (`IS DISTINCT FROM`)
16. **`IsNot(IsNot)`**: Negated identity comparison operator (`IS NOT`)
17. **`IsNotDistinctFrom(IsNotDistinctFrom)`**: Negated distinct comparison operator (`IS NOT DISTINCT FROM`)
18. **`LAngle(SyntaxToken)`**: Less than operator (`<`)
19. **`Like(SyntaxToken)`**: Pattern match operator (`LIKE`)
20. **`Lteq(SyntaxToken)`**: Less than or equal operator (`<=`)
21. **`Minus(SyntaxToken)`**: Subtraction operator (`-`)
22. **`Neq(SyntaxToken)`**: Inequality operator (`!=` / `<>`)
23. **`Neqb(SyntaxToken)`**: Another inequality operator representation
24. **`NotIlike(NotIlike)`**: Negated case-insensitive pattern match operator (`NOT ILIKE`)
25. **`NotIn(NotIn)`**: Negated set membership operator (`NOT IN`)
26. **`NotLike(NotLike)`**: Negated pattern match operator (`NOT LIKE`)
27. **`NotSimilarTo(NotSimilarTo)`**: Negated regex-like pattern match operator (`NOT SIMILAR TO`)
28. **`OperatorCall(OperatorCall)`**: Procedural schema-qualified operator invocation (e.g., `OPERATOR(schema.op)`)
29. **`Or(SyntaxToken)`**: Logical OR (`OR`)
30. **`Overlaps(SyntaxToken)`**: Temporal/range overlap operator (`OVERLAPS`)
31. **`Percent(SyntaxToken)`**: Modulo operator (`%`)
32. **`Plus(SyntaxToken)`**: Addition operator (`+`)
33. **`RAngle(SyntaxToken)`**: Greater than operator (`>`)
34. **`SimilarTo(SimilarTo)`**: Regex-like pattern match operator (`SIMILAR TO`)
35. **`Slash(SyntaxToken)`**: Division operator (`/`)
36. **`Star(SyntaxToken)`**: Multiplication operator (`*`)

