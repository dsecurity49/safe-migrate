# Non-Schema Side Effects Reference for safe-migrate

## Status

Conceptual synthesis document. No new AST inspection required — this document
consolidates verified findings from across the AST reference set and defines
the boundary between schema-structural mutations (what safe-migrate primarily
models) and runtime-behavioral side effects (what safe-migrate must detect
and flag even when it cannot fully simulate them).

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
  → Detectable: yes (database.md) | Value extractable: NO (grammar gap)
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
| `ALTER DATABASE db SET search_path` | `SetConfigParam` (database.md) | NO (grammar gap) | Future sessions only |
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
| `ALTER DATABASE db SET param` | `SetConfigParam` (database.md) | YES | NO (grammar gap) |
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
| `ALTER COLUMN ... RESTART` | `Restart` as `AlterColumnOption` (columns.md) | Presence-only, value not captured |

**Simulator handling:** Sequence restarts can cause duplicate-key violations
if the restarted value overlaps with existing data. This is a runtime
concern, not structural — the simulator cannot evaluate it without knowing
the current max value in the table (from pg_catalog, which DbCache can
provide) vs the restart target (which the AST cannot provide due to grammar
gaps).

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
| `ALTER DATABASE SET search_path` | Param name only | NO (value) | Medium — future sessions affected |
| `LOCK TABLE` | YES | YES (table) | Low — operational, not correctness |
| `SEQUENCE RESTART` | YES (presence) | NO (restart value) | Low — duplicate-key risk only if overlapping |
| `PREPARE TRANSACTION` | YES | YES (XID) | Low — cross-session, not in current migration |
