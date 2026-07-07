# safe-migrate Roadmap 2

This roadmap picks up from where Phases 4-9 landed. It is written at implementation level — exact bugs, exact files, exact test cases — based on everything discovered during development, testing, and the supernova stress test. No speculative features; every item here has a concrete motivating finding.

---

## Current State (baseline for this roadmap)

**185 lib tests + 4 CLI tests passing, 0 failures, clippy clean.**

Shipped in Phases 4-9:
- Bi-directional state machine simulator with undo-log rollback
- Full ecosystem coverage: roles, functions, triggers, policies, publications, subscriptions
- Reversibility classification (Phase 6)
- Multi-file chain execution with same-chain conflict detection (Phase 7)
- Confidence degradation (Phase 8)
- Source-range threading and `At:` snippet printing (Phase 9)
- `DriftDetectionRule`, varchar precision narrowing detection (Phase 5a)

Known bugs confirmed from test output and discussion:
- BUG-007: Stale statistics gate suppressing violations on small/empty tables — fixed
- BUG-008: Index ObjectIds leaking into `baseline_relations` via `AnalysisState::new()`
- BUG-009: `now()` classified as VOLATILE (it is STABLE)
- BUG-010: Stale statistics warning firing on `DROP INDEX` (lock-behavior-only rule, row counts irrelevant)
- BUG-011: `[SAFE] Irreversible data-destructive operation detected` — operation kind and risk level overloaded in same string
- BUG-012: Summary footer says "safe to deploy" even when irreversible Tier 3 operations are present

---

## Phase 10: Correctness Fixes + Output Redesign

**Goal:** Fix the confirmed bugs from Phase 4-9 testing, then redesign the output layer to be unambiguous. These two concerns are bundled because the output redesign (splitting `operation_kind` from `risk_level`) fixes the presentation bugs at the same time as it restructures the data model.

### 10.1 BUG-008: Index ObjectIds in baseline_relations

**File:** `src/analysis/state.rs`

**The bug:** `AnalysisState::new()` inserts index ObjectIds into `baseline_relations`:

```rust
// CURRENT (wrong):
for idx in cache.indexes {
    baseline_relations.insert(idx.index_id.clone());  // ← indexes are not relations
    graph.indexes.push(IndexEdge { ... });
}
```

This causes any rule that checks `baseline_relations.contains(&id)` to treat indexes as relations. The symptom: `Table public.idx_accounts_username statistics are stale` — the stale stats warning fired on an index because the index ObjectId was in `baseline_relations` and got picked up as a relation snapshot target.

**The fix:**

```rust
// Add a dedicated baseline set for indexes
pub struct AnalysisState {
    pub baseline_relations: HashSet<ObjectId>,
    pub baseline_indexes: HashSet<ObjectId>,    // NEW: separate from relations
    // ...
}

// In new():
for idx in cache.indexes {
    // Remove: baseline_relations.insert(idx.index_id.clone());
    baseline_indexes.insert(idx.index_id.clone());   // correct home
    graph.indexes.push(IndexEdge { ... });
}
```

Update `DriftDetectionRule` to check `baseline_indexes` for index-related mutations instead of `baseline_relations`.

**Tests to add:**
- `test_bug008_index_not_in_baseline_relations` — create an index in cache, assert `state.baseline_relations` does not contain the index ObjectId
- `test_bug008_index_in_baseline_indexes` — assert `state.baseline_indexes` does contain it
- `test_bug008_stale_stats_does_not_fire_on_index` — run lint on `DROP INDEX idx_accounts_username`, assert no "statistics are stale" violation fires

### 10.2 BUG-009: now() classified as VOLATILE

**File:** `src/analysis/expr_ir.rs` (wherever `is_volatile()` is implemented)

**The bug:** `now()` and `current_timestamp` are classified as VOLATILE. They are STABLE — they return the transaction start time, the same value for every row within one statement. This means `ALTER TABLE orders ADD COLUMN created_at TIMESTAMP DEFAULT NOW()` incorrectly triggers a table-rewrite warning on PG11+.

PostgreSQL volatility classification, for reference:

| Function | Correct classification | Reason |
|----------|----------------------|--------|
| `now()` | STABLE | Returns transaction start time, same within statement |
| `current_timestamp` | STABLE | Same as now() |
| `current_date` | STABLE | Same |
| `current_user` | STABLE | Same |
| `clock_timestamp()` | VOLATILE | Returns real wall clock, different on every call |
| `random()` | VOLATILE | Non-deterministic |
| `gen_random_uuid()` | VOLATILE | Non-deterministic |
| `txid_current()` | VOLATILE | Different per transaction |
| `timeofday()` | VOLATILE | Real wall clock as text |

**The fix:** Remove `now`, `current_timestamp`, `current_date`, `current_user` from the volatile function list. Keep `clock_timestamp`, `random`, `gen_random_uuid`, `txid_current`, `timeofday`.

**Tests to add:**
- `test_now_is_not_volatile` — `ExprIr` for `now()` call, assert `is_volatile()` returns false
- `test_clock_timestamp_is_volatile` — assert `clock_timestamp()` returns true
- `test_add_column_now_default_not_flagged` — `ALTER TABLE t ADD COLUMN created_at TIMESTAMP DEFAULT NOW()` on PG11+, assert no `size-aware-add-column` violation

### 10.3 BUG-010: Stale statistics warning on DROP INDEX

**File:** `src/rules/indexes.rs`

**The bug:** `require-concurrent-drop-index` emits a "stale statistics" Tier 2 warning. This rule evaluates lock behavior, not row count thresholds. Row count statistics are irrelevant to whether `DROP INDEX` blocks — the lock type is determined by the SQL form (`CONCURRENTLY` or not), not by the table size.

**The fix:** Remove the stale-stats check from any rule whose tier decision does not depend on row counts. For `require-concurrent-drop-index`, the evaluate path should only care about whether `CONCURRENTLY` is present:

```rust
impl Rule for RequireConcurrentDropIndexRule {
    fn evaluate(&self, mutation: &Mutation, /* ... */) -> Vec<Violation> {
        if let Mutation::DropIndex(d) = mutation {
            if !d.concurrently {
                // No stale-stats check here — lock behavior is determined
                // by the SQL form alone, not by table size
                return vec![Violation {
                    rule_id: self.id(),
                    tier: ViolationTier::Tier2,
                    // ...
                }];
            }
        }
        vec![]
    }
}
```

General principle going forward: only rules that gate their tier decision on `estimated_rows` should emit stale-statistics warnings. Rules that evaluate lock behavior from SQL structure alone (concurrent-in-transaction, vacuum-full, require-concurrent-index, require-concurrent-drop-index) should never emit stale-statistics warnings.

**Tests to add:**
- `test_drop_index_no_stale_stats_warning` — run lint on `DROP INDEX idx`, assert no stale-statistics violation, only the concurrent-drop violation

### 10.4 operation_kind / risk_level split (fixes BUG-011 and BUG-012)

**Files:** `src/report/violations.rs`, all rule files, `src/report/reporter.rs`

**The bug:** `operation_kind` and `risk_level` are currently fused into a single `title: String`. This produces contradictory-reading output like `[SAFE] Irreversible data-destructive operation detected`. A developer reading this has to mentally parse what "SAFE" means in the context of "irreversible" — they're two orthogonal facts that the current model forces into one string.

**The fix — add `operation_kind` and `object_kind` to `Violation`:**

```rust
// src/report/violations.rs
pub enum OperationKind {
    DropColumn,
    DropTable,
    DropIndex,
    DropView,
    DropFunction,
    AddColumn,
    AlterColumnType,
    AddConstraint,
    CreateIndex,
    RefreshMaterializedView,
    AttachPartition,
    DetachPartition,
    VacuumFull,
    Grant,
    RevokeGrant,
    CreateFunction,
    AlterFunction,
    OpaqueSql,
    Other(String),   // escape hatch for rules that don't fit cleanly
}

pub enum ObjectKind {
    Table,
    Index,
    View,
    MaterializedView,
    Function,
    Procedure,
    Trigger,
    Sequence,
    Schema,
    Role,
    Publication,
    Subscription,
    Unknown,
}

pub struct Violation {
    pub rule_id: &'static str,
    pub operation_kind: OperationKind,   // NEW: what the SQL is doing
    pub object_kind: ObjectKind,         // NEW: what type of object is affected
    pub tier: ViolationTier,             // EXISTING: assessed risk level
    pub reason: String,                  // RENAMED from title: concise human explanation
    pub recipe: &'static str,            // EXISTING: how to fix it
    pub dedup_key: Option<String>,
    pub source_range: Option<TextRange>,
}
```

Both `operation_kind` and `object_kind` are inferred from `Mutation` at violation-construction time. `object_kind` is derived from the `RelationKind` of the affected object in `pre_relations`, or from the mutation type for non-relation objects (indexes, functions, etc.). This follows the same pattern as Phase 9's `TextRange` threading — mechanical, touches all rule files, but bounded.

**Fix BUG-012 — verdict classification:**

```rust
// src/report/reporter.rs
pub enum Verdict {
    Halt,           // any Tier 1
    Cautious,       // Tier 2 present, no Tier 1
    SafeWithRisk,   // Tier 3 irreversible present, no Tier 1 or 2
    Safe,           // all Tier 3 or no findings
}

fn compute_verdict(violations: &[Violation]) -> Verdict {
    let has_tier1 = violations.iter().any(|v| v.tier == ViolationTier::Tier1);
    let has_tier2 = violations.iter().any(|v| v.tier == ViolationTier::Tier2);
    let has_irreversible_tier3 = violations.iter().any(|v| {
        v.tier == ViolationTier::Tier3 && v.rule_id == "irreversible-migration"
    });

    match (has_tier1, has_tier2, has_irreversible_tier3) {
        (true, _, _)           => Verdict::Halt,
        (false, true, _)       => Verdict::Cautious,
        (false, false, true)   => Verdict::SafeWithRisk,
        (false, false, false)  => Verdict::Safe,
    }
}
```

### 10.5 CLI output redesign

**Motivating evidence:** The current output wraps mid-word on narrow terminals, fires multiple violations for the same SQL with no visual grouping, uses inconsistent separator lengths, and produces contradictory strings like `[SAFE] Irreversible data-destructive operation detected`. Screenshot confirmed: all these problems are visible in the real output against `test_5.sql`.

**New dependencies:**

```toml
# Cargo.toml
comfy-table = "7"      # header box, summary box, column alignment, pure Rust
owo-colors = "3"       # ANSI color on tier labels only, zero-dependency
terminal_size = "0.3"  # terminal width for proportional separator
```

All three are pure Rust with no C dependencies. `comfy-table` is the same crate used in `cargo`'s own output. No runtime overhead.

**Target output format** (based on the confirmed design from screenshot):

```
┌──────────────────────────────────────────────────────────────────────────┐
│ safe-migrate lint                                                         │
│ File: migration.sql          Verdict: CAUTIOUS        Confidence: Exact  │
│ HALT: 0                       WARN: 1                  SAFE: 6           │
└──────────────────────────────────────────────────────────────────────────┘

 [WARN] require-concurrent-drop-index
  object : index public.idx_accounts_username
  reason : synchronous drop can block writes
  recipe : use DROP INDEX CONCURRENTLY outside a transaction block
  sql    : DROP INDEX IF EXISTS idx_accounts_username;

 ──────────────────────────────────────────────────────

 [SAFE] irreversible-migration
  object : table public.accounts
  reason : estimated rows = 0
  recipe : ensure backups exist before deploying
  sql    : ALTER TABLE accounts DROP COLUMN legacy_code;

 ──────────────────────────────────────────────────────

 [SAFE] missing-idempotency
  object : table public.accounts
  reason : CREATE TABLE without IF NOT EXISTS
  recipe : add IF NOT EXISTS to prevent failures on partial re-runs
  sql    : CREATE TABLE accounts (id bigint, created_at timestamptz);

┌────────────────────────────── SUMMARY ──────────────────────────────────┐
│ Verdict        : CAUTIOUS                                                │
│ Recommendation : review warnings before deploy                           │
│ HALT (Tier 1)  : 0                                                       │
│ WARN (Tier 2)  : 1                                                       │
│ SAFE (Tier 3)  : 6                                                       │
└──────────────────────────────────────────────────────────────────────────┘
```

**Verdict words** (mapping from `Verdict` enum):
- `Halt` → `HALT` (red) + `do not deploy`
- `Cautious` → `CAUTIOUS` (yellow) + `review warnings before deploy`
- `SafeWithRisk` → `SAFE WITH RISK` (cyan) + `irreversible operations present on empty objects`
- `Safe` → `SAFE` (green) + `safe to deploy`

**Per-finding block rules:**

Each finding renders as:
```
 [TIER] rule-id
  object : {object_kind} {schema}.{name}
  reason : {reason}
  recipe : {recipe}
  sql    : {full sql snippet}
```

`object_kind` comes from the new `ObjectKind` enum on `Violation` — the reporter renders it as lowercase (`table`, `index`, `view`, `function`, etc.). This replaces the current practice of embedding the type in the free-text title.

`reason` is the concise human explanation of why the finding fired (renamed from `title`).

`recipe` is the actionable fix — what the developer should do instead. Already exists on `Violation` as `&'static str`, just not currently displayed in the right place. In the old reporter it appeared as a separate indented block; in the new format it sits inline with the other fields so it's visually associated with the finding it belongs to.

`sql` shows the full statement as extracted from the source range. No truncation.

**Updated target output format:**

```
┌──────────────────────────────────────────────────────────────────────────┐
│ safe-migrate lint                                                         │
│ File: migration.sql          Verdict: CAUTIOUS        Confidence: Exact  │
│ HALT: 0                       WARN: 1                  SAFE: 6           │
└──────────────────────────────────────────────────────────────────────────┘

 [WARN] require-concurrent-drop-index
  object : index public.idx_accounts_username
  reason : synchronous drop can block writes
  recipe : use DROP INDEX CONCURRENTLY outside a transaction block
  sql    : DROP INDEX IF EXISTS idx_accounts_username;

 ────────────────────────────────────────

 [SAFE] irreversible-migration
  object : table public.accounts
  reason : estimated rows = 0
  recipe : ensure backups exist before deploying
  sql    : ALTER TABLE accounts DROP COLUMN legacy_code;

 ────────────────────────────────────────

 [SAFE] missing-idempotency
  object : table public.accounts
  reason : CREATE TABLE without IF NOT EXISTS
  recipe : add IF NOT EXISTS to prevent failures on partial re-runs
  sql    : CREATE TABLE accounts (id bigint, ...);

┌────────────────────────────── SUMMARY ──────────────────────────────────┐
│ Verdict        : CAUTIOUS                                                │
│ Recommendation : review warnings before deploy                           │
│ HALT (Tier 1)  : 0                                                       │
│ WARN (Tier 2)  : 1                                                       │
│ SAFE (Tier 3)  : 6                                                       │
└──────────────────────────────────────────────────────────────────────────┘
```

**Finding separator:** Drawn just wide enough to visually cover the longest field line above it — approximately 75-80% of terminal width. `terminal_size::terminal_size()` gives `(columns, rows)`; draw `"─".repeat((columns.0 as f32 * 0.77) as usize)`. On a standard 80-column terminal that's ~61 characters, which covers a typical `  sql    : DROP INDEX IF EXISTS idx_accounts_username;` line. On wider terminals it scales proportionally. The separator is deliberately narrower than the full-width box borders — heavy boxes bookend the output, lighter separators divide findings within it.

```rust
let (cols, _) = terminal_size::terminal_size()
    .unwrap_or((terminal_size::Width(80), terminal_size::Height(24)));
let sep_width = (cols.0 as f32 * 0.77) as usize;
println!(" {}", "─".repeat(sep_width));
```

**Grouping same-object violations:** When two violations share the same `source_range` (same SQL statement) and the same object, group them under one block rather than printing two separate blocks. This directly fixes the double-firing of `require-concurrent-drop-index` on a single `DROP INDEX` statement:

```
 [WARN] require-concurrent-drop-index
  object : index public.idx_accounts_username
  reason : synchronous drop can block writes
  recipe : use DROP INDEX CONCURRENTLY outside a transaction block
  also   : stale statistics — lock evaluation may be inaccurate
  sql    : DROP INDEX IF EXISTS idx_accounts_username;
```

The `also :` line appears for secondary violations on the same statement. This requires grouping `violations` by `source_range` before rendering, which is a sort + group operation in the reporter, not a change to any rule or data model.

**Color application:** Only the tier label in brackets gets color. Nothing else:
- `[HALT]` → red
- `[WARN]` → yellow  
- `[SAFE]` → green
- All other text → terminal default

No background colors, no full-line color, no colored borders. The boxes use default terminal color — `comfy-table`'s border characters render in whatever the terminal's default foreground is. This ensures readability on both dark and light terminal themes.

**CI / no-color mode:** Detect `NO_COLOR` environment variable and `--no-color` flag. When either is set, strip all ANSI codes. `owo-colors` supports this natively via `owo_colors::OwoColorize::if_supports_color()`. CI environments that set `NO_COLOR=1` will get plain text output with no escape sequences — safe for log parsers and artifact storage.

**Schema inference labeling:** When the schema was inferred from `search_path` rather than explicitly written in the SQL, append `(inferred)` to the object line:

```
  object : table public.accounts (inferred)
```

This requires the `inferred_schema: bool` field on `ObjectId` from section 10.5. Lower priority than the other display changes — implement last within Phase 10.

**Implementation order within Phase 10.5:**
1. Add `comfy-table`, `owo-colors`, `terminal_size` to `Cargo.toml`
2. Rewrite `reporter.rs` header box and summary box using `comfy-table`
3. Rewrite per-finding block with field alignment (fixed-width label prefix: `object :`, `reason :`, `sql :`)
4. Add proportional separator (70-75% of terminal width) between findings
5. Add same-source-range grouping (`also :` line)
6. Add color via `owo-colors` on tier labels only
7. Add `NO_COLOR` / `--no-color` detection
8. Add `(inferred)` schema label (last, after `inferred_schema` field exists)

**Tests to update:** `test_reporter_print_violations` and `test_reporter_print_empty` will need full rewrites since the output format changes completely. Every rule test that asserts on `v.title` needs updating to assert on `v.reason` instead.

**Tests to add:**
- `test_operation_kind_drop_column` — assert `DropColumn` variant set correctly
- `test_operation_kind_inferred_from_mutation` — all mutation types map to correct `OperationKind`
- `test_object_kind_from_relation_kind` — `RelationKind::Table` → `ObjectKind::Table`, etc.
- `test_verdict_halt_tier1` — any Tier 1 → `Verdict::Halt`
- `test_verdict_cautious_tier2` — Tier 2, no Tier 1 → `Verdict::Cautious`
- `test_verdict_safe_with_risk` — irreversible Tier 3, no Tier 1/2 → `Verdict::SafeWithRisk`
- `test_verdict_safe` — all Tier 3 non-irreversible → `Verdict::Safe`
- `test_reporter_groups_same_source_range` — two violations on same SQL → rendered as one block with `also :` line
- `test_reporter_no_color_mode` — `NO_COLOR=1` produces output with no ANSI escape sequences

### 10.6 Deterministic violation ordering

**Files:** `src/engine/engine.rs`, `src/report/reporter.rs`

**Why this matters:** Without an explicit sort, violation order is determined by iteration order over `HashMap`s in `LocalState` — which is non-deterministic across runs due to hash randomization. This causes:
- Output that flickers between runs on the same input (different ordering each time)
- Snapshot tests that are painful to maintain (any HashMap iteration order change breaks them)
- Noisy CI diffs (git diff shows reordered violations as additions and deletions even when nothing actually changed)

This is a correctness issue for the test suite and a trust issue for CI output — a developer who sees different ordering between two identical runs will doubt the tool.

**The fix:** Sort `all_violations` in `engine.rs` before returning, using a stable multi-key sort:

```rust
// src/engine/engine.rs — at the end of analyze() / analyze_chain(), before Ok(all_violations)
all_violations.sort_by(|a, b| {
    // 1. Tier first: Tier1 (HALT) before Tier2 (WARN) before Tier3 (SAFE)
    a.tier.cmp(&b.tier)
        // 2. Source range: earlier in the file before later
        .then_with(|| {
            let a_start = a.source_range.map(|r| u32::from(r.start())).unwrap_or(u32::MAX);
            let b_start = b.source_range.map(|r| u32::from(r.start())).unwrap_or(u32::MAX);
            a_start.cmp(&b_start)
        })
        // 3. Object name: alphabetical within same statement
        .then_with(|| a.object.to_string().cmp(&b.object.to_string()))
        // 4. Rule ID: alphabetical as final tiebreaker
        .then_with(|| a.rule_id.cmp(b.rule_id))
});
```

**Why this ordering:**
- **Tier first** — the developer should see HALTs before WARNs before SAFEs regardless of where they appear in the file. The most dangerous findings are always at the top.
- **Source range second** — within the same tier, findings appear in file order. This mirrors how a developer reads a migration: top to bottom. It also makes the `also :` grouping (same source range) trivially correct since same-range violations are now adjacent after the sort.
- **Object third** — when two findings on the same tier hit the same byte offset (e.g. a table-level constraint touching multiple objects), alphabetical object name gives a stable secondary order.
- **Rule ID fourth** — final tiebreaker ensures two violations on the same tier, same range, same object (e.g. `irreversible-migration` and `missing-idempotency` both firing on `DROP COLUMN`) always appear in the same relative order.

**`ViolationTier` must implement `Ord`:**

```rust
// src/report/violations.rs
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ViolationTier {
    Tier1,  // HALT — sorts first (lowest discriminant)
    Tier2,  // WARN
    Tier3,  // SAFE — sorts last
}
```

This is a one-line derive addition. The enum variant declaration order defines the sort order — `Tier1` declared first means it sorts before `Tier2` and `Tier3`.

**Snapshot tests become trivial once this is in place.** A snapshot test against a known migration file will produce identical output on every run, on every machine, regardless of HashMap iteration order or Rust version. This unblocks adding `insta`-style snapshot tests for the reporter in Phase 12.

**Tests to add:**
- `test_violations_sorted_tier_first` — violations in tier order regardless of insertion order
- `test_violations_sorted_source_range_within_tier` — two Tier 2 violations at different file positions, assert earlier position sorts first
- `test_violations_sorted_rule_id_tiebreaker` — two violations at identical tier/range/object, assert alphabetical rule_id order
- `test_sort_is_stable_across_runs` — run the same analysis twice, assert `Vec<Violation>` is identical both times (this is the regression guard)

### Phase 10 release criteria

- [x] BUG-008 fixed and tested — index ObjectIds no longer in `baseline_relations`
- [x] BUG-009 fixed and tested — `now()` classified STABLE, not VOLATILE
- [x] BUG-010 fixed and tested — no stale-stats warning on lock-behavior-only rules
- [x] `operation_kind` and `object_kind` fields on `Violation` — all rules updated
- [x] `Verdict` enum with four-way classification
- [x] Deterministic violation ordering — `violations.sort_by(tier → source_range → object → rule_id)`
- [x] `ViolationTier` derives `Ord` with correct variant order
- [x] CLI output matches confirmed design (header box, per-finding blocks with recipe, summary box)
- [x] `comfy-table`, `owo-colors`, `terminal_size` added and used correctly
- [x] Color only on tier labels, `NO_COLOR` respected
- [x] Same-source-range grouping with `also :` line
- [x] All existing 185 tests still passing (updated for new format)
- [x] New tests for all fixes and format changes passing
- [x] `cargo clippy -- -D warnings` clean
- [x] FIX: Resolve `opaque-dynamic-sql` source-range mismatch (ensure `sql :` shows the actual `DO` block or `EXECUTE` statement instead of the next statement when the finding was triggered by dynamic/opaque code detection)

---

## Phase 11: Cache Scalability

**Goal:** Make the cache file practical for large schemas and safe to commit to source control.

**Motivating data:** Supernova stress test (50,000 tables × 8 schemas): sync produces 97MB JSON in 9.6 seconds. zstd compression at level 19 reduces to 743KB (99.25% reduction — extreme because all 50K tables are structurally identical in that synthetic dataset; real production schemas will compress less dramatically but still significantly since column names and type strings are highly repetitive across any real schema). The 9.6 second sync time is fine; the 97MB file is not — it's not committable to git and imposes a full-deserialization cost on every `lint` call.

### 11.1 Binary serialization + zstd compression

**Files:** `Cargo.toml`, `src/sync.rs`, `src/main.rs`

**The change:** Replace `serde_json::to_string_pretty` with `bincode` + `zstd` on write, and reverse on read. The existing `DbCache` struct and all existing serde derives stay exactly as-is — only the serialization format changes.

```toml
# Cargo.toml additions
bincode = "2.0"
zstd = "0.13"
```

```rust
// src/sync.rs — replace the final write block
let encoded = bincode::encode_to_vec(&cache, bincode::config::standard())
    .context("Failed to encode cache")?;
let compressed = zstd::encode_all(encoded.as_slice(), 3)  // level 3: fast with good ratio
    .context("Failed to compress cache")?;
let tmp_path = out_path.with_extension("tmp");
fs::write(&tmp_path, &compressed).context("Failed to write cache")?;
fs::rename(&tmp_path, out_path).context("Failed to finalize cache")?;
```

```rust
// src/main.rs — replace cache read block
let compressed = fs::read(&cache).context("Failed to read cache file")?;
let decoded = zstd::decode_all(compressed.as_slice())
    .map_err(|_| anyhow!("Cache file '{}' is corrupted. Run `safe-migrate sync` to rebuild.", cache.display()))?;
let db_cache = bincode::decode_from_slice::<DbCache, _>(&decoded, bincode::config::standard())
    .map_err(|_| anyhow!("Cache schema mismatch. Run `safe-migrate sync` to rebuild."))?
    .0;
```

**Backward compatibility:** The current cache is `.safe-migrate-stats.json`. After this change, the format is binary. Options:
- Change the default filename to `.safe-migrate.cache` to make it obvious it's not JSON anymore
- Or keep `.safe-migrate-stats.json` but detect format at read time (check first bytes for zstd magic `0xFD2FB528` vs `{` for JSON, fall back to JSON parse if not zstd) — this gives a graceful upgrade path without requiring everyone to delete their old cache

Recommend the magic-byte detection approach: zero migration friction, old JSON caches still work until the next sync overwrites them.

**Expected results at supernova scale:** 97MB JSON → roughly 2-5MB bincode → 200-500KB bincode+zstd. Deserialization time: JSON parse of 97MB is multiple seconds on slow CI hardware; bincode decode of the compressed form is likely under 200ms. For the median production case (1,000-5,000 tables), cache goes from ~5MB JSON to ~50-100KB compressed — small enough to commit to git without discussion.

### 11.2 Schema-scoped sync

**Files:** `src/engine/config.rs`, `src/main.rs`, `src/sync.rs`

**The problem:** A company with 50 services sharing one PostgreSQL instance doesn't want the payments team's sync to pull 50,000 tables when their migrations only touch 800 tables in `payments` and `payments_audit`. The other 49,200 tables inflate sync time, cache size, and generate false positives from drift detection on tables the linter has no business knowing about.

**Config addition:**

```toml
# safe-migrate.toml
schemas = ["payments", "payments_audit"]
```

```rust
// src/engine/config.rs
pub struct Config {
    // existing fields...
    pub schemas: Vec<String>,   // empty = no filter (current behavior)
}
```

**Sync filter:** All six sync queries share the same schema filter condition. Build it once:

```rust
// src/sync.rs
fn build_schema_filter(schemas: &[String]) -> (String, Vec<String>) {
    if schemas.is_empty() {
        (
            "AND n.nspname NOT IN ('pg_catalog', 'information_schema')".to_string(),
            vec![],
        )
    } else {
        let placeholders = (1..=schemas.len())
            .map(|i| format!("${}", i))
            .collect::<Vec<_>>()
            .join(", ");
        (
            format!("AND n.nspname IN ({})", placeholders),
            schemas.to_vec(),
        )
    }
}
```

Apply `(filter_clause, params)` to all six queries. This is ~10 lines of change per query, all mechanical.

**Cross-schema FK handling:** When schema scope is configured, a FK from `payments.orders` to `users.accounts` references an out-of-scope schema. Two options:

- **Option A (ships first):** Warn at sync time: `"FK payments.orders → users.accounts references out-of-scope schema 'users' — FK-dependent rules may be incomplete. Add 'users' to schemas config or run sync without schema filtering."` Simple, honest, puts the decision on the user.
- **Option B (future):** Auto-pull FK dependencies — after the main schema-scoped queries, run a second pass that finds all tables referenced by FKs from within the scoped schemas and pulls their metadata, flagging them as `is_fk_dependency: true` so the linter knows they're there for constraint resolution only. Better UX, more engineering.

Ship Option A first.

**CLI override:**

```bash
# Override config for a one-off full sync
safe-migrate sync --schemas ""

# Sync specific schemas without editing the config
safe-migrate sync --schemas payments,payments_audit
```

### Phase 11 release criteria

- [ ] `bincode` + `zstd` cache write/read in place
- [ ] Magic-byte detection for backward compatibility with JSON caches
- [ ] `schemas` config field and `--schemas` CLI flag
- [ ] All six sync queries respect schema filter
- [ ] Cross-schema FK warning (Option A)
- [ ] `test_cache_bincode_roundtrip` — write cache as bincode+zstd, read back, assert identical to original
- [ ] `test_cache_json_backward_compat` — write JSON cache, read back via new code, assert it still loads
- [ ] `test_sync_schema_filter_excludes_other_schemas` — sync with `schemas = ["payments"]`, assert tables from other schemas absent from cache
- [ ] `test_sync_cross_schema_fk_warning` — FK from scoped schema to out-of-scope schema, assert warning emitted

---

## Phase 12: operation_kind / risk_level in operation_kind-aware rules (post-10 cleanup)

**Goal:** After Phase 10 adds `operation_kind` to `Violation`, go back through every rule and ensure the `OperationKind` variant is set correctly and consistently. Phase 10 does the structural change; Phase 12 does the audit pass.

This is a small phase but deserves its own slot because touching all 14 rule files in one PR creates a large, hard-to-review diff. Better to land the data model change in Phase 10, then do a focused rule-by-rule audit in Phase 12 once the dust settles.

**Specific things to audit:**
- Every `Violation` construction site sets an explicit `OperationKind` variant, not `Other(_)`
- Rules that can fire on multiple mutation types set the correct variant per mutation (e.g. `BlockingConstraintRule` fires on both `AddForeignKey` and `AddCheckConstraint` — each should get its own `OperationKind`)
- `dedup_key` logic is consistent with `operation_kind` — a dedup key should include the operation kind so that the same object being touched by two different operation kinds doesn't get deduplicated as the same finding

---

## Phase 13: Interactive CLI mode

**Goal:** Add a `--interactive` flag that allows keyboard navigation through findings without requiring a full TUI framework.

**Why before TUI:** The `--interactive` mode is text-based with keyboard input — no alternate screen, no mouse handling, no pane layout. It's a simple read-print loop with arrow key detection via `crossterm`'s event polling. This is a fraction of the TUI work and delivers the main user value (navigating large outputs without scrolling) at much lower engineering cost.

**What it does:**
- Displays one finding at a time
- `↓` / `↑` move forward and backward through findings
- `1` / `2` / `3` filter by tier
- `/` opens a simple search prompt (match by rule ID or object name, print matching findings)
- `q` or `Esc` exit
- `Enter` toggles between compact view (one line) and full view (reason + recipe + SQL snippet)

**What it does not do:** No pane layout, no split screen, no persistent sidebar. That's Phase 14.

**Dependency:** `crossterm` (pure Rust, no system deps, already widely used in the ecosystem). Does not require `ratatui` at this stage.

**Implementation:** A new `src/interactive.rs` module. `main.rs` checks for `--interactive` flag and calls `interactive::run(violations)` instead of `Reporter::print_report`. The analysis pipeline is unchanged — interactive mode is a different rendering path for the same `Vec<Violation>` output.

**Tests:** Terminal UI code is notoriously hard to unit test meaningfully. Cover the data layer (filtering, search matching, navigation state) not the rendering:

- `test_interactive_filter_tier1` — filter function returns only Tier 1 violations
- `test_interactive_search_by_rule_id` — search returns violations matching rule ID
- `test_interactive_search_by_object` — search returns violations matching object name
- `test_interactive_navigation_state` — assert cursor bounds (doesn't go below 0 or above len-1)

### Phase 13 release criteria

- [ ] `--interactive` flag recognized by CLI
- [ ] Single-finding display with compact/full toggle
- [ ] Tier filter keys (1/2/3)
- [ ] Search by rule ID and object name
- [ ] Navigation bounds correct at list start and end
- [ ] `q` / `Esc` exit cleanly (no raw mode leak)
- [ ] Data layer tests passing

---

## Phase 14: Full TUI (separately scoped, not yet sized)

**Goal:** Full-screen terminal inspector with three-pane layout.

**Why not sized yet:** A three-pane, keyboard-navigable, color-coded terminal UI is a real dependency addition (`ratatui`) and a genuinely separate subsystem from the linter core — it has its own event loop, its own rendering concerns, its own test strategy. This is not "step 5 of 7" in terms of effort relative to the rest of this roadmap. It is likely more total engineering time than Phases 10-13 combined. Sizing it properly requires knowing what Phase 13's interactive mode teaches you about what users actually need, rather than specifying it upfront against assumptions.

**Planned layout (reference, not final):**

```
┌─ safe-migrate ─────────── migration.sql ── WARN: 2  SAFE: 5 ── Confidence: Exact ─┐
│                                                                                      │
│  WARN  require-concurrent-drop-index   public.idx_accounts_username              │   │
│  SAFE  missing-idempotency             public.accounts                           │   │  operation_kind: drop_index
│  SAFE  irreversible-migration          public.empty_scratchpad.temp_data         │   │  risk_level:     SAFE
│  WARN  blocking-mat-view-refresh       public.mv_order_totals                    │   │  object:         public.idx_accounts_username
│  SAFE  missing-idempotency             public.mv_order_totals                    │   │  confidence:     Exact
│  SAFE  volatile-default                public.accounts.created_at                │   │
│                                                                                   │   │  reason: index drop blocks writes. Use CONCURRENTLY.
│                                                                                   │   │
│                                                                                   │   │  recipe: DROP INDEX CONCURRENTLY idx_accounts_username;
│                                                                                   │   │
│                                                                                   │   │  at: DROP INDEX IF EXISTS idx_accounts_username;
│                                                                                   │   │
└───────────────────────────────────────────────────────────────────────────────────┴───┘
  ↑↓ navigate   / search   1 HALT   2 WARN   3 SAFE   Enter expand   q quit
```

**Keyboard actions (planned):**
- `↑` / `↓` — move selection in left pane
- `/` — search by rule or object
- `1` / `2` / `3` — filter by tier
- `Enter` — toggle detail expansion in right pane
- `q` / `Esc` — quit

**Grouping/deduplication:** Build on top of the existing `dedup_key` infrastructure. Show grouped findings with counts: `WARN  require-concurrent-drop-index   public.idx_accounts_username  ×27`. The grouping key reuses `dedup_key` where it exists, falls back to `rule_id + object` for rules without explicit dedup keys.

**Color:** Severity labels only. `HALT` = red, `WARN` = yellow, `SAFE` = green. No full-screen color washes.

**Object type badges:** Since the engine knows whether an object is a table, index, view, function, etc. (from `OperationKind` added in Phase 10), display it:
```
WARN  index   public.idx_accounts_username
SAFE  table   public.accounts
```

**This phase will be scoped properly after Phase 13 ships.** The interactive CLI mode will surface what users actually navigate and search for, which should drive the TUI layout decisions rather than pre-specifying them now.

---

## Summary table

| Phase | Status | Scope | Key deliverable |
|-------|--------|-------|-----------------|
| 4 | ✅ Complete | Roles, functions, triggers, replication | 168 tests |
| 5a | ✅ Complete | Structural cache enrichment, drift detection | `DriftDetectionRule`, varchar precision |
| 5b | ⏸ Deferred | `pg_attrdef` expression parsing | Only when a rule actually needs it |
| 6 | ✅ Complete | Reversibility classification | `ReversibilityRule`, row-count gate |
| 7 | ✅ Complete | Multi-file chain execution | `analyze_chain`, `rules/conflict.rs` |
| 8 | ✅ Complete | Confidence degradation | Tier 1 → Tier 2 under Tainted |
| 9 | ✅ Complete | Source-range threading | `At:` snippet in every violation |
| **10** | ⬜ Next | Bug fixes + output redesign | BUG-008/009/010/011/012 fixed, `operation_kind` split |
| **11** | ⬜ | Cache scalability | bincode+zstd, schema-scoped sync |
| **12** | ⬜ | operation_kind audit pass | All 14 rule files audited |
| **13** | ⬜ | Interactive CLI mode | `--interactive` flag, keyboard nav |
| **14** | ⬜ Not yet sized | Full TUI | Three-pane terminal inspector |

**Phase 10 is the immediate next target.** BUG-009 (`now()` volatility) in particular should be fixed before the next crates.io release since it produces incorrect rule evaluations that users will hit on real migrations.
