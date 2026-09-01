# Local benchmark baseline

This document records reproducible, non-CI performance scenarios. The values
are comparison points for the later `0.7.0` work, not performance guarantees.
Run them with:

```sh
cargo test --locked --test performance_scenarios -- --ignored --nocapture
```

The scenarios validate final state as well as timing, so an apparent speedup
that breaks transaction cleanup is not a valid comparison.

## Initial `v0.6.2` baseline

Captured on 2026-08-26 from base commit `ac8b5ad`, with local uncommitted
`v0.6.2` hardening changes, using Rust 1.98.0 on an aarch64 Android Linux
environment. Timings are wall-clock milliseconds from a debug test build and
will vary with device load.

| Scenario | Statements | Elapsed |
| --- | ---: | ---: |
| ordered thousand-statement chain | 1,000 | 11,595 ms |
| large synchronized-baseline hydration | 1,000 relations | 99 ms |
| cache encode/compress/encrypt/decrypt/decompress/decode | 1,000 relations | 99 ms |
| long transaction rollback | 503 | 4,952 ms |
| repeated savepoint rollback | 752 | 1,586 ms |
| failed multi-action statement rollback | 3 | 14 ms |
| rename and cascade dependency graph | 304 | 3,323 ms |
| location-rich reports with many findings | 250 | 2,440 ms |

The scenarios cover ordered-chain analysis, baseline hydration, cache
processing, transaction undo, compound-statement atomicity, savepoint cleanup,
rename/cascade graph cleanup, and location-rich report generation. They
intentionally avoid timing thresholds in CI. Allocation, peak-memory,
checkpoint-capture, and isolated dependency-query measurements require a
profiler or allocator instrumentation and are deliberately not inferred from
these wall-clock samples.

## Optimized-profile `v0.7.0` structural baseline

Captured on 2026-08-28 from commit `b639b04` using Rust 1.98.0 on the same
aarch64 Android Linux environment. This run uses Cargo's optimized `release`
profile and is the comparison point for evidence-gated `v0.7.0` work; it is not
comparable to the debug timings above and is not a performance guarantee.

| Scenario | Statements | Elapsed |
| --- | ---: | ---: |
| ordered thousand-statement chain | 1,000 | 6,652 ms |
| large synchronized-baseline hydration | 1,000 relations | 54 ms |
| cache encode/compress/encrypt/decrypt/decompress/decode | 1,000 relations | 24 ms |
| long transaction rollback | 503 | 2,673 ms |
| repeated savepoint rollback | 752 | 308 ms |
| failed multi-action statement rollback | 3 | 1 ms |
| rename and cascade dependency graph | 304 | 1,477 ms |
| location-rich reports with many findings | 250 | 922 ms |

### Location-report parsing improvement

On 2026-08-28, the location-report scenario was sampled five times after
reusing the parse already required to calculate statement ranges. The samples
were 250, 231, 238, 235, and 235 ms (median **235 ms**). This is a 74.5%
reduction from the structural baseline; both the CLI location test and the
scenario's state assertions remained green. This measurement is specific to
the same aarch64 Android Linux host and optimized profile described above.

Run future comparisons with the same command and profile:

```sh
cargo test --release --locked --test performance_scenarios -- --ignored --nocapture --test-threads=1
```

The allocation scenarios use a process-global counting allocator. Run them
alone (or keep `--test-threads=1`) so allocations from another test cannot be
attributed to the scenario under measurement.

## Phase 2 state-copying measurements

Captured on 2026-08-28 in the same optimized profile and environment. The
pre-optimization samples were taken immediately before the Phase 2 changes;
the optimized samples include the statement undo checkpoint and incremental
`PreState` capture. All scenarios retain their exact final-state and rollback
assertions.

| Scenario | Structural baseline | Phase 2 median | Change |
| --- | ---: | ---: | ---: |
| long transaction rollback | 2,673 ms | 1,052 ms | -60.6% |
| repeated savepoint rollback | 308 ms | 127 ms | -58.8% |
| ordered thousand-statement chain | 6,652 ms | 6,529 ms | -1.8% |

The long-transaction samples were 1,124, 849, 767, 1,094, and 1,052 ms. The
savepoint samples were 127, 130, 97, 113, and 242 ms. The ordered-chain samples
were 6,371, 6,529, and 10,201 ms; the outlier illustrates why these local
timings are comparisons rather than release thresholds. Its median shows no
material small/ordinary-chain regression against the checked-in structural
baseline.

The 50-statement chain over a 1,000-relation synchronized baseline provides a
less load-sensitive allocation comparison:

| Measurement | Before Phase 2 | After Phase 2 | Change |
| --- | ---: | ---: | ---: |
| allocations | 1,027,883 | 724,358 | -29.5% |
| allocated bytes | 168,246,639 | 114,914,704 | -31.7% |

Reserving and reusing the public `PreState` map storage also reduced a fresh
1,000-relation capture from 2,060,848 to 1,061,260 allocated bytes (-48.5%).
The returned public fields and values remain unchanged; an equivalence test
compares incremental capture with a fresh capture after update, insertion, and
removal mutations.

Cache V8 decoding streams decompressed bytes through the bounded bincode
reader instead of retaining a second, fully decompressed byte vector. This is a
structural peak-memory reduction, not an RSS claim: authenticated decryption
still completes before decompression, the 256 MiB decoded-size bound remains
enforced, and a regression test rejects trailing decompressed payload data.

## Phase 3 dependency-graph measurements

Captured on 2026-08-28 from the Phase 3 worktree using the debug test profile
on the same aarch64 Android Linux host. These samples are intentionally kept
separate from the optimized-profile baseline above.

An initial eager index regressed the existing 304-statement rename/cascade
scenario from a five-sample median of 1,048 ms to 1,285 ms. A lazy index still
measured 1,093 ms. Both designs were rejected. The retained design preserves
canonical scans below 1,024 edges and lazily builds a referenced-object index
only for larger cascade graphs. It also omits derived indexes when cloning a
graph for a statement checkpoint.

The unchanged-size rename/cascade scenario then measured 1,042, 1,015, and
1,013 ms (median **1,015 ms**, 3.1% below the 1,048 ms pre-change median). The
large isolated scenario includes initial index construction and compares the
same 1,000 lookups over 10,000 edges:

| Lookup path | Elapsed |
| --- | ---: |
| lazy referenced-object index | 447,268 us |
| canonical full-edge scan | 2,834,576 us |

The indexed path was about **6.3x faster** while returning the same edge count.
Run the isolated comparison with:

```sh
cargo test --locked --jobs 1 --test performance_scenarios large_dependency_graph_lookup_index -- --ignored --nocapture --test-threads=1
```
