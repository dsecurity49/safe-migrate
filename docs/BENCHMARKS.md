# Local benchmark baseline

This document records reproducible, non-CI performance scenarios. The values
are comparison points for later `0.6.x` work, not performance guarantees.
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
