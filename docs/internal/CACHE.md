# Cache and Synchronization

This guide describes safe-migrate-owned cache behavior. It is for maintainers
and contributors; the root README is the user setup guide.

## Responsibilities

`sync` reads PostgreSQL catalogs and writes a versioned `DbCache`. The cache is
the baseline used by analysis to distinguish existing production objects from
objects created inside a migration. It is not a database dump and must never
contain connection credentials.

New cache files store provenance:

- creation time as Unix seconds;
- source database name;
- requested schema list, when filtering was used.

Older compatible caches without this provenance remain readable but are stale.
Freshness is calculated from recorded provenance, never filesystem modification
time.

## Connection boundary

`DATABASE_URL` is read only from the environment. The current build accepts
localhost and Unix-socket PostgreSQL URLs. A remote database must be accessed
through an SSH tunnel terminating locally. Do not add credentials to command
line options, TOML, diagnostics, or cache metadata.

`lint` and `lint-chain` are offline by default. `auto_sync = true` is the sole
opt-in that refreshes before analysis. `--no-cache` bypasses both cache loading
and automatic synchronization.

## Write and failure semantics

Synchronize into a temporary file beside the destination, then atomically
replace the destination only after the compressed payload is complete. A sync
failure must not remove or corrupt a previous cache.

When automatic sync fails, report the underlying failure and load the previous
readable cache. Its confidence is determined by cache freshness and analysis,
not by the refresh failure alone. With no readable cache, analysis continues
against an unavailable baseline and is tainted.

## Encryption

When `cache_encryption = true`, cache bytes are encrypted with
XChaCha20-Poly1305. Key material comes only from `SAFE_MIGRATE_CACHE_KEY` as
64 hexadecimal characters (32 bytes). Each write uses a fresh nonce.

The encrypted envelope is authenticated. Missing configuration, missing key
material, an incorrect key, or modified ciphertext must fail closed. Never add
fallback decryption, key storage in TOML, or a command-line key option.

## Change checklist

Changes to cache layout, provenance, encryption, or synchronization behavior
need:

1. versioned decode coverage, including compatible legacy caches;
2. atomic-write and failure-preservation tests;
3. CLI JSON/provenance coverage where user-visible;
4. encryption round-trip and rejection-path tests when applicable;
5. updates to `docs/CONTRACT.md`, the root README, and `CHANGELOG.md` for
   behavior changes.
