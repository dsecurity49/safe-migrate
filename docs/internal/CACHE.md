# Cache and Synchronization

This guide describes safe-migrate-owned cache behavior. It is for maintainers
and contributors; the root README is the user setup guide.

## Responsibilities

`sync` reads PostgreSQL catalogs and writes a versioned `DbCache`. The cache is
the baseline used by analysis to distinguish existing production objects from
objects created inside a migration. It is not a database dump and must never
contain connection credentials.

It does contain sensitive metadata: schema, relation, column, constraint,
index, trigger, function, type, role-grant, dependency, and statistics data.
Treat the file like a schema inventory, not a safe-to-share build artifact.

V6 cache files store provenance and session context:

- creation time as Unix seconds;
- source database name;
- effective and session role names;
- the unexpanded search-path setting, including `$user`;
- effective `lock_timeout` and `statement_timeout` values in milliseconds;
- requested schema list, when filtering was used.

They also store the non-secret `pg_roles` catalog fields needed by analysis and
separate ordinary membership from permission to use `SET ROLE`. On PostgreSQL
16 and newer, that distinction comes from `pg_auth_members.set_option`.

V6 also stores authoritative synchronized schema states and sequence
states, including owner, owning table/column, generation, and mutually
exclusive standalone, owned, serial-like, or identity kind. With scoped sync,
only requested schemas are authoritative; schemas pulled in solely for
cross-schema foreign keys remain dependency evidence, not complete catalogs.

V1–V5 caches are unsupported and must be rebuilt. Freshness is calculated from
recorded provenance, never filesystem modification time.

## Connection boundary

`DATABASE_URL` is read only from the environment. The current build accepts
localhost and Unix-socket PostgreSQL URLs. A remote database must be accessed
through an SSH tunnel terminating locally. Do not add credentials to command
line options, TOML, diagnostics, or cache metadata.

`lint` and `lint-chain` are offline by default. `auto_sync = true` is the sole
opt-in that refreshes before analysis. `--no-cache` bypasses both cache loading
and automatic synchronization.

## Inspection and redaction

`safe-migrate cache inspect --cache <path>` reads a cache locally and prints
format/provenance plus redacted object and role counts. `--json` makes that
summary scriptable. It never prints object, column, role, membership, or
dependency names and edges, and never reads `DATABASE_URL`. It can inspect an
encrypted cache only when encryption is configured and the environment key is
available; neither the key nor credentials are emitted.

There is intentionally no in-place cache redactor. Removing names or edges
from a serialized baseline can make later analysis misleading. To produce a
lower-sensitivity cache, re-sync from a sanitized database or an explicit,
approved schema scope, inspect the new cache, and dispose of the original using
your normal artifact-retention procedure. For encrypted cache-key rotation,
write a fresh cache with a new `SAFE_MIGRATE_CACHE_KEY`, update the secret
store, then remove the old cache and key according to local policy.

Keep plaintext real database caches out of Git and logs. The tracked
`live_tests/.safe-migrate.cache` is a deliberate exception containing only
synthetic fixture data, and Cargo excludes it from published crate packages.
An encrypted cache may be tracked only as an explicit repository policy: keep
its key outside Git and account for permanent binary history and a changed
ciphertext on every write. Prefer owner-only filesystem permissions, bounded CI
retention, and access controls appropriate for a schema/dependency snapshot.

## Least-privilege sync role

`sync` only issues read-only `SHOW`, `SELECT`, and catalog/view-function calls.
It queries server/version, effective/session role, search-path values, and
timeout settings from `pg_settings`, plus
`pg_class`, `pg_namespace`, `pg_attribute`, `pg_attrdef`, `pg_constraint`,
`pg_depend`, `pg_index`, `pg_proc`, `pg_type`, `pg_trigger`, `pg_policy`,
`pg_rewrite`, `pg_roles`, `pg_auth_members`, `pg_stats`, and
`pg_stat_user_tables`. `pg_roles` is used instead of `pg_authid`, so password
hashes are never cached.

Start with a dedicated `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION`
role, `CONNECT` on the target database, and `USAGE` only on schemas included in
the sync scope. Do not grant write privileges, database ownership,
`pg_read_all_data`, `pg_monitor`, server-file roles, or broad table `SELECT`
by default. PostgreSQL limits `pg_stats` to readable tables, so this minimal
role can yield unknown column widths; that is safer than granting raw data
access solely to improve a heuristic. If a team requires richer widths, grant
`SELECT` only to reviewed relations/columns and record that exception. The
optional `pg_read_all_stats` role reveals broader server statistics and must be
approved separately.

## Write and failure semantics

Synchronize into a temporary file beside the destination, then atomically
replace the destination only after the compressed payload is complete. A sync
failure must not remove or corrupt a previous cache.

When automatic sync fails, report the underlying failure and load the previous
readable V6 cache. Its confidence is determined by cache freshness and
analysis, not by the refresh failure alone. An unsupported older cache cannot
be used after a failed refresh. With no readable cache, analysis continues
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

1. versioned decode coverage, including generic legacy rejection;
2. atomic-write and failure-preservation tests;
3. CLI JSON/provenance coverage where user-visible;
4. encryption round-trip and rejection-path tests when applicable;
5. updates to `docs/CONTRACT.md`, the root README, and `CHANGELOG.md` for
   behavior changes.
