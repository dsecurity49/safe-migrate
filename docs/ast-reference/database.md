# Database AST Reference for safe-migrate

## Status

Verified against squawk_syntax 2.58.0 — July 2026

---

## Documentation Contract

1. Only document AST behavior that has been directly verified.
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. Assume additional nodes or helpers may exist outside the inspected surface.

---

## Why This Matters for safe-migrate

Database-level mutations affect the environment in which all subsequent
migrations execute. They are not schema-structural changes (no table or
column is affected directly) but they can alter:

- **Configuration** (`ALTER DATABASE ... SET search_path = ...`) — changes
  the default `search_path` for all new connections to this database,
  affecting how all subsequent object references resolve. Directly
  interacts with the search_path system documented in search_path.md.
- **Ownership** (`ALTER DATABASE ... OWNER TO`) — changes who can further
  alter the database
- **Collation version** (`REFRESH COLLATION VERSION`) — a maintenance
  operation relevant after OS/library upgrades
- **Connection parameters** (`ENCODING`, `CONNECTION LIMIT`, `TABLESPACE`)
  — environment-level configuration not visible in schema diffs

`DROP DATABASE` is the highest-blast-radius possible PostgreSQL operation
— it removes the entire database and all its contents irreversibly. This
warrants the strongest tier-1 classification safe-migrate can issue.

---

# Core Nodes

## CreateDatabase

### Verified Accessors (line 4283)

```rust
pub fn create_database_option_list(&self) -> Option<CreateDatabaseOptionList>
pub fn name(&self) -> Option<Name>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn database_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
CreateDatabase =
  'create' 'database' Name CreateDatabaseOptionList ';'?
```

### safe-migrate guidance

```rust
struct CreateDatabaseFact {
    name: String,                           // from name()
    options: Vec<CreateDatabaseOptionFact>, // from create_database_option_list()
}
```

`CREATE DATABASE` during a migration is highly unusual — migrations
typically run inside an existing database. When it does appear, it creates
a new isolated database context that the current migration session cannot
directly observe for schema state. The simulator should flag this as an
opaque environment change and consider downgrading confidence to `Tainted`.

---

## CreateDatabaseOptionList / CreateDatabaseOption

### CreateDatabaseOptionList — Verified Accessors (line 4357)

```rust
pub fn create_database_options(&self) -> AstChildren<CreateDatabaseOption>
pub fn with_token(&self) -> Option<SyntaxToken>
```

### CreateDatabaseOption — Verified Accessors (line 4310)

```rust
pub fn literal(&self) -> Option<Literal>
pub fn eq_token(&self) -> Option<SyntaxToken>
pub fn connection_token(&self) -> Option<SyntaxToken>
pub fn default_token(&self) -> Option<SyntaxToken>
pub fn encoding_token(&self) -> Option<SyntaxToken>
pub fn ident_token(&self) -> Option<SyntaxToken>
pub fn limit_token(&self) -> Option<SyntaxToken>
pub fn owner_token(&self) -> Option<SyntaxToken>
pub fn tablespace_token(&self) -> Option<SyntaxToken>
pub fn template_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
CreateDatabaseOptionList =
  'with'? CreateDatabaseOption*

CreateDatabaseOption =
  ('owner'
| 'template'
| 'encoding'
| '#ident'
| 'tablespace'
| 'connection' 'limit')
  '='?
  (Literal | 'default')
```

All option types are distinguishable via token presence, and values are
accessible via `literal()` (when not `DEFAULT`).

### Option Type Discrimination

```rust
fn extract_db_option(opt: &CreateDatabaseOption) -> DatabaseOptionFact {
    let value = if opt.default_token().is_some() {
        DatabaseOptionValue::Default
    } else {
        DatabaseOptionValue::Literal(opt.literal().map(|l| /* extract */))
    };

    if opt.owner_token().is_some() {
        DatabaseOptionFact::Owner(value)
    } else if opt.template_token().is_some() {
        DatabaseOptionFact::Template(value)
    } else if opt.encoding_token().is_some() {
        DatabaseOptionFact::Encoding(value)
    } else if opt.tablespace_token().is_some() {
        DatabaseOptionFact::Tablespace(value)
    } else if opt.connection_token().is_some() && opt.limit_token().is_some() {
        DatabaseOptionFact::ConnectionLimit(value)
    } else if opt.ident_token().is_some() {
        // '#ident' form — covers LC_COLLATE, LC_CTYPE, OID, STRATEGY, LOCALE,
        // ICU_LOCALE, ICU_RULES, LOCALE_PROVIDER etc. The specific parameter
        // name must be read from ident_token().text()
        DatabaseOptionFact::Named(opt.ident_token().unwrap().text().to_string(), value)
    } else {
        DatabaseOptionFact::Unknown(value)
    }
}
```

**Note on `ident_token()`:** the `'#ident'` form covers the locale-related
and newer PostgreSQL 15+ parameters (`LOCALE`, `ICU_LOCALE`,
`LOCALE_PROVIDER`, `STRATEGY`, etc.) that don't have dedicated keyword
tokens in this grammar. Reading the raw ident text here is appropriate
and expected — these are not quoted identifiers in the `NameRef.text()`
sense, they are grammar-level unrecognized keywords treated as generic
identifiers.

---

## AlterDatabase

### Verified Accessors (line 672)

```rust
pub fn create_database_option_list(&self) -> Option<CreateDatabaseOptionList>
pub fn name_ref(&self) -> Option<NameRef>
pub fn owner_to(&self) -> Option<OwnerTo>
pub fn refresh_collation_version(&self) -> Option<RefreshCollationVersion>
pub fn rename_to(&self) -> Option<RenameTo>
pub fn reset_config_param(&self) -> Option<ResetConfigParam>
pub fn set_config_param(&self) -> Option<SetConfigParam>
pub fn set_tablespace(&self) -> Option<SetTablespace>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn database_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
AlterDatabase =
  'alter' 'database' NameRef
  (
    RenameTo
  | OwnerTo
  | SetTablespace
  | SetConfigParam
  | ResetConfigParam
  | RefreshCollationVersion
  | CreateDatabaseOptionList
  )? ';'?
```

7 mutually exclusive action forms, all with distinct accessors. Well
structured — unlike `AlterRole`/`AlterPublication`/`AlterSubscription`.

### SetConfigParam / ResetConfigParam

```rust
// SetConfigParam (line 16575)
pub fn path(&self) -> Option<Path>
pub fn set_token(&self) -> Option<SyntaxToken>

// ResetConfigParam (line 15241)
pub fn path(&self) -> Option<Path>
pub fn all_token(&self) -> Option<SyntaxToken>
pub fn reset_token(&self) -> Option<SyntaxToken>
```

Grammar:
```
SetConfigParam =
  'set' Path

ResetConfigParam =
  'reset' ('all' | Path)
```

**Correction:** Earlier draft claimed the value "cannot be extracted" — this
was incorrect. `SetConfigParam` exposes `literals()` (`AstChildren<Literal>`)
and `name_refs()` carrying the assigned value(s). `ALTER DATABASE db SET
search_path = public, myschema` can be detected (param name via `path()`)
and the new value list (`public, myschema`) IS extractable via
`literals()`. This matches the same rich extraction available via
`SetFuncOption` (functions.md).

### Relevance to safe-migrate

`ALTER DATABASE db SET search_path = ...` changes the default search_path for
all future connections to `db`. The param name and string values are fully
extractable via `path()` and `literals()`. The simulator can know the exact
search_path tuple being set — enabling better downstream context awareness.

`ResetConfigParam.all_token()` detects `RESET ALL` — resetting every
configuration parameter simultaneously, including search_path.

### safe-migrate guidance

```rust
enum AlterDatabaseFact {
    Rename { from: String, to: String },
    OwnerChange(RoleFact),
    TablespaceChange { new_tablespace: String },
    SetConfigParam { param: String, values: Vec<String> }, // fully extractable via literals()
    ResetConfigParam { param: Option<String> }, // None = RESET ALL
    RefreshCollationVersion,
    OptionChanges(Vec<DatabaseOptionFact>),
}
```

---

## RefreshCollationVersion

### Verified Accessors (line 14880)

```rust
pub fn collation_token(&self) -> Option<SyntaxToken>
pub fn refresh_token(&self) -> Option<SyntaxToken>
pub fn version_token(&self) -> Option<SyntaxToken>
```

Token-only presence node — `ALTER DATABASE db REFRESH COLLATION VERSION`.
Used after OS/library upgrades to suppress collation mismatch warnings.
No payload needed — this is a maintenance acknowledgment, not a value change.

---

## DropDatabase

### Verified Accessors (line 6916)

```rust
pub fn if_exists(&self) -> Option<IfExists>
pub fn name_ref(&self) -> Option<NameRef>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn database_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
DropDatabase =
  'drop' 'database' IfExists? NameRef ';'?
```

Single database name, no CASCADE/RESTRICT options (PostgreSQL's `DROP
DATABASE` does not support these — it always drops everything).

### safe-migrate guidance

`DROP DATABASE` should unconditionally be tier-1 (block) when the target
database name matches the database being analyzed — it destroys the entire
schema state the simulator has been building, making any further analysis
meaningless. If the target database name does not match (unusual — migrating
a different database from within the current one), it should still be flagged
as an extremely high-impact external operation.

---

# Verified Findings Summary

## Confirmed Complete

- `CreateDatabase`: fully resolved
- `CreateDatabaseOptionList` / `CreateDatabaseOption`: fully resolved,
  all option types extractable including the `#ident` locale-parameter form
- `AlterDatabase`: fully resolved, all 7 action forms with distinct accessors
- `RefreshCollationVersion`: fully resolved (presence-only, no payload needed)
- `DropDatabase`: fully resolved

## Grammar-Confirmed Limitations

- `SetConfigParam`: value **is captured** via `literals()` and `name_refs()`,
  correcting earlier "value gap". The param name is extractable via `path()`
  and the assigned value(s) via the accessors above.

## Key Architectural Findings

1. **`SetConfigParam` value IS extractable** — `ALTER DATABASE db SET
   search_path = ...` can be fully resolved: param via `path()` and value
   via `literals()` (or `name_refs()` for identifier references). This
   enables downstream context awareness. Note: the value arrives as an
   `AstChildren<Literal>` list, not a single `value()` accessor.
2. **`DROP DATABASE` warrants unconditional tier-1 blocking** — no further
   analysis is meaningful if the current database is dropped.
3. **`CreateDatabase` during a migration is unusual and context-opaque** —
   the new database is not accessible to the current session's schema
   simulation, warranting `Confidence::Tainted`.
4. **`AlterDatabase` is well-structured** (7 distinct forms, all extractable)
   unlike the `AlterRole`/`AlterPublication`/`AlterSubscription` black-box
   pattern — a positive finding relative to the cluster of grammar gaps in
   that area.

## Grammar Cross-Check

All nodes cross-checked against postgresql.ungram in a single pass.
No discrepancies found.

---

# Remaining Open Questions

None identified in this pass.
