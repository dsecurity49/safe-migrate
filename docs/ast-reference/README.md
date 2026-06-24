# AST Reference Documentation

**For Contributors & Maintainers Only** — This is internal reference material for extending the AST extraction logic or understanding how safe-migrate parses PostgreSQL DDL.

If you're using safe-migrate as a user, see the main [README.md](../README.md) instead.

---

This directory contains verified PostgreSQL grammar and AST node extraction guides for safe-migrate contributors. Each document maps PostgreSQL DDL syntax to the typed AST nodes exposed by `squawk_syntax`, including:

- Complete node accessor methods with return types
- Polymorphic node dispatch patterns (token-presence based)
- Handwritten extensions in the crate
- Grammar-confirmed limitations and gaps

**Verified against:** `squawk_syntax` v2.56.0  
**PostgreSQL grammar version:** PostgreSQL 17 (latest at time of review)  
**Last reviewed:** [DATE]

---

## Document Index (22 files)

### Schema Definition & Structure

| Document | Coverage | Key Nodes |
|----------|----------|-----------|
| **columns.md** | Column lifecycle, constraints, defaults | `Column`, `ColumnList`, `AddColumn`, `AlterColumn`, `DropColumn`, `RenameColumn`, `TableArg` enum (3 members) |
| **constraints.md** | FK, CHECK, UNIQUE, PRIMARY KEY, exclusion | `Constraint` (9 variants), `ColumnConstraint` (7), `TableConstraint` (5), `ForeignKeyConstraint`, `UniqueConstraint` |
| **indexes.md** | Index creation, alteration, dropping, concurrency | `CreateIndex`, `DropIndex`, `AlterIndex`, `PartitionItem` (missing sort order), multiple index support |
| **partitions.md** | Partition hierarchies, RANGE/LIST/HASH, attach/detach | `CreateTable.partition_by()`, `PartitionOf.path()`, `AttachPartition`, `DetachPartition`, reverse-graph walk required |
| **sequences.md** | Sequence creation, OWNED BY, ownership tracking | `SequenceOption` (polymorphic, 14 variants), `extract_owned_by` text-search workaround, `AlterSequence` options missing |
| **schemas.md** | Schema creation/dropping, identifier normalization | `CreateSchema`, `DropSchema`, `NameRef.text()` + `is_quoted()` (handwritten), case-folding rules |

### Data Types & Domains

| Document | Coverage | Key Nodes |
|----------|----------|-----------|
| **enums.md** | Enum type definition, value management | `CreateType` (4 polymorphic forms: enum, range, composite, shell), `AlterType` |
| **domains.md** | Domain creation, constraints, defaults | `CreateDomain`, `DropDomain`, `AlterDomain`, `AlterDomainAction` (11 variants) |

### Views & Materialized Views

| Document | Coverage | Key Nodes |
|----------|----------|-----------|
| **views.md** | View creation, alteration, dropping, materialized views | `CreateView`, `AlterView`, `DropView` (single path, **asymmetry with DropIndex**), `CreateMaterializedView`, `AlterMaterializedView`, `DropMaterializedView`, `Refresh` |
| **materialized_views.md** | Reference to views.md with physical storage emphasis | Cross-reference document |

### Functions & Procedures

| Document | Coverage | Key Nodes |
|----------|----------|-----------|
| **functions.md** | Function/procedure creation, parameters, volatility | `CreateFunction`, `FuncOptionList`, volatility detection (`VOLATILE`, `STABLE`, `IMMUTABLE`) |
| **triggers.md** | Trigger creation, event detection, timing | `CreateTrigger`, `DropTrigger`, `AlterTrigger`, event detection via token presence |

### Access Control & Permissions

| Document | Coverage | Key Nodes |
|----------|----------|-----------|
| **roles.md** | Role/user/group creation, membership, attributes | `CreateRole` (3 semantic aliases: ROLE, USER, GROUP), `DropRole`, `AlterRole`, `GrantRole`, `RevokeRole` |
| **grant_revoke.md** | Grant/revoke of privileges on objects | `Grant`, `Revoke`, `RevokeCommandList`, `Privileges`, `PrivilegeTarget`, `AlterDefaultPrivileges` |
| **security_model.md** | Two-axis risk model: structural vs access-control | Conceptual framework, orthogonal to other docs |

### Replication & Subscriptions

| Document | Coverage | Key Nodes |
|----------|----------|-----------|
| **publications.md** | Logical replication publication creation, table lists | `CreatePublication` (ALL TABLES vs explicit list), dual-form dispatch |
| **subscriptions.md** | Logical replication subscription management | `CreateSubscription`, `DropSubscription`, `AlterSubscription` |

### Database & Session Configuration

| Document | Coverage | Key Nodes |
|----------|----------|-----------|
| **database.md** | Database creation, alteration, dropping | `CreateDatabase`, `DropDatabase`, `AlterDatabase` |
| **search_path.md** | Schema resolution, search_path configuration | `Set` (polymorphic, 20+ forms), `config_values()` → `AstChildren<ConfigValue>`, no dedicated SearchPath node |
| **transactions.md** | Transaction control, savepoints, rollback forms | `Begin`, `Commit`, `Rollback` (polymorphic: full/SAVEPOINT/PREPARED), `Savepoint`, `Release` |

### Row-Level Security & Policies

| Document | Coverage | Key Nodes |
|----------|----------|-----------|
| **policies.md** | RLS policy creation, two-layer model (policy objects + table toggle) | `CreatePolicy`, `DropPolicy`, `AlterPolicy` |

### Non-Schema Side Effects

| Document | Coverage | Key Nodes |
|----------|----------|-----------|
| **non_schema_effects.md** | **[SYNTHESIS]** Session context changes, replication effects, config params | Taxonomy + simulator handling strategy, cross-references all other docs |

---

## Key Architectural Patterns

### Polymorphic Nodes (Token Dispatch Required)

Three nodes require explicit token-combination matching instead of enum dispatch:

1. **`Set`** (search_path.md, non_schema_effects.md)
   - 20+ parameter types, distinguished by token presence
   - Example: `SET search_path = ...` detected via `path()` accessor + string comparison

2. **`Rollback`** (transactions.md)
   - Full rollback vs `ROLLBACK TO SAVEPOINT` vs `ROLLBACK PREPARED`
   - Dispatch: `to_token().is_none()` + `prepared_token().is_none()`

3. **`SequenceOption`** (sequences.md)
   - 14 option types, dispatched by token presence
   - OWNED BY extraction requires text-search workaround

### Handwritten Extensions (18 total)

Most impactful for safe-migrate:
- `RenameColumn.from()` / `to()` (columns.md)
- `ForeignKeyConstraint.from_columns()` / `to_columns()` (constraints.md)
- `NameRef.text()` / `is_quoted()` (schemas.md) — **Critical for identifier normalization**
- `BinExpr.lhs()` / `rhs()` / `op()` (expressions, not in this index)

See individual documents for complete list.

### Grammar-Confirmed Limitations

These are parser limitations, not extraction gaps:

| Limitation | Document | Impact |
|-----------|----------|--------|
| `PartitionItem` missing sort order (ASC/DESC), nulls ordering, operator class | partitions.md | Cannot extract partition column specifics |
| `PartitionOf` missing FOR VALUES bounds | partitions.md | Cannot validate partition ranges |
| `AlterSequence` missing options clause | sequences.md | Cannot analyze sequence alterations |
| `CreateIndex INCLUDE` clause missing | indexes.md | Covering columns not extractable |
| `AlterPublication` / `AlterSubscription` value extraction missing | publications.md, subscriptions.md | Cannot determine which tables added/dropped |
| `ALTER DATABASE SET param` / `ALTER ROLE SET param` value extraction missing | database.md, roles.md | Future-session config changes not fully analyzable |

---

## Using These Docs

### For AST Visitor Writers

When implementing `AstVisitor::extract()` for a new statement:

1. Find the statement node in the appropriate document
2. Check the **Accessor Methods** section for what can be extracted
3. Look for **Handwritten Extensions** in that document or cross-references
4. Check **Confirmed Limitations** to know what's unavailable
5. For polymorphic nodes, implement explicit token dispatch (see examples)

### For Rule Implementers

When writing a new rule evaluation:

1. Check **non_schema_effects.md** to understand which DDL affects schema state vs runtime behavior
2. Reference the relevant document for your mutation type (e.g., **constraints.md** for FK rules)
3. Note grammar gaps that might affect your rule's confidence level

### For Engine Maintainers

When updating to a new `squawk_syntax` version:

1. Review the grammar changelog against **each document** to identify breaking changes
2. Update accessor methods and limitations lists
3. Rerun extraction tests against the full test suite (78+ tests should catch most gaps)
4. Update version/review date at top of this README

---

## Navigation

- **By PostgreSQL feature:** Use the index tables above
- **By AST pattern:** Search for node names (e.g., "Set", "Rollback", "SequenceOption")
- **By limitation:** See the "Grammar-Confirmed Limitations" table above
- **Conceptually:** Start with **non_schema_effects.md** to understand schema vs non-schema DDL

---

## Document Maintenance Notes

- **No new grammar parsing needed** for v0.3.0 — all gaps are parser-level limitations, not extraction problems
- These docs are **reference, not tutorial** — assume familiarity with PostgreSQL DDL and the squawk AST structure
- **Update frequency:** After squawk_syntax updates or when new rule types require expanded extraction
- **Verification method:** Compare document examples against `src/ast/visitor.rs` implementations and test suite coverage

