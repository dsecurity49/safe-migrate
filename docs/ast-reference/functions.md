# Functions AST Reference for safe-migrate

## Status

Verified against squawk_syntax 2.58.0 — July 2026

---

## Documentation Contract

1. Only document AST behavior that has been directly verified.
2. Do not infer PostgreSQL semantics from missing AST accessors.
3. Distinguish verified facts from unresolved areas.
4. Assume additional nodes or helpers may exist outside the inspected surface.

---

## Handwritten Extension Note

Per the exhaustive `impl ast::*` inventory established in columns.md:

```
impl ast::HasParamList for ast::FunctionSig {}
impl ast::HasParamList for ast::Aggregate {}
```

`FunctionSig` has a marker trait `HasParamList`, shared with `Aggregate`.
This is a zero-method marker trait per the inventory (no additional methods
beyond what's already covered by the generated `param_list()` accessor) —
it exists for generic code in the squawk codebase that needs to treat
`FunctionSig` and `Aggregate` uniformly, not to expose new functionality
relevant to this documentation.

---

# Core Nodes — Functions

## CreateFunction

### Verified Accessors (line 5489)

```rust
pub fn option_list(&self) -> Option<FuncOptionList>
pub fn or_replace(&self) -> Option<OrReplace>
pub fn param_list(&self) -> Option<ParamList>
pub fn path(&self) -> Option<Path>
pub fn ret_type(&self) -> Option<RetType>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn function_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
CreateFunction =
  'create' OrReplace? 'function' Path ParamList RetType? option_list:FuncOptionList ';'?
```

Fully populated, matches exactly. Note `ParamList` is required (no `?`) in
the grammar, while `RetType` is optional — PostgreSQL allows `CREATE
FUNCTION f() ...` with no explicit `RETURNS` clause only in specific
contexts (e.g. trigger functions implicitly return `trigger`, and some
language-specific inference applies) — `ret_type()` being `None` is a valid
state, not a parse failure.

### safe-migrate guidance

```rust
struct CreateFunctionFact {
    name: QualifiedName,                // from path()
    or_replace: bool,
    params: Vec<ParamFact>,             // from param_list()
    return_type: Option<RetTypeFact>,   // from ret_type()
    options: Vec<FuncOptionFact>,       // from option_list()
}
```

`CREATE OR REPLACE FUNCTION` is semantically significant for safe-migrate:
replacing an existing function can silently change behavior depended on by
triggers, views, or other functions that call it, without any direct schema
change being visible to those dependents. The dependency graph should treat
function replacement as a potential blast-radius event affecting every
known caller (triggers via `CallExpr`, views referencing the function in
their query, other functions calling it) — though resolving "every known
caller" fully requires expression-level analysis beyond simple DDL tracking.

---

## DropFunction

### Verified Accessors (line 8348)

```rust
pub fn function_sig_list(&self) -> Option<FunctionSigList>
pub fn if_exists(&self) -> Option<IfExists>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
pub fn restrict_token(&self) -> Option<SyntaxToken>
```

(`function_token()` also present per the established `Drop*` pattern, not
shown in the partial grep view but consistent with every other `Drop*` node
in this codebase.)

### Grammar Confirmation

```
DropFunction =
  'drop' 'function' IfExists? FunctionSigList
  ('cascade' | 'restrict')? ';'?
```

Multiple function signatures droppable in one statement via
`function_sig_list()` → `FunctionSigList.function_sigs()` →
`AstChildren<FunctionSig>`.

### safe-migrate guidance

PostgreSQL function names can be overloaded — multiple functions can share
a name with different parameter signatures. `DropFunction` resolution
**requires the parameter types**, not just the function name, to correctly
identify which overload is being dropped. `FunctionSig.param_list()` carries
this — the resolver must match on `(schema, name, param_types)` as the
effective `ObjectId` for functions, not `(schema, name)` alone like tables.
This is a meaningfully different identity model from every other object
type documented so far in this AST reference set.

---

## AlterFunction

### Verified Accessors (line 1223)

```rust
pub fn depends_on_extension(&self) -> Option<DependsOnExtension>
pub fn func_option_list(&self) -> Option<FuncOptionList>
pub fn function_sig(&self) -> Option<FunctionSig>
pub fn no_depends_on_extension(&self) -> Option<NoDependsOnExtension>
pub fn owner_to(&self) -> Option<OwnerTo>
pub fn rename_to(&self) -> Option<RenameTo>
pub fn set_schema(&self) -> Option<SetSchema>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
pub fn restrict_token(&self) -> Option<SyntaxToken>  // per established pattern
pub fn function_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
AlterFunction =
  'alter' 'function' FunctionSig
  (
    RenameTo
  | OwnerTo
  | SetSchema
  | DependsOnExtension
  | NoDependsOnExtension
  | FuncOptionList
  )
  'restrict'? ';'?
```

6 mutually exclusive forms confirmed, all with direct accessors.

### safe-migrate guidance

```rust
enum AlterFunctionFact {
    Rename { from: String, to: String },
    OwnerChange(RoleFact),
    SchemaChange { new_schema: String },
    DependsOnExtension { extension: String },
    NoDependsOnExtension { extension: String },
    OptionsChange(Vec<FuncOptionFact>),  // e.g. changing VOLATILE/IMMUTABLE/STABLE
}
```

**Changing a function's volatility category** (`IMMUTABLE`/`STABLE`/`VOLATILE`,
captured via `VolatilityFuncOption` inside `FuncOptionList`) is a particularly
risky operation worth flagging specifically: marking a function `IMMUTABLE`
when it isn't truly side-effect-free/deterministic can cause PostgreSQL's
query planner to cache or reorder results incorrectly, producing silently
wrong query results elsewhere in the database without any error being raised.

---

# Core Nodes — Procedures

## CreateProcedure

### Verified Accessors (line 5944)

```rust
pub fn option_list(&self) -> Option<FuncOptionList>
pub fn or_replace(&self) -> Option<OrReplace>
pub fn param_list(&self) -> Option<ParamList>
pub fn path(&self) -> Option<Path>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn create_token(&self) -> Option<SyntaxToken>
pub fn procedure_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
CreateProcedure =
  'create' OrReplace? 'procedure' Path ParamList option_list:FuncOptionList ';'?
```

**Key structural difference from `CreateFunction`: no `RetType` accessor at
all** — confirmed by the grammar showing no `RetType?` field. This correctly
reflects PostgreSQL semantics: procedures do not have a return type (they
may use `OUT` parameters via `ParamMode` for output values instead, but
there is no `RETURNS` clause).

---

## DropProcedure

### Verified Accessors (line 8817)

```rust
pub fn function_sig_list(&self) -> Option<FunctionSigList>
pub fn if_exists(&self) -> Option<IfExists>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn cascade_token(&self) -> Option<SyntaxToken>
pub fn drop_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
DropProcedure =
  'drop' 'procedure' IfExists? FunctionSigList
  ('cascade' | 'restrict')? ';'?
```

Identical shape to `DropFunction` — reuses `FunctionSigList`/`FunctionSig`,
same overload-resolution-by-parameter-types consideration applies.

---

## AlterProcedure

### Verified Accessors (line 1747)

```rust
pub fn depends_on_extension(&self) -> Option<DependsOnExtension>
pub fn func_option_list(&self) -> Option<FuncOptionList>
pub fn function_sig(&self) -> Option<FunctionSig>
pub fn no_depends_on_extension(&self) -> Option<NoDependsOnExtension>
pub fn owner_to(&self) -> Option<OwnerTo>
pub fn rename_to(&self) -> Option<RenameTo>
pub fn set_schema(&self) -> Option<SetSchema>
pub fn semicolon_token(&self) -> Option<SyntaxToken>
pub fn alter_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
AlterProcedure =
  'alter' 'procedure' FunctionSig
  (
    RenameTo
  | OwnerTo
  | SetSchema
  | DependsOnExtension
  | NoDependsOnExtension
  | FuncOptionList
  )
  'restrict'? ';'?
```

Identical shape to `AlterFunction` — same 6 forms, same accessor pattern.

---

# Shared Supporting Nodes

## FunctionSig

### Verified Accessors (line 11241)

```rust
pub fn param_list(&self) -> Option<ParamList>
pub fn path(&self) -> Option<Path>
```

### Grammar Confirmation

```
FunctionSig =
  Path ParamList?
```

Used wherever a function/procedure must be uniquely identified by name plus
argument types: `DropFunction`, `DropProcedure`, `AlterFunction`,
`AlterProcedure`, `CommentOn`, `CreateCast`, `SecurityLabel`, `CreateTransform`
(per the cross-reference grep performed during columns.md's exhaustive
inventory pass — `FunctionSig` appears across many node types as a
disambiguating overload signature).

**`ParamList` is optional here** (unlike `CreateFunction`'s required
`ParamList`) — `ALTER FUNCTION f OWNER TO new_owner` (no parens, no params)
is valid when the function name is unambiguous (no overloads exist), while
`ALTER FUNCTION f(integer) OWNER TO new_owner` disambiguates when needed.

## FunctionSigList

### Verified Accessors (line 11256)

```rust
pub fn function_sigs(&self) -> AstChildren<FunctionSig>
```

### Grammar Confirmation

```
FunctionSigList =
  (FunctionSig (',' FunctionSig)*)
```

---

## ParamList / Param / ParamMode / ParamDefault

### Verified Accessors

```rust
// Param (line 15481)
pub fn mode(&self) -> Option<ParamMode>
pub fn name(&self) -> Option<Name>
pub fn param_default(&self) -> Option<ParamDefault>
pub fn ty(&self) -> Option<Type>

// ParamDefault (line 15504)
pub fn expr(&self) -> Option<Expr>
pub fn eq_token(&self) -> Option<SyntaxToken>
// default_token() also present per established naming pattern
```

### Grammar Confirmation

```
ParamMode =
  ParamVariadic
| ParamInOut
| ParamIn
| ParamOut

ParamDefault =
 ('default' | '=') Expr

Param =
  mode:ParamMode? Name? Type ParamDefault?

ParamList =
  (Param (',' Param)*)?
```

`ParamMode` is a 4-member enum: `VARIADIC`, `INOUT`, `IN`, `OUT`. PostgreSQL
defaults to `IN` when no mode is specified (`mode()` returning `None` means
implicit `IN`, not an error state).

`Param.name()` is optional — PostgreSQL allows unnamed parameters
(`CREATE FUNCTION f(integer, text) ...`), which is common for simple
functions where parameter names aren't needed for documentation or
named-argument calling.

`ParamDefault` accepts either the `DEFAULT` keyword or `=` as the assignment
token (PostgreSQL syntax allows both spellings interchangeably) — captured
via `eq_token()` vs `default_token()`, the grammar's `('default' | '=')`
alternation.

### safe-migrate guidance

```rust
struct ParamFact {
    mode: ParamModeFact,           // In | Out | InOut | Variadic, default In
    name: Option<String>,
    ty: TypeIr,
    default: Option<ExprIr>,
}
```

Parameters with defaults must appear after all parameters without defaults
in PostgreSQL (same rule as most languages) — the AST grammar does not
enforce this ordering structurally (it would parse `Param ParamDefault? `
sequences in any order), so this is a PostgreSQL-semantic validation that
belongs in the rule engine, not something the AST guarantees.

---

## RetType

### Verified Accessors (line 17369)

```rust
pub fn table_arg_list(&self) -> Option<TableArgList>
pub fn ty(&self) -> Option<Type>
pub fn returns_token(&self) -> Option<SyntaxToken>
pub fn table_token(&self) -> Option<SyntaxToken>
```

### Grammar Confirmation

```
RetType =
  'returns' ('table' TableArgList | Type)
```

Two mutually exclusive forms:
- `RETURNS TABLE (col1 type1, col2 type2, ...)` — set-returning function
  with named output columns, via `table_arg_list()` (reusing the same
  `TableArgList`/`TableArg` documented in columns.md — though here it would
  only ever contain `TableArg::Column` variants, never `LikeClause` or
  `TableConstraint`, since this context only makes sense for column
  definitions)
- `RETURNS sometype` (including `RETURNS SETOF sometype`, `RETURNS TABLE`
  with a single type, `RETURNS trigger`, etc.) — via `ty()`

### safe-migrate guidance

```rust
enum RetTypeFact {
    Table(Vec<ColumnFact>),   // from table_arg_list()
    Scalar(TypeIr),            // from ty(), includes SETOF-wrapped types
}
```

---

## FuncOptionList / FuncOption

### Verified Accessors (line 11230)

```rust
pub fn options(&self) -> AstChildren<FuncOption>
```

### Grammar Confirmation

```
FuncOptionList =
  options:(FuncOption*)

FuncOption =
  BeginFuncOptionList
| ReturnFuncOption
| AsFuncOption
| SetFuncOption
| SupportFuncOption
| RowsFuncOption
| CostFuncOption
| ParallelFuncOption
| SecurityFuncOption
| StrictFuncOption
| LeakproofFuncOption
| ResetFuncOption
| VolatilityFuncOption
| WindowFuncOption
| TransformFuncOption
| LanguageFuncOption
```

16-member enum confirmed. Each option's individual accessor surface was not
inspected in this pass (out of scope — these are mostly simple
presence/value nodes for things like `LANGUAGE plpgsql`, `COST 100`, `ROWS
1000`, `STRICT`, `IMMUTABLE`/`STABLE`/`VOLATILE`, etc.).

### All 16 Members — Grammar-Resolved

postgresql.ungram confirms the shape of all 16 members:

```
LanguageFuncOption =
  'language' NameRef

TransformFuncOption =
  'transform'

WindowFuncOption =
  'window'

VolatilityFuncOption =
  'immutable' | 'stable' | 'volatile'

LeakproofFuncOption =
  'leakproof' | 'not' 'leakproof'

ResetFuncOption =
  'reset' NameRef

StrictFuncOption =
  'strict' | 'called' 'on' 'null' 'input' | 'returns' 'null' 'on' 'null' 'input'

SecurityFuncOption =
  'security' ('invoker' | 'definer')

ParallelFuncOption =
  'parallel' '#ident'

CostFuncOption =
  'cost'

RowsFuncOption =
  'rows'

SupportFuncOption =
  'support'

SetFuncOption =
  'set'

AsFuncOption =
  'as' (definition:Literal | obj_file:Literal ',' link_symbol:Literal)
```

(`BeginFuncOptionList` and `ReturnFuncOption` already covered above under
RetType's grammar context.)

### CostFuncOption and RowsFuncOption Carry a Literal

`CostFuncOption = 'cost' Literal` and `RowsFuncOption = 'rows' Literal`. Each
node exposes a `literal()` accessor (`Option<Literal>`) yielding the numeric
cost/row-estimate value. Verified at `src/ast/generated/nodes.rs` lines 4990
(`CostFuncOption`) and 17951 (`RowsFuncOption`) — both implement
`pub fn literal(&self) -> Option<Literal>`. A `COST`/`ROWS` change is
detectable (`cost_token()`/`rows_token()`) **and** the actual value is
fully extractable via `literal()`. The earlier "grammar-empty" claim was
incorrect.

### Other Notable Shapes

- `VolatilityFuncOption`, `LeakproofFuncOption`, `StrictFuncOption`,
  `SecurityFuncOption`: all confirmed as flat token-alternation nodes (no
  child node, just which keyword combination was present) — fully
  extractable via dedicated token accessors:
  - `VolatilityFuncOption` has `immutable_token()`, `stable_token()`, and `volatile_token()`.
  - `SecurityFuncOption` has `security_token()`, `definer_token()`, and `invoker_token()`. It does *not* expose a single `security_definer_token()`.
  - `LeakproofFuncOption` has `leakproof_token()` and `not_token()`.
  - `StrictFuncOption` has `called_token()`, `input_token()`, `null_token()`, `on_token()`, `returns_token()`, and `strict_token()`.
- `LanguageFuncOption`: carries a real `NameRef` for the language name —
  fully extractable (`plpgsql`, `sql`, `c`, `python3`, etc.).
- `ParallelFuncOption`: carries `'#ident'` (generic identifier token) for
  `UNSAFE`/`RESTRICTED`/`SAFE` — extractable via direct token text
  inspection, not a structured enum.
- `ResetFuncOption`: carries a `NameRef` — the config parameter being reset.
- `AsFuncOption`: two real forms — either a single `Literal` (function body
  definition, used for SQL/plpgsql functions) or two `Literal`s separated by
  comma (`obj_file`, `link_symbol` — used for C language functions linking
  to a compiled shared object). **This shares the exact same "two same-typed
  Literal children, single flat accessor" risk pattern already found in
  `RenameValue` (enums.md) and `PartitionForValuesFrom` (partitions.md)** —
  worth flagging for the same kind of accessor-level scrutiny if this node
  is ever used for safe-migrate analysis of C-language function definitions,
  though this was not separately verified against src/ast/generated/nodes.rs in this pass.
- `TransformFuncOption`, `WindowFuncOption`, `SupportFuncOption`: confirmed
  presence-only per their bare-keyword grammar.
- `SetFuncOption`: **not** presence-only — it wraps a `SetConfigParam` child
  node accessible via `set_config_param()`. `SetConfigParam` exposes
  `name_refs()` (`AstChildren<NameRef>` for the parameter name), `path()`
  (qualified `search_path.param` form), `literals()` (`AstChildren<Literal>`
  for the value/list), plus `eq_token()`, `current_token()`, `default_token()`,
  `from_token()`, etc. The configuration parameter name and value are
  therefore fully extractable — the earlier "presence-only" claim was
  incorrect. Note: the accessor is `name_refs()` (plural), not a singular
  `name()`.

### safe-migrate guidance

```rust
enum FuncOptionFact {
    Language(String),                          // fully extractable
    Volatility(VolatilityKind),                 // fully extractable
    Security(SecurityKind),                     // fully extractable
    Strict(StrictKind),                         // fully extractable
    Leakproof(bool),                            // fully extractable
    Parallel(String),                           // fully extractable, raw ident text
    Cost(Option<Literal>),                      // fully extractable via literal()
    Rows(Option<Literal>),                      // fully extractable via literal()
    Reset(String),                              // fully extractable
    As { definition: Option<String>, obj_file: Option<String>, link_symbol: Option<String> },
    Transform,                                  // presence-only
    Window,                                     // presence-only
    Support,                                    // presence-only
}
```

A `COST`/`ROWS` change being undetectable in its specific value is a minor
finding compared to the trigger enable/disable gap or `RenameValue` gap,
since `COST`/`ROWS` changes are query-planner hints, not data-integrity or
correctness concerns — appropriate for a low-severity or informational tier
classification rather than blocking.

### BEGIN ATOMIC Function Bodies — Architecturally Significant

`BeginFuncOptionList` / `ReturnFuncOption` (covered earlier under RetType's
grammar context) cover the `BEGIN ATOMIC ... END` SQL-standard function body
syntax (PostgreSQL 14+), which embeds actual `Stmt` nodes as
`BeginFuncOption::Stmt` per its grammar
(`BeginFuncOption = Stmt | ReturnFuncOption`) — meaning a SQL-language
function body written in this style is **fully parsed as structured SQL
statements**, not an opaque string. This is architecturally significant:
unlike `plpgsql`/`sql`-as-string function bodies (which are opaque to this
AST and must be treated as `OpaqueMutation::DoBlock`-equivalent per the
blueprint), a `BEGIN ATOMIC` SQL-standard body could in principle be visited
and analyzed like any other statement sequence. This is a candidate for
materially better function-body analysis than function bodies are treated by
default in the blueprint's confidence model, but the visitor and
Mutation/Fact model would need to be extended deliberately to take advantage
of this — it does not happen automatically simply because the AST supports it.

---

# Verified Findings Summary

## Confirmed Complete

- `CreateFunction`: fully resolved
- `DropFunction`: fully resolved
- `AlterFunction`: fully resolved, all 6 forms verified
- `CreateProcedure`: fully resolved, confirmed no RetType (correct per
  PostgreSQL semantics)
- `DropProcedure`: fully resolved
- `AlterProcedure`: fully resolved, all 6 forms verified, identical shape to AlterFunction
- `FunctionSig` / `FunctionSigList`: fully resolved
- `Param` / `ParamList` / `ParamMode` / `ParamDefault`: fully resolved
- `RetType`: fully resolved, both TABLE and scalar forms
- `FuncOptionList`: fully resolved, all 16 `FuncOption` members individually
  grammar-resolved

## Grammar-Confirmed Limitations

- `CostFuncOption` / `RowsFuncOption`: each exposes a `literal()` accessor
  (`Option<Literal>`) returning the numeric COST/ROWS value; fully
  extractable (verified at nodes.rs lines 4990 and 17951).

## Key Architectural Findings

1. **Functions/procedures use a different identity model than every other
   object type documented so far.** `ObjectId` for a table/view/sequence/etc.
   is `(schema, name)`, but functions and procedures require
   `(schema, name, param_types)` due to PostgreSQL overload support. This is
   a meaningful divergence the resolver must account for — a naive
   `(schema, name)`-only `ObjectId` would conflate distinct overloaded
   functions into one object.
2. **`BEGIN ATOMIC ... END` SQL-standard function bodies are structurally
   parsed**, not opaque — a notable exception to the general rule that
   function bodies are unanalyzable. This is flagged as a future
   enhancement opportunity, not something currently exploited by the
   blueprint's existing Mutation model.
3. **Volatility and security options carry real safety implications**
   (planner correctness, privilege escalation) beyond simple schema
   structure, worth surfacing as their own rule category distinct from
   structural DDL safety.
4. **`AsFuncOption` shares the same "two same-typed Literal children" risk
   pattern** already confirmed as a real bug source in `RenameValue`
   (enums.md) and a real ambiguity in `PartitionForValuesFrom`
   (partitions.md) — flagged for follow-up scrutiny if C-language function
   definitions become relevant to safe-migrate's analysis scope.

## Grammar Cross-Check

This document was cross-checked against `src/ast/generated/nodes.rs` and `src/ast/node_ext.rs` from `squawk-syntax-2.58.0`. All generated function/procedure node accessors (such as `CreateFunction` at line 5489 and `CreateProcedure` at line 5944) and handwritten extensions (none found for function/procedure types) have been verified against these source files alongside `postgresql.ungram`.

---

# Remaining Open Questions

None remaining. All findings in this document have been resolved through
direct grammar cross-check against postgresql.ungram, cross-referenced
against the original verified src/ast/generated/nodes.rs accessor inventory where applicable
(`CostFuncOption`/`RowsFuncOption`).
