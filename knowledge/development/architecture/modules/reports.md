---
title: "Module: reports — contract for the definition AST, dataset registry, compiler and run record"
date: 2026-10-30
updated: 2026-10-30
status: draft
owner: heramb
author: solution-architect
ticket: T-0865
tier: server
binding_sources: ADR-0002, ADR-0003, ADR-0005 rule 10, ADR-0010 (proposed), safe-primitives P5 and P7, reports-2a spec (scope locked)
---

# Module `reports`: definition AST, dataset registry, compiler and run record

**Purpose.** An admin opens a canned report, sees results already trimmed to what they may read,
and exports or schedules exactly what they saw.
**Owner:** reporting-engineer (blueprint §5.4). **Epic:** E-002. **Spec:**
[reports-2a](../../../product/specs/reports-2a.md) (scope locked; this page changes no report and
no acceptance criterion).
**Parity:** ADM-083, ADM-084, ADM-085, ADM-086, ADM-087, ADM-089, ADM-099, ADM-100, ADM-101.
**Capabilities required (`Requires()`):** none at 2a, so the module loads in every profile.
**Platform matrix:** `windows` and `linux-oci` behave the same. Reports are server-side, read
PostgreSQL, and reach DCs only through the connector's `ReadPerDC` over the same transport in both
profiles (spec §10; ADR-0002 rule 1). Entra datasets are absent at 2a (spec §11), and that is a
scope decision, not a platform asymmetry.

> **This page comes before the code.** `internal/modules/reports/` does not exist yet. Row B4 of
> §12 creates the module and takes this page over as its module page (modules/README). Until
> then the page is the build contract. Every Go name below is the name the build tickets use. A
> ticket that needs a different name changes this page in the same change.

## 0. What exists today (grep, 2026-10-30) and what this page fixes

| Piece | State today | Where this page fixes it |
| --- | --- | --- |
| `internal/platform/report` (EP-8 host), `Registrar.Dataset` | **Built (T-0956, row B1).** Pure types and `Resolve` (no SQL driver), `Registrar.Dataset`, `Contributions.Datasets()`, `platform.Deps.Report`, and the Boot table-ownership check (`report.CheckTables`). Deviations below | §2, §3, row B1 |
| `internal/platform/store/reportsql` | **Missing.** `sqlconst` (FF-SP2) already lets values of type `reportsql.CompiledSQL` through, and `tools/gen/api` holds a pending `ReportAst → reportsql.Report` binding | §5, rows B1 and B2, RP1 |
| Directory read-scope producer | **Built (T-0880, T-0881, T-0882).** `authz.ReadScope` and the EP-6 `ScopeEvaluator` host (T-0880), the `ou_one_level` root kind (T-0881), and the one producer `rbac.ReadScopes.For` with the read oracle `authz.Evaluator.AuthorizeRead` (T-0882). The old per-object post-filter over candidates, which had no callers, is deleted. Two adapters are still to be wired in `compose/server`: `rbac.OwnerStatus` (over the account store) and `rbac.ObjectConnections` (over inventory) | §4 |
| Inventory rows | `directory_objects` (migration 0033) holds `connection_id`, `object_guid`, `nc_guid`, `parent_guid`, `ancestry uuid[]`, `kind`, `state`, `lockout_time`, `pwd_last_set`, `account_expires`, `attributes jsonb`, `observed_at`. Links are in `links` (0012). There is no GIN index on `ancestry`, no policy-input tables (D4) and no group closure. Row P2 (T-0948, migration 0059) is built: `Populate` takes a per-(tenant, connection) advisory lock and refuses non-READ COMMITTED transactions (DM-16.I10); `ancestry_complete` is derived by the writer on every upsert (`objects.go`, `upsertObjectSQL`), a move rewrites every descendant's `ancestry` in the same transaction (`rewriteDescendants`, found by `ancestry @>` until B3's GIN index) and `repairCompleteness` walks `parent_guid` to set or clear the flag below a row that arrived or changed. Row P1 (T-0949, migration 0060) is built: `nc_sync_passes` (one row per tenant, connection, NC) holds `last_pass_at` and `state` (`ok`, `resync_required`, `paused`). `Writer.RecordPass` sets the pass as-of (start of the read) in the cycle's transaction and `Ingest` calls it on the last batch for each `Cycle.PassNCs`, so a quiet domain is fresh; `Writer.MarkNC` records resync or pause; `Reader.Freshness` returns `[]report.NCWatermark` and the `report.Label` result, with `DefaultStalenessThreshold` = 60 min | §3.4, §4.5, rows P1, **P2**, B3, B6 |
| `platform/export` | CSV and XLSX encoders, `export.Cell`, `Source`, `Run`, `RunToBlob` (T-0150). **No canonical digest** (spec §8.3) | §7, row B9 |
| `platform/jobs` | Kinds, `ModeDefault` and `ModeManagedTx`, queue, leases, and the DM-44 `Schedule` value (T-0951: recurrence, IANA zone, DST rules, `Check` fires a missed run once). **The stored schedule table and the tick loop are not built** (T-0951 follow-up) | §8, row P4 |
| `platform/notify` | `notify/api` and `notify/syslog` only. **No SMTP, no DM-84 Delivery** | §7.2, §8, row P3 |
| Per-DC read | `ReadPerDC` exists in the connector proto (`read.proto`). There is **no Go client method** in `directory/client` | §6.5, row P5 |
| `platform/store` | Entry points `WithTenant`, `WithTenantSeparate` and `WithPlatform`. `store.Tx` exposes `Exec`, `Query` and `QueryRow` | §6.3 uses them as they are |

The ticket numbers in the spec's traceability table (T-0075, T-0089, T-0094, T-0099…T-0104,
T-0181, T-0182) were plan placeholders and now name unrelated tickets. **§12 replaces them.**
T-0874 carries the spec and blueprint edits.

## 1. Rules this module obeys (summary)

1. **A report is data.** It is a `report.Definition` (an AST over one registered dataset). No report
   accepts LDAP filter text or any text that is executed (FR-05, DM-71.I3).
2. **One compiler.** `reportsql.Compile` is the only producer of dynamic SQL. Identifiers come only
   from the pre-quoted registry. Operators, sort directions and value types are enums. Every value
   is a bind parameter (P5 rules 3 and 13).
3. **Authority is in the query.** The runner's `authz.ReadScope` is rendered into the `WHERE` by the
   compiler, so counts and pages come after trimming (LF-39, FR-07). An empty scope, an unknown
   kind, a zero root or a row whose ancestry is not known to be complete compiles to `FALSE`: zero
   rows, with the reason recorded. Every directory relation a column reads goes through a
   compiler-scoped anchor, so no count, name or GUID outside the scope reaches a cell (§3.3).
4. **A run is frozen.** Rows are stored once per run (ADR-0010). Pages, sorts, exports, digests
   and deliveries read the stored rows and never re-query a dataset.
5. **Derived states are SQL columns.** `locked_out`, `password_state` and the other derived states
   are dataset columns evaluated in the compiled query, with `now` bound once per run (FR-09). They
   are never computed by a loop after the query.
6. **A run is readable only by its runner under the scope it was computed with** (§6.6). Another
   account gets 404; the runner whose scope has changed gets 409 and re-runs. A delivered file is
   readable only through its DM-84 Delivery row (§7.2).

## 2. Packages and ownership

| Package | Owner | Holds | May import |
| --- | --- | --- | --- |
| `internal/platform/report` | reporting-engineer | EP-8 host: `Dataset`, `Column`, `Definition`, `Query` (the AST), `Cell`, `Narrowing`, `Freshness`, `PerDCReader` port, `Host`. Pure types and validation, with **no SQL driver** (FF-SP1) | `authz` (types), `tenant`, stdlib |
| `internal/platform/store/reportsql` | reporting-engineer. security-architect reviews every change (P5 rule 3) | `Registry` (pre-quoted, built once), `Compile`, `CompileCount`, `Exec`, `Query`, `CompiledSQL`, term rendering | `report`, `authz`, `store`, pgx (it sits under `store`) |
| `internal/directory/inventory` | directory-engineer | descendant ancestry rewrite on move and `ancestry_complete` (row P2); the datasets `inventory.users`, `.computers`, `.groups`, `.group_members`, `.ous` and `.contacts` through `inventory.Datasets() []report.Dataset`; the D4 policy-input tables; the D6 watermarks through `Reader.Freshness` (built, row P1) | `report` (types only) |
| `internal/platform/authz` + `internal/platform/rbac` + `modules/delegation` | backend-engineer | `authz.ReadScope` (**T-0880**), the `ou_one_level` root kind (**T-0881**) and the producer `rbac.ReadScopes` (**T-0882**), fed by the EP-6 `ScopeEvaluator`s that `delegation` registers (T-0880) | as today |
| `internal/modules/reports` (+ `run`, `library`, `export`, `schedule` subpackages) | reporting-engineer | DM-71 to DM-73 tables, the library, the run path, export jobs, schedules, API handlers | `platform/...`, `directory` via `directory.Services` (ADR-0003) |

`compose/server` hands `inventory.Datasets()` to `report.NewHost` with the owner key `inventory`.
`module.Boot` runs the dataset-table ownership check on those datasets and on any registered
through `Registrar.Dataset` (blueprint §4.1). The reports module **registers no dataset** at 2a:
it consumes them.

## 3. Report definition AST and dataset registry (EP-8)

### 3.1 Dataset

```go
// package report (internal/platform/report)

type DatasetID string   // "<owner>.<name>", e.g. "inventory.users"; ^[a-z][a-z0-9]{1,30}\.[a-z][a-z0-9_]{1,40}$
type ColumnID string    // ^[a-z][a-z0-9_]{0,62}$; stable, appears in the API, definitions and digests
type AnchorID string    // ^[a-z][a-z0-9_]{0,30}$; also the SQL alias of the anchor's relation

type Dataset struct {
    ID        DatasetID
    Base      Relation       // the FROM: one owned table plus a fixed row predicate; the base anchor "t"
    RowKey    Expr           // unique per row within a run: object GUID, or an edge key for edge datasets
    Anchors   []Anchor       // >= 1 RowAnchor. Every RowAnchor must be in scope for the row to exist (§4.3)
    Rels      []Rel          // every other relation a fragment may read, each through {rel.<id>} (§3.3)
    Columns   []Column
    Freshness FreshnessSource
    Tables    []string       // every table any anchor or rel names; Boot checks owners.gen.go (ADR-0003 rule 6)
}

type Relation struct {
    Table Ident              // e.g. Ident("directory_objects"); aliased "t" by the compiler
    Where Fragment           // fixed predicate, e.g. kind IN ('user','inetorgperson') AND state = 'live'
    Joins []RowJoin          // edge datasets: the endpoint objects, e.g. "grp" and "mbr" for group_members
}

// RowJoin joins a RowAnchor into the FROM. The compiler renders JOIN <table> AS "<anchor>" ON <On>
// and adds scope(<anchor>) to the WHERE. When the base table holds directory objects, "t" is
// itself a RowAnchor.
type RowJoin struct{ Anchor AnchorID; On Fragment }

// Anchor is a relation over a table whose rows are directory objects (they carry the scope
// columns). The compiler, never a fragment, decides what an anchor's rows show (§3.3, §4.3).
type Anchor struct {
    ID         AnchorID     // also the SQL alias; "t" when the base table holds directory objects
    Table      Ident        // directory_objects, or another table that carries the six scope columns
    Mode       AnchorMode   // RowAnchor | FilterAnchor | MaskAnchor (§3.3)
    Project    []Ident      // the columns the compiler's subselect exposes to fragments
    Identity   []Ident      // MaskAnchor only: columns exposed as NULL when the row is out of scope
    Connection Ident        // connection_id
    NC         Ident        // nc_guid
    Object     Ident        // object_guid
    Parent     Ident        // parent_guid
    Ancestry   Ident        // ancestry (uuid[], nearest parent first; GIN-indexed, row B3)
    Complete   Ident        // ancestry_complete (bool NOT NULL, row P2; §4.5)
}

type AnchorMode uint8 // RowAnchor (the row is visible only if in scope), FilterAnchor, MaskAnchor

// Rel is a relation that holds no directory-object identity of its own: an edge table (links,
// the group closure) or a policy-input table (D4). Its projection may hold only GUID, int, bool,
// time and enum columns, never text; NewRegistry refuses a text column.
type Rel struct {
    ID      AnchorID
    Kind    RelKind          // RelEdge | RelInput
    Table   Ident
    Project []Ident
    Where   Fragment         // fixed predicate (constant SQL, §3.3 slots allowed)
}

type Column struct {
    ID       ColumnID
    Label    string          // English at 2a; i18n keys arrive with the i18n spec
    Type     ValueType
    Enum     []EnumValue     // TypeEnum only: {ID, Label, SortRank}
    Source   ColumnSource    // exactly one of the four kinds below
    Filter   []Op            // the operators this column accepts; empty = not filterable
    Sortable bool
    Default  bool            // shown when a definition names no columns (definitions normally do)
    Count    bool            // Derived only: counts other objects (member, subtree counts); RP11 compares it
    UnknownWhen ColumnID     // Derived non-enum only: the state column whose unknown_input_missing makes this cell "u" (§3.3, §6.2)
}

type ValueType uint8 // TypeText, TypeInt, TypeBool, TypeTime, TypeEnum, TypeGUID, TypeTextList

type ColumnSource interface{ columnSource() } // sealed:
type Attr     struct{ Col Ident }                                // t."col"
type JSONAttr struct{ Col Ident; Key string; As ValueType }      // t."attributes" ->> $n (key bound, SQL-16)
type Derived  struct{ SQL Fragment }                             // §3.3: constant SQL with slots
type PerDC    struct{ Attr PerDCAttr; Agg PerDCAgg }             // §6.5: filled after the query, never SQL

type FreshnessSource uint8 // FreshNCWatermark | FreshPolicyRead | FreshPerDC
```

**Identifiers (P5 rule 3).** `Ident` is a string that `report` validates against
`^[a-z_][a-z0-9_]{0,62}$`. `report` does not quote it, because it cannot import pgx (FF-SP1).
**Pre-quoting happens once, at registry build**:
`reportsql.NewRegistry(ds ...report.Dataset) (*Registry, error)` runs `pgx.Identifier{name}.Sanitize()`
on every `Ident` and stores the quoted text inside an unexported `reportsql.Dataset`. `Compile`
only concatenates those pre-quoted strings, fixed keywords, and `$n` placeholders it numbers
itself. A column ID from a request or a definition is a **map key into the registry**, never text
in SQL (SQL-04, SQL-05: an unknown, quoted, case-varied or padded key is `ErrUnknownColumn`).

**Registry build refuses** (start-up fails, `compose/server` boot test):
- a fragment that contains the name of any table in `owners.gen.go` (tables enter only through
  `{rel.<id>}`, §3.3), or a `{rel.<id>}` the dataset does not declare;
- an anchor or rel whose `Project` names a column the table does not have (checked against the
  migration schema snapshot), or a `Rel` that projects a text column;
- a duplicate dataset or column ID;
- a column whose type does not fit its operators;
- a `JSONAttr` key in the secret-attribute set (D8, TM-TB15-T3; row B3 exports the predicate
  `inventory` already uses, `secretKey`);
- a `Fragment` that fails §3.3 validation;
- a dataset with no anchor, or a dataset that names a table its owner does not own.

### 3.2 Operators and values (closed vocabulary, P5 rule 13)

```go
type Op uint8      // OpEq, OpNe, OpLt, OpLe, OpGt, OpGe, OpIn, OpPresent, OpAbsent,
                   // OpContains, OpPrefix (text: LikePattern, P5 rule 4), OpWithinLastDays,
                   // OpOlderThanDays, OpWithinNextDays (time: compared with the bound now)
type SortDir uint8 // Asc, Desc; anything else is ErrBadSortDirection (SQL-06)
type Value struct{ /* unexported: one typed value; constructors TextV, IntV, BoolV, TimeV, EnumV, GUIDV */ }
```

- `OpIn` renders `= ANY($n)` with a typed array, capped at 1,000 values (`ErrTooManyValues`).
- Text values are refused when they contain NUL or invalid UTF-8 (SQL-10, SQL-11).
- `Enum` values are checked against the column's `EnumValue` IDs.
- Relative-time operators take whole days. A definition parameter can set a floor (§3.5), for
  example 30 days on replicated logon.

There is **no function, aggregate or grouping node at 2a**. Top N is a sort plus `Query.Top`. The
2c builder adds grouping with an amendment to this page, so the type never names something that
does not exist.

### 3.3 Derived columns and fragments (spec §6.4, FR-09)

Derived columns are where SQL that is more than an identifier is written. The rule that keeps it
safe:

- A `Fragment` is built only by `report.SQL(text)`, and `text` **must be a compile-time constant**.
  This is RP1, the FF-SP2 `sqlconst` amendment in T-0873, the same rule sqlc queries already obey.
  Fragments live in the dataset owner's package and are reviewed with it.
- A fragment may contain only constant SQL and these **slots**, which `reportsql` fills:
  - `{t}` is the base alias.
  - `{now}` is the run's single bound `now` (`$n`, `timestamptz`).
  - `{rel.<id>}` is a relation the dataset declared (an anchor other than `t`, or a `Rel`). The
    compiler expands it into a subselect it builds itself (below). **A fragment never names a
    table.**
  - `{in_scope.<anchor>}` (expands to `"<anchor>".in_scope`) is the boolean "this anchor's row is
    in scope", for `MaskAnchor`s only.
    Fragments use it to choose a label such as "(group outside your scope)".
- `NewRegistry` rejects a fragment that contains `;`, `--`, `/*`, `$`, an unknown slot or a table
  name, or whose parentheses are unbalanced.

**Every alias over a directory table is a declared anchor, scoped by the compiler.** A
fragment reads directory data only through `{rel.<id>}`, and the compiler builds that relation:

| Declared as | `{rel.<id>}` expands to | Used for |
| --- | --- | --- |
| `FilterAnchor` | `(SELECT <Project> FROM <table> WHERE <scope(alias)>) AS "<id>"` | counts and lists of other objects: GRP-01 member counts, OU-01 subtree counts, a member's groups. Out-of-scope rows do not exist for the fragment |
| `MaskAnchor` | `(SELECT <Project minus Identity>, CASE WHEN <scope> THEN <identity col> END AS <identity col>…, <scope> AS in_scope FROM <table>) AS "<id>"` | inputs that must be read whatever the scope, whose identity must not show: the PSO that sets a user's policy (`policy_source`), the `Via` hop of an effective membership |
| `RelEdge`, `RelInput` | `(SELECT <Project> FROM <table> WHERE <Rel.Where>) AS "<id>"` | links, closure edges, D4 policy values. No text columns (enforced), so no name can come from them |

`<scope(alias)>` is the full rendered scope of §4.3 over that alias, including the token layer
and the ancestry-complete requirement. So:
- `policy_source` shows the PSO's name only when the PSO is in scope, and "(policy outside your
  scope)" otherwise. The password state itself still uses the PSO's values: reading an in-scope
  user's expiry is the read being granted; the PSO's identity is not.
- A `Via` hop outside scope shows as "(group outside your scope)".
- Counts over a `FilterAnchor` count in-scope objects only (post-trim, LF-39).
- A count of an edge `Rel` alone, with no anchor joined, would count out-of-scope objects, and a
  GUID output straight from a `Rel` would name one. Review rule for dataset fragments: counts join
  a `FilterAnchor`; a GUID or name in a cell comes from a `RowAnchor` or a `MaskAnchor` identity
  column. RP11 catches a breach per dataset.

**Test RP11** (rows B3 and B6, listed by T-0873):
`Test_dataset_reveals_nothing_outside_scope`. For **every registered dataset** and every column:
1. Write an inventory through the inventory writer. One base object is in scope; every other
   object (members, groups, `Via` hops, PSOs, sibling and child OUs, contacts) is outside it and
   carries a sentinel name and GUID.
2. Run the dataset's full column set under a `ReadScope` whose single grant includes the base
   objects and excludes everything else.
3. Fail when any cell holds a sentinel name or GUID, or when any numeric aggregate column differs
   from the same aggregate computed with the out-of-scope objects deleted. Aggregate columns are
   those declared `Column.Count`.

**The derived columns of `inventory.users` (row B3).** Each one is evaluated in the query. Each
state column has a companion `<column>_reason` enum, which the UI shows on hover:

| Column | Type | Values / rule |
| --- | --- | --- |
| `locked_out` | enum | `locked`, `not_locked`, `not_applicable` (trust accounts), `unknown_input_missing`. The rule is spec §6.4: `lockoutTime ≠ 0` and (duration = until-unlock, or `{now}` < `lockoutTime` + duration) |
| `lockout_ends_at` | time | absent when not locked or the lockout lasts until an admin unlocks |
| `password_state` | enum | `not_applicable`, `never_account_flag`, `not_applicable_smartcard`, `must_change`, `never_policy`, `expired`, `expires`, `unknown_input_missing`, in the order of the spec §6.4 table |
| `password_expires_at`, `days_to_password_expiry` | time, int | absent unless the state is `expires` or `expired` |
| `account_expired` | enum | `expired`, `not_expired`, `never`, `unknown_input_missing` (`accountExpires` 0 or max means `never`, DM-16 codec) |
| `policy_source` | text | "Domain policy", the PSO's name when the PSO is in scope, or "(policy outside your scope)" (PSO read through a `MaskAnchor`, §3.3) |
| `probable_service_account`, `probable_service_account_reason` | bool, enum | spec §6.7 (SPN; or `DONT_EXPIRE_PASSWORD` plus the tenant pattern list) |
| `last_activity`, `activity_source` (`inventory.computers`) | time, enum | later of `lastLogonTimestamp` and `pwdLastSet`, with a fallback to `whenCreated` (spec §6.4 CMP-02) |

**Effective policy is resolved inside the query** from the D4 policy-input tables, which
`inventory` owns (row B3): the domain policy per NC, the PSOs and the PSO-applies-to links resolved
by precedence through a lateral join over `{rel.pso}` (a `MaskAnchor`) and `{rel.pso_applies}`
(a `RelEdge`). It is in the same snapshot as the user row. This meets
"resolved at run time from the synced policy objects" (spec §6.4, AC-14). Binding per-user policy
as arguments is not possible for PSOs. A PSO that cannot be resolved gives
`unknown_input_missing`, never a fallback to the domain policy.

**Unknown cells (FR-09; the API's `unknown` cell kind).** A derived value whose input is missing is
stored as the cell `["u"]` (§6.2), never as an inferred or absent value:
- A derived **state** column (`TypeEnum` whose `Enum` holds the reserved ID
  `unknown_input_missing`) is stored as `u` when its value is that ID. The enum value stays in
  `Enum`, so a filter `locked_out = unknown_input_missing` still works in SQL.
- A derived **non-enum** column that depends on a state names it in `Column.UnknownWhen`, and is
  stored as `u` when that state is `unknown_input_missing`. At 2a: `lockout_ends_at` →
  `locked_out`; `password_expires_at` and `days_to_password_expiry` → `password_state`. Absent
  still means "the rule gives no value" (not locked, or the state is not `expires` or `expired`).
- `NewRegistry` refuses an `UnknownWhen` that is not a `Derived` `TypeEnum` column of the same
  dataset holding `unknown_input_missing`, and an enum column that is not `Derived` but holds that ID.
- **The compiler never lets a filter infer.** When an `UnknownWhen` column is requested, it selects
  the state column as well. Every predicate on that column renders as
  `CASE WHEN <state> = 'unknown_input_missing' THEN NULL ELSE (<predicate>) END`, so an unknown row
  is selected by neither the predicate nor its negation (`OpNe`, `OpAbsent` included). RP8 covers the
  encoding and these filters.

**Test RP8** (row B3, listed by T-0873): `Test_derived_columns_match_reference`. It is a
table-driven test over the spec §6.4 rows. For every row, the column the compiled query returns
equals a pure-Go reference function `inventory.DeriveUserState(inputs, now)`. The Go function is a
**test oracle only**, and RP3 keeps it out of the run path.

### 3.4 Definitions, presets and the AST a run executes

```go
type DefinitionID string // "usr-01" … "ctc-01" (spec §6.2 IDs, lower case)

type Definition struct {            // shipped as JSON under internal/modules/reports/library/
    ID       DefinitionID
    Version  int                    // a change is a new file usr-01.v2.json; the old one stays (FR-03)
    Category Category               // Users, Passwords, Groups, Computers, Contacts, OUs
    Title, Description string
    Dataset  DatasetID
    Columns  []ColumnID             // default column set, in order
    Sort     []SortKey              // default sort (<= 4 keys)
    Presets  []Preset               // >= 1; Presets[0] is the default opened without Generate (FR-04)
    Params   []ParamSpec            // what a run may set (§3.5)
    PerDC    *PerDCSpec             // USR-04 and PWD-03 only (§6.5)
    Caveats  []CaveatID             // header texts such as "accurate to the sync interval"
}

type Preset struct {
    ID      string                  // "inactive", "enabled", …
    Names   []string                // the ME names it answers (FR-02 "Also known as")
    Where   Expr                    // nil = all rows
    Hidden  []HiddenGroup           // rows counted in the header, not stored (E2, CMP-02 gMSA/cluster)
    Columns []ColumnID              // nil = the definition's
    Sort    []SortKey
    Top     int                     // 0 = no top-N; GRP-01 "Top N Big Groups" = 25
    Requires *Subjects              // GRP-02, GRP-03: one or more group / user GUIDs required
}

type HiddenGroup struct{ ID string; Label string; Where Expr }

// Expr is a sealed tagged union. JSON: {"and":[…]}, {"or":[…]}, {"not":…},
// {"cmp":{"col":"status","op":"eq","value":{"enum":"enabled"}}}, {"param":"days"} as a value.
type Expr interface{ expr() }
type And struct{ Terms []Expr }    // <= 32 terms, depth <= 8
type Or  struct{ Terms []Expr }
type Not struct{ Term Expr }
type Cmp struct{ Column ColumnID; Op Op; Value Value; Param string }  // Value xor Param
type SortKey struct{ Column ColumnID; Dir SortDir }

// Query is the fully resolved AST one run executes. Only report.Resolve builds it.
type Query struct {
    Dataset    DatasetID
    Columns    []ColumnID   // 1..64, output order = export order = digest order
    Where      Expr         // SQL part: no PerDC column may appear
    PerDCWhere Expr         // per-DC part: only PerDC columns (§6.5)
    Hidden     []HiddenGroup
    Sort       []SortKey    // the compiler appends the row key as the final tie-break
    Top        int
    Narrowing  Narrowing    // what the admin picked; narrows only (§4.4)
    Subjects   []authz.ObjectID
}

func Resolve(def Definition, preset string, p RunParams, ds Dataset) (Query, error)
func (q Query) Hash() [32]byte  // canonical JSON → SHA-256; run reuse (§6.1) and the filters hash in audit
```

- **`RunParams`** is the decoded body of the run request (ADR-0004: the OpenAPI `ReportAst` and
  `RunParams` schemas generate it). Row B1 flips the pending `tools/gen/api` binding from
  `reportsql.Report` to `report.Query`. It carries:
  - the preset;
  - connections and OU include/exclude roots, each with depth `subtree` or `one_level`;
  - the period, as a preset of 7, 30, 90, 180 or 365 days, or a custom range;
  - extra column filters (`Cmp` only);
  - columns, sort, show-hidden group IDs and subjects.
- **`Resolve` refuses:**
  - a column that is not in the dataset;
  - an operator the column does not accept;
  - a missing required parameter (`Requires`);
  - a value below a parameter floor;
  - a `PerDC` column in `Where`, or a non-`PerDC` column in `PerDCWhere`;
  - more than 64 columns.

  Errors are `report.ValidationError{Code, Path}` and never echo values.

### 3.5 Parameters

`ParamSpec{Name, Kind (Days | GUIDList | Enum), Default, Min, Max, Required}`. The 30-day floor on
replicated-logon thresholds (spec §6.4) is `Min: 30` on USR-03's `days` parameter. A domain whose
`msDS-LogonTimeSyncInterval` is 0 is narrowed out of USR-03 by the run path and named in the header
(row B5, AC-16).

### 3.6 Library immutability (FR-03)

- Shipped definitions are embedded JSON files under `internal/modules/reports/library/`, one
  file per (ID, version).
- `library/LOCK` lists the SHA-256 of every shipped file. **RP7** (T-0873) fails when a listed file
  changes.
- A run records `definition_id`, `definition_version` and `definition_sha256`.
- The library loads at boot with strict decoding: unknown fields are refused, and every definition
  is `Resolve`d against its dataset with its default preset, so a broken definition stops
  start-up.

## 4. Scope: the `authz.ReadScope` input (EP-6, spec §8.1)

### 4.1 Who produces it today: nobody

Plainly: **no package produces a directory read-scope predicate today**. `modules/delegation` has
no scope evaluator. A per-object post-filter over candidates, with no callers, was the opposite of
"in the query"; T-0882 deleted it. Three tickets built the producer (split from T-0872 by T-0877):

| Ticket | Delivers | Unblocks |
| --- | --- | --- |
| **T-0880** | `authz.ReadScope` types (§4.2), `authztest.ReadScope`, EP-6 `ScopeEvaluator` host, `delegation` evaluators | B2 (compiler) |
| **T-0881** | the `ou_one_level` assignment root kind (migration, per-target `Authorize`) | T-0882 |
| **T-0882** | the producer `rbac.ReadScopes.For`, the read oracle `authz.Evaluator.AuthorizeRead` (§4.6), deletion of the old per-object post-filter | B4 (run path), T-0875 (search) |

### 4.2 The type (built in T-0880; the fields are fixed here)

*Landed (T-0880):* `internal/platform/authz/readscope.go` (types, `Fingerprint`), `authz/authztest`
(`ReadScope`, `ReadScopeWithToken`, `ReadScopeWithReasons`), `module.Registrar.ScopeEvaluator` with
`Contributions.ScopeEvaluator(kind)` and `ScopeKinds()` (one evaluator per root kind; Boot fails on a
duplicate and names the kind), and `modules/delegation/scope.go`, which registers `naming_context`,
`ou_subtree` and `ou_one_level`. `authz.ScopeEvaluator` is `RootKind() string` plus
`Term(connection, root ObjectID) (ScopeTerm, error)`; a zero connection or root is
`ErrInvalidObjectID`. `TermKind`'s zero value is unknown, so a forgotten kind never matches.
fitness-reports RP2 (`tools/fitness/reports`, type-aware) enforces that only `authz`, `rbac` and `authztest` call
`NewReadScope`. `ou_one_level` is evaluated here but not yet assignable: that is T-0881.

A read scope has **two layers**: the union of the account's grants, and an optional token layer
that is **AND-ed** with that union. This mirrors per-target `Authorize`, which checks
`tok.Scope.covers` separately from the assignments (`authz.go`). A token's narrowing can't be
merged into the grants: "(A ∪ B) ∩ T" is not a union of grants.

```go
// package authz
type ReadScope struct{ /* unexported: grants []ScopeGrant, token *TokenLayer, reasons []ScopeReason, summary string */ }
func (s ReadScope) Empty() bool                 // no grants, or a token layer with no include: grants nothing
func (s ReadScope) Terms() []ScopeGrant         // callers: reportsql and authz only (RP2)
func (s ReadScope) Token() (TokenLayer, bool)   // false = no token narrowing (a session, or a token with nil Scope)
func (s ReadScope) Reasons() []ScopeReason      // e.g. "scope_kind_unsupported:group_members"
func (s ReadScope) Summary() string             // human text for scope_applied
func (s ReadScope) Fingerprint() [32]byte       // SHA-256 of the canonical form of grants AND token layer (§6.1, §6.6)

type ScopeGrant struct{ Include, Exclude []ScopeTerm }  // one per assignment
type TokenLayer struct{ Include, Exclude []ScopeTerm }  // the token's DM-32 scope_narrowing; required when present
type ScopeTerm  struct{ Kind TermKind; Connection, Root ObjectID }
type TermKind uint8 // TermNamingContext, TermSubtree, TermOneLevel (2a); any other value is unknown

// package rbac: the only producer (RP2: NewReadScope callable only from rbac and authz)
func (r ReadScopes) For(ctx context.Context, tx store.Tx, t tenant.ID, chain authority.Chain,
    perm authz.Permission) (authz.ReadScope, error) // ErrOwnerDead for a disabled or deleted owner
```

- **Canonical form** for `Fingerprint`: grants sorted, terms sorted within each list by
  (kind, connection, root), the token layer encoded after the grants with a presence byte. Two
  scopes that grant the same rows by different routes may have different fingerprints. That only
  costs a re-run, never a leak.
- **Token layer.** A token's `Scope` roots carry no kind. `authz.Scope.covers` treats a root as
  "this object or any ancestor", which is `TermSubtree`. The producer resolves each root's
  connection from inventory. A root it cannot resolve, or a zero root, makes the layer grant
  nothing.
  - A token whose `Scope` is nil adds no layer.
  - A token with a non-nil empty `Scope` adds a layer with no include, so the scope is `Empty`.
  - A token that is expired, or does not list `perm`, gives `ErrTokenRefused` (the same reasons
    as `tokenOK`).

The producer's rules are in T-0882:
- grants from the account and its groups;
- the token as a separate layer (above), never merged into grants;
- excludes per assignment;
- an unknown kind contributes nothing, and the reason is recorded;
- an assignment with an exclude of unknown kind is dropped whole;
- correlation-derived (`Via`) grants contribute nothing at 2a;
- the tenant root contributes nothing to directory datasets;
- Tier-0 does not narrow reads (DM-35.I5).

### 4.3 How the compiler renders it

Every part is parenthesised, and every place where SQL could yield `NULL` is closed explicitly.
For an anchor `a`:

```
scope(a)   = COALESCE( ( a.complete ) AND ( G(a) ) [AND ( K(a) )] , false )

G(a)       = ( grant(a, g1) ) OR ( grant(a, g2) ) OR …               -- no grants: FALSE
grant(a,g) = ( inc(a, g.Include) ) [AND NOT ( exc(a, g.Exclude) )]   -- clause omitted when Exclude is empty
K(a)       = ( inc(a, k.Include) ) [AND NOT ( exc(a, k.Exclude) )]   -- token layer k, only when present
inc(a, L)  = ( COALESCE(term(a, l1), false) ) OR ( COALESCE(term(a, l2), false) ) OR …   -- empty L: FALSE
exc(a, L)  = ( COALESCE(term(a, l1), true) )  OR ( COALESCE(term(a, l2), true) )  OR …   -- unknown counts as excluded

term(a, NamingContext{c, r}) = ( a.connection = $c AND a.nc = $r )
term(a, Subtree{c, r})       = ( a.connection = $c AND ( a.object = $r OR a.ancestry @> ARRAY[$r]::uuid[] ) )
term(a, OneLevel{c, r})      = ( a.connection = $c AND a.parent = $r )      -- direct children only
```

- **2a kinds are exactly `naming_context`, `ou_subtree` and `ou_one_level`** (spec §8.1).
- **Fail closed, at every level.**
  - The zero or empty `ReadScope` compiles to `FALSE`. There is no "empty means everything"
    path in the scope renderer.
  - A term with a zero `Connection` or a zero `Root` is invalid. The compiler renders its whole
    grant `FALSE` (an exclude we cannot bind must never widen), or, in the token layer, the whole
    scope `FALSE`. Reason: `scope_term_invalid`.
  - An include term of an unknown `TermKind` renders `FALSE`. A grant with an exclude term of an
    unknown kind renders `FALSE` for the whole grant. In the token layer, an unknown kind anywhere
    renders the whole scope `FALSE`. Reason: `scope_term_unsupported:<kind>`.
  - The outer `COALESCE(…, false)` means a `NULL` column can't make a row visible, including
    inside a `CASE` in a fragment. Excludes treat `NULL` as excluded.
  - A row with `ancestry_complete = false` is out of scope (§4.5).
  - The run **succeeds with zero rows** when the scope renders `FALSE`. Its `scope_applied`
    carries `ReadScope.Reasons()` plus the compiler's reasons, and the empty state names the
    reason (AC-07).
- **Every `RowAnchor` must pass.** A row is visible only when `scope(a)` holds for each one. For
  `inventory.group_members`, a member row needs both `grp` and `mbr` in scope. `FilterAnchor`s and
  `MaskAnchor`s use the same `scope(a)` (§3.3).
- Root and connection GUIDs are bound `uuid` parameters. The number of terms is capped at 512. Above
  that, `ErrScopeTooLarge` fails the run with `scope_too_large`, never a partial scope.

### 4.4 Narrowing the admin picks (ADM-099)

`report.Narrowing{Connections []ObjectID; Include, Exclude []NarrowRoot{Connection, Root ObjectID, Depth}}`
narrows only. It is AND-ed with the scope, and it has **its own renderer**, `narrowing(t)`, which
shares the `term` function but not the scope's empty handling:

```
narrowing(t) = [ ( t.connection = ANY($conns) ) ]                      -- omitted when Connections is empty
               [ AND ( inc(t, Include) ) ]                              -- omitted when Include is empty
               [ AND NOT ( exc(t, Exclude) ) ]                          -- omitted when Exclude is empty
```

- An empty narrowing renders nothing: "default all permitted domains" means the scope alone
  decides. It never renders `TRUE` into the scope's position, and the scope renderer never
  renders an empty part as `TRUE`.
- A narrowing root with a zero GUID is a `report.ValidationError` (400), not a silently dropped
  clause.

### 4.5 Ancestry must be current: inventory requirement (row P2)

Terms trust the stored `ancestry`. Today the inventory writer upserts `ancestry` as given and never
rewrites descendants. When an OU moves, every object under it keeps its old chain. It stays under
an include it has left and misses an exclude it has entered. Per-target `Authorize` refuses a target
whose chain is not `Complete`; the SQL must refuse the same. So row **P2** (directory-engineer)
delivers:

1. **Descendant rewrite in the move transaction.** When the writer changes an object's
   `parent_guid` or `ancestry`, it rewrites, in the same transaction, the `ancestry` of every row
   with `ancestry @> ARRAY[<moved>]` in that connection. The rewrite is static SQL: the new prefix,
   then the old suffix after the moved object.
2. **`ancestry_complete bool NOT NULL DEFAULT false`** on `directory_objects`. It is true only
   when the row's parent is its NC head, or the parent row exists with `ancestry_complete = true`
   and the stored chain equals the parent's chain plus the parent. A child synced before its
   parent stays `false` until the parent arrives, and the writer then completes the waiting
   descendants in the same transaction.
3. **A term renders `FALSE` without it**: `scope(a)` requires `a.complete` (§4.3).
4. A test that moves an OU between an include and an exclude through the writer and checks every
   descendant's `ancestry` and `ancestry_complete`.

B2 (RP6 generates trees with moves) and B4 (first real run) depend on P2.

### 4.6 Fitness RP6: compiled scope equals the per-target decision

`Test_compiled_scope_matches_read_oracle` (row B2) is a property test. **The oracle is not new
code.** It is `authz.Evaluator.AuthorizeRead(p, tok, perm, target)` (built in T-0882): the existing
`Authorize` path, including `Scope.covers`, `tokenOK` and the separate `tok.Scope.covers` check,
with two differences. The Tier-0 deny is skipped, because Tier-0 does not narrow reads (DM-35.I5),
and `Via` grants contribute nothing. A target is built from the inventory row with
`Complete = ancestry_complete`.

- **Trees** are written through the inventory writer, never inserted directly. They include OU
  moves (into and out of includes and excludes), children synced before their parents, and objects
  in two connections.
- **Scopes** cover:
  - grants with several includes and several excludes;
  - several grants, where one grant excludes what another includes;
  - `ou_one_level`, `ou_subtree` and `naming_context` terms;
  - zero roots and unknown kinds in includes, excludes and the token layer;
  - a token layer that narrows, one that is empty, and none.
- **Datasets:** `inventory.users` (anchor `t`), and `inventory.group_members` with both anchors
  `grp` and `mbr`, so a row appears only when the oracle admits both.
- **Assertion:** the rows the compiled SQL returns equal the objects the oracle admits. A scope
  that renders `FALSE` yields zero rows and the expected reason.

### 4.7 Search consumes the same scope (T-0875, m2-plan decision 4)

`GET /directory/users` (`modules/directory`) trims to the caller's `ReadScope` for `directory.read`. The
design choice (directory-engineer): **push the include roots to the directory, then decide each result
in memory** rather than filter through inventory.

- **Producer.** `directory.ReadScopes` is a one-method port (`ReadScope(ctx, tenant, chain, perm)`); the
  composition root implements it over `rbac.ReadScopes.For` and a transaction (T-0916). The handler
  names the chain from the console session only: a token principal does not carry its token, so it is
  refused (403) rather than read with its owner's wider scope. No producer, `ErrOwnerDead`,
  `ErrTokenRefused`, `ErrUnsupportedChain` and `ErrDenied` are 403 and search nothing.
- **Roots.** `ReadScope.SearchRoots(connection)` gives the include roots of the grants that can admit
  anything (naming context and subtree become `SUBTREE`, one-level `ONE_LEVEL`). `client.UserSearch`
  sends them as the `ScopedSearch` roots, so the directory returns nothing outside every include. A
  scope with no roots in the connection answers empty without a directory call.
- **Decision.** Excludes, the token layer and chain completeness are not roots. `ReadScope.Admits(ObjectView)`
  decides each result from its live parent chain (the entry's `parent_guid`, then one container read per
  distinct parent per search, memoised, budget 2000 reads). Chains come from the directory, never from
  inventory ancestry, which is stale until P2. An incomplete chain, a loop, a vanished parent or a spent
  budget is not admitted. `Admits` is a second renderer of the terms (beside the SQL one) and lives in
  `authz`, the only package besides `reportsql` that may read `Terms`/`Token` (RP2); the rbac property test
  `Test_ReadScope_matches_read_oracle` holds it to `AuthorizeRead` for every object.
- **Counts after trimming (LF-39).** The 1,000-match cap and the limit count admitted users only; the
  response has no count and no truncation mark.
- **Known limits.** An OU root is sent with the forest root as `nc_guid` (a scope term carries no NC), so
  a child-domain OU root relies on the connector resolving the GUID on the bound DC. The token layer is
  applied after the query, not pushed into the roots, so a narrow token on a broad grant reads more
  candidates than it returns.

## 5. The compiler: `store/reportsql`

```go
// package reportsql (internal/platform/store/reportsql)

type CompiledSQL string                 // RP1: only this package may convert to it or build a Query
type Query struct {                     // unexported fields
    sql      CompiledSQL
    args     []any
    columns  []report.Column            // output layout: row key, columns…, hidden-group flags
    reasons  []string                   // compiler scope reasons (§4.3)
}
func (q Query) ScopeReasons() []string

type Inputs struct{ Now time.Time }     // bound once per run; the only time any column sees

func NewRegistry(ds ...report.Dataset) (*Registry, error)
func (r *Registry) Dataset(id report.DatasetID) (Dataset, bool)   // Dataset: pre-quoted, unexported fields

func Compile(q report.Query, ds Dataset, scope authz.ReadScope, in Inputs) (Query, error)
func CompileCount(q report.Query, ds Dataset, scope authz.ReadScope, in Inputs) (Query, error)

// Exec runs q as a server-side cursor inside tx (DECLARE … NO SCROLL CURSOR FOR <compiled>, then
// constant FETCH n). Between batches, fn may use tx: the run path inserts each batch into its own
// tables. One cursor = one snapshot, so every row and every hidden count come from the same data.
func Exec(ctx context.Context, tx store.Tx, q Query, batch int,
    fn func(ctx context.Context, rows []report.Row) error) (int64, error)
```

- **Shape of the compiled SQL.**
  `SELECT <rowkey>, <cols…>, <hidden flags…> FROM <base> t <row joins…> WHERE (<base.where>) AND (<scope(a)> for each RowAnchor a) [AND (<narrowing>)] [AND (<subjects>)] [AND (<Where>)] ORDER BY <sort…>, <rowkey> LIMIT $n`.
  Every operand of the top-level `AND` is parenthesised; optional operands are omitted when empty,
  never rendered as `TRUE`.
  - Hidden groups are **not** in the `WHERE`. They are output booleans, so the run counts them
    while streaming and stores only the rows not hidden (E2 "7 hidden · Show").
  - `LIMIT` is bound: `min(Top, cap + 1)`.
- `CompileCount` produces `SELECT count(*)` over the same `FROM` and `WHERE`. The run uses it only
  for the "this run would hold 1.4 million rows" message after the cap trips (§6.3), and the
  per-DC path uses it for its estimate. Totals shown to users are never `COUNT(*)` (ADR-0010
  rule 3).
- `Exec` sets nothing: `WithTenant` already set `app.tenant_id` and `statement_timeout` (P5 rule 11).
  The run job's `statement_timeout` is the `[PROPOSED]` 15 minutes; on expiry the run fails with
  `query_timeout` (SQL-22).
- **Errors** are typed and carry no SQL or values: `ErrUnknownColumn`, `ErrBadOperator`,
  `ErrBadSortDirection`, `ErrTooManyValues`, `ErrScopeTooLarge`, `ErrNulInText`,
  `ErrInvalidUTF8`, `ErrQueryTimeout`. A scope that renders `FALSE` is **not** an error: `Compile`
  succeeds and `Query.ScopeReasons()` names why.
- **Vectors.** SQL-01 to SQL-12, SQL-15, SQL-16, SQL-21 and SQL-22 run against `Compile` and `Exec`
  (row B2, FF-SP4).

## 6. Run record, run path and freshness (DM-72)

### 6.1 Creating a run

`POST /reports/runs` (operation in T-0866; permission `reports.run`) creates a run:

1. Resolve the `report.Query`.
2. Compute the caller's `ReadScope` for `reports.run` (`rbac.ReadScopes.For`, T-0882).
3. If a run with the same `runner_account`, `Query.Hash()` and `scope_fingerprint` (equal to this
   `ReadScope.Fingerprint()`) was created in the last **60 s** and is `queued`, `running` or
   `succeeded`, return that run (reuse window, ADR-0010). Reuse is a read, so it obeys §6.6; the
   key already makes it so.
4. Otherwise insert `report_runs` in state `queued` with `scope_fingerprint` set to this
   fingerprint, and enqueue the `reports.run` job, in one transaction.
5. Refuse with 429 `too_many_report_jobs` when the tenant already has 4 non-terminal runs and
   exports (spec §8.3). The count is taken under the tenant's advisory transaction lock.

Any change to the preset, filters, period, scope narrowing or columns is a new `Query.Hash()`,
hence a new run (FR-11).

### 6.2 Tables and Go types (owned by `reports`; RLS + `FORCE`, tenant-led keys; ADR-0002)

```
report_runs (DM-72)
  tenant_id, id uuid                                 PK (tenant_id, id)
  definition_id text, definition_version int, definition_sha256 bytea
  preset text, params jsonb (RunParams, typed), query_hash bytea
  scope_fingerprint bytea NOT NULL                   -- set at create; overwritten in T2 with the scope APPLIED (§6.3)
  runner_account uuid NOT NULL                       -- chain.Requester: the account whose authority the run uses
  chain jsonb NOT NULL                               -- the full authority.Chain (typed refs: token id, schedule id)
  schedule_id uuid NULL
  rerun_of uuid NULL                                 -- the run a retry or an expired-export re-run was made from (API rerunOf)
  state text NOT NULL CHECK (state IN run.State values)
  failure_reason text NULL CHECK (failure_reason IN run.FailureReason values)
  attempt int NOT NULL DEFAULT 0                     -- the job attempt that owns the run (§6.3)
  scope_applied jsonb   -- {summary, reasons[], narrowing summary}
  freshness jsonb       -- {label, per_nc[{connection, nc, last_pass_at, state}], computed_at}
  per_dc jsonb NULL     -- PerDcSummary{dcs_in_scope, dcs_answered, coverage, unreachable[{dc, error_code}]}
  as_of timestamptz NULL, row_count bigint NULL, hidden_counts jsonb NULL, digest bytea NULL
  columns jsonb         -- the stored column IDs in order (= export order = digest order)
  created_at, started_at, finished_at, expires_at timestamptz
  CHECK (state <> 'succeeded' OR (row_count, digest, as_of, expires_at) all NOT NULL)
  CHECK ((state IN ('failed')) = (failure_reason IS NOT NULL))
  trigger report_runs_state_edge: BEFORE UPDATE OF state, refuses any edge not in the table below
  INDEX (tenant_id, runner_account, created_at DESC, id DESC)   -- the history list (§6.6), keyset on (created_at, id)

report_run_rows (ADR-0010)
  tenant_id, run_id, row_key text (<= 200), ordinal bigint, cells jsonb, sort_keys jsonb
  PK (tenant_id, run_id, row_key); UNIQUE (tenant_id, run_id, ordinal) DEFERRABLE INITIALLY DEFERRED
  FK (tenant_id, run_id) → report_runs
  trigger: INSERT/UPDATE only while the run is 'running'; DELETE only when it is failed, cancelled or expired

report_exports (§7)  report_schedules, report_schedule_versions, report_schedule_recipients (§8)
```

```go
// package run (internal/modules/reports/run)
type State string
const (
    StateQueued    State = "queued"
    StateRunning   State = "running"
    StateSucceeded State = "succeeded"
    StateFailed    State = "failed"
    StateCancelled State = "cancelled"
    StateExpired   State = "expired"
)
func (s State) Terminal() bool          // succeeded, failed, cancelled, expired
func (s State) CanMoveTo(n State) bool  // exactly the edges below; the trigger enforces the same set

type FailureReason string
const (
    FailRunnerInactive        FailureReason = "runner_inactive"
    FailTokenRefused          FailureReason = "token_refused"
    FailRowCapExceeded        FailureReason = "row_cap_exceeded"
    FailPerDCReadCapExceeded  FailureReason = "per_dc_read_cap_exceeded"
    FailScopeTooLarge         FailureReason = "scope_too_large"
    FailQueryTimeout          FailureReason = "query_timeout"
    FailConnectionUnavailable FailureReason = "connection_unavailable" // per-DC only
    FailDefinitionRetired     FailureReason = "definition_retired"
    FailInterrupted           FailureReason = "interrupted"            // §6.3 rule 6
    FailInternal              FailureReason = "internal"
)
```

The UI and audit show the enum and its fixed text, never driver error text. A test in B4 asserts
that the Go constants and the two `CHECK` lists are the same sets.

**State transitions (every edge; anything else is refused by `CanMoveTo` and by the trigger):**

| From | To | When | Rows |
| --- | --- | --- | --- |
| `queued` | `running` | T1 of the run job | none yet |
| `queued` | `cancelled` | cancel before the job starts | none |
| `queued` | `failed` | T1 finds the definition retired (`definition_retired`) | none |
| `running` | `succeeded` | the final commit (§6.3 step 2.6, or §6.5 stage 4) | kept, read-only |
| `running` | `failed` | any `FailureReason`, including `interrupted` | deleted in the same transaction |
| `running` | `cancelled` | `jobs.Cancel` while running | deleted in the same transaction |
| `succeeded` | `expired` | `reports.retention`, at `expires_at` | deleted in batches after the flip |

- `failed`, `cancelled` and `expired` are final. **Failed and cancelled records do not become
  `expired`**: they hold no rows. Their `expires_at` is set like any other (`finished_at` + 7 days).
- `reports.retention` **deletes run records** in any final state 30 days after `expires_at`
  (`[PROPOSED]`). Until then the **record** stays readable (`GET /reports/runs/{id}`, §6.6): an
  expired run answers 200 with state `expired` and its header (`as_of`, row count, digest, scope
  applied), and a failed or cancelled run answers 200 with its state and reason. The **rows and
  files** are what is gone: a page read or file download of an expired run answers 410
  `report-result-expired`, and a page read of a failed or cancelled run answers 409 `run_failed`
  with the reason. Export create of an expired run re-runs instead (§7.1). After the record is
  deleted, every read answers 404. Audit events keep the run ID for ever.

**Cells (`report.Cell`).** `cells` is a JSON array in `columns` order. Each cell is
`[tag, value]`:

| Tag | Meaning | Value | API `ReportCell` kind |
| --- | --- | --- | --- |
| `"a"` | absent | none | `absent` |
| `"s"` | text | UTF-8 string | `text` |
| `"i"` | integer | decimal string, so 64-bit values stay exact | `integer` |
| `"b"` | boolean | `true` / `false` | `boolean` |
| `"t"` | time | RFC 3339 UTC, whole seconds | `time` |
| `"e"` | enum | the enum value's stable ID | `enum` |
| `"g"` | GUID | canonical lower-case string | `guid` |
| `"l"` | text list | array of strings | `textList` |
| `"n"` | never | none | `never` |
| `"u"` | unknown (input missing, FR-09; §3.3) | none | `unknown` |

The tags map one-to-one onto:
- the **canonical digest tags** of spec §8.3. Row B9 fixes the byte values. `u` has its own digest
  tag with length 0, distinct from `a` and `n`, so a run whose inputs were missing never has the
  digest of one where the value was absent;
- **`export.Cell`**: `"n"` maps to `export.Never()`, `"l"` to `export.Multi`, and `"u"` to
  `export.Unknown()`. Row B9 adds that constructor; it resolves to the fixed text
  `Unknown (input missing)`, as `Never()` resolves to `Never`;
- the **API `ReportCell` kinds** in the last column (`api/openapi/modules/reports.yaml`, T-0866).
  A test in B4 asserts the three sets are equal.

`u` has no sort key, like `a`, so unknown rows sort `NULLS LAST`. That is where
`unknown_input_missing` sits in every state enum's `SortRank` anyway.

**Sort keys.** `sort_keys` holds, for each sortable stored column, an order-preserving text:
- text is NFC and case-folded;
- an integer is sign-flipped and zero-padded to 20 digits;
- a time is fixed-width RFC 3339;
- an enum is its `SortRank`, zero-padded;
- an absent value has no key, so it sorts `NULLS LAST`.

`report.SortKey(c Cell, col Column) (string, bool)` is the one encoder.

### 6.3 The run job (`reports.run`, `jobs.ModeManagedTx`, timeout `[PROPOSED]` 30 min)

Every transaction below starts with `SELECT … FROM report_runs WHERE id = $1 FOR UPDATE` and
checks the state and `attempt` it expects. Two deliveries of the same job therefore serialise on the
run row, and the one that does not own the run changes nothing.

1. **T1:** lock the run. If it is `queued`, set `running`, `started_at` and `attempt` = this job
   attempt. If it is `cancelled`, stop. If it is `running`, apply rule 6.
2. **T2**, one `WithTenant` transaction holding the snapshot:
   1. `ReadScopes.For(runner chain, reports.run)`. `ErrOwnerDead` fails the run with
      `runner_inactive`; `ErrTokenRefused` fails it with `token_refused`.
   2. **Store the applied scope:** set `scope_fingerprint` to this `ReadScope.Fingerprint()`. This,
      not the create-time value, is what §6.6 compares against.
   3. Read the freshness watermarks (§6.4) **before** opening the cursor, so `as_of` never claims
      data newer than it read.
   4. `Compile`.
   5. `Exec` with batch size 2,000. Each batch is inserted with one static sqlc statement
      (`INSERT … SELECT * FROM unnest($1::text[], $2::bigint[], $3::jsonb[], $4::jsonb[])`). The
      job assigns `ordinal` in cursor order, counts the hidden groups, and feeds the digest from
      `platform/export` as rows stream.
   6. At `cap + 1` rows: roll back T2, run `CompileCount` for the message, and fail the run with
      `row_cap_exceeded {rows, cap}` (refuse and explain, FR-18).
   7. **Non-per-DC run:** in the same transaction, set `row_count`, `hidden_counts`, `digest`,
      `as_of`, `freshness`, `scope_applied`, `expires_at`, state `succeeded`, and append the audit
      event `reports.run.completed`. **One commit**, so a reader never sees a partial run.
3. **Per-DC run:** T2 commits the candidate rows with the run still `running`, and §6.5 continues.
4. **Cancel** (`jobs.Cancel`) or failure: a short transaction sets the terminal state and deletes
   the run's rows (the trigger allows that only in a terminal state).
5. **Failure reasons** are the `run.FailureReason` constants (§6.2).
6. **Interrupted runs.** A job delivery that finds its run already `running` (a retry after a
   crash, or a lease lost) does not resume it. Under the row lock it sets `failed` with
   `interrupted` and deletes any rows (per-DC candidates may exist), in one transaction, and
   appends `reports.run.failed`. The admin re-runs; a schedule fires again at its next tick. Because
   the run is never re-filled, a retry can't collide on `(run_id, row_key)`. If the first delivery
   is still alive inside T2, the second waits on the row lock and then finds `succeeded` (and
   stops) or `running` after a rollback (and fails it).

**Pages** are static sqlc queries over `report_run_rows` joined to `report_runs`
(`state = 'succeeded' AND expires_at > now()`). They run only after the §6.6 check. They order by
`ordinal`, or by `sort_keys->>@col COLLATE "C"` (two static variants, `ASC` and `DESC`, with
`NULLS LAST`), then by `ordinal`. Page size is ≤ 500, with a bound `LIMIT` and `OFFSET`. The total
is `report_runs.row_count` (ADR-0010 rule 3, FR-12). An expired run gives `ErrRunExpired` (410).

### 6.4 Freshness label (spec §8.2, D6, FR-08)

- **Source.** `inventory.Freshness` (row P1) returns
  `[]NCWatermark{Connection, NC, LastPassAt, State (ok | resync_required | paused | never_synced)}`.
  `LastPassAt` is the **last successful sync pass**, not `last_change_at`, so a quiet domain is not
  "Stale" (AC-09).
- **Covered NCs** are those of the connections the scope's terms and the narrowing reach.
- **The label** is computed by the pure function `report.Label(ws []NCWatermark, threshold, now) Freshness`:
  - `synced` when every covered NC is `ok` and within the threshold;
  - `stale` (naming the age and the connection) when any covered NC is older than the threshold,
    `resync_required` or `paused`;
  - `not_synced_yet` lists the connections skipped.
- **`as_of`** is the oldest `LastPassAt` among the covered NCs.
- **The threshold** belongs to `inventory`: `[PROPOSED]` 60 min, set by row P1 (spec Q6).
- **"Live" is never used.** Per-DC runs add `read_from {answered, in_scope, at}` (§6.5).

### 6.5 Per-DC reads (USR-04, PWD-03; spec §6.5, FR-10)

**Mechanism (spec Q2, decided here).** We read live: one `ReadPerDC` per candidate object. The
connector fans the read out over the domain's DCs (`read.proto`). We do not keep a stored per-DC
dataset refreshed by a sweep, because:
- the connector contract already bounds the fan-out (`max_concurrency`, a closed attribute enum);
- a sweep would read every user on every DC every day for two reports;
- the read cap of spec §6.5 is defined per object per DC, which a live read meets directly.

The port keeps this reversible:

```go
// package report
type PerDCReader interface {
    // Read returns, per object, one value per DC in scope and the coverage; it never sums.
    Read(ctx context.Context, conn authz.ObjectID, nc authz.ObjectID, objs []authz.ObjectID,
        attrs []PerDCAttr, scope PerDCScope) ([]PerDCObject, PerDcSummary, error)
}
```

Row P5 implements it over `directory/client`, through `directory.Services`. A stored-dataset
implementation could replace it later without touching the module.

**Stages:**
1. **Candidates.** T2 as in §6.3, with the run still `running`.
2. **Read cap.** `candidates × DCs in scope > 250,000` (`[PROPOSED]`) fails the run with
   `per_dc_read_cap_exceeded {candidates, dcs, cap}` **before any read** (AC-41).
3. **Reads.** These happen outside any transaction (ModeManagedTx, ADR-0005 rule 6), in batches
   of 200 objects. After each batch, a short transaction locks the run row, checks it is still
   `running` with this `attempt` (§6.3), and updates those rows' `PerDC` cells and sort keys by
   `row_key` (static SQL).
   - Under `PARTIAL` coverage the column label becomes "(at least)" and an empty maximum is
     `"Not confirmed"`, never "never" (AC-40).
   - `PerDCWhere` is evaluated over the per-DC cells by `report.EvalPerDC`. Rows that fail it are
     deleted in the same short transaction. This is the one predicate evaluated outside SQL, and it
     touches only values SQL cannot see. Scope trimming has already happened in SQL.
4. **Finalise** (one transaction):
   - if the sort uses a `PerDC` column, renumber `ordinal` with one static statement per
     direction;
   - stream the rows in `ordinal` order into the digest;
   - set `row_count`, `per_dc`, `as_of` (the read time) and `succeeded`.

Schedules of per-DC reports are floored at daily (§8, AC-38).

### 6.6 Who may read a run (run GET, pages, reuse, export create)

A stored run holds rows trimmed to one account's scope at one moment. Holding `reports.run` or
`reports.export` is not enough to read someone else's. `run.ReadAccess(ctx, tx, runID, chain)
(Run, error)` is the **one gate** every run read goes through: run GET, page GET, the reuse lookup
(§6.1) and export create (§7). It checks, in this order:

| # | Check | On failure |
| --- | --- | --- |
| 1 | The caller holds the operation's permission: `reports.run` for GET, pages and reuse; `reports.run` and `reports.export` for export create (route-level, before any run is looked up) | 403, as for any operation (FR-30) |
| 2 | The run exists in the tenant (RLS) **and** `runner_account = chain.Requester` | **404** `run_not_found` (it does not say that the run exists) |
| 3 | The run's rows still exist (not `expired`). **Pages only.** Run GET of an expired run answers 200 with the record and state `expired`, and export create re-runs instead (§7.1) | **410** `report-result-expired` |
| 4 | `rbac.ReadScopes.For(chain, reports.run).Fingerprint()` **equals** the stored `scope_fingerprint`, the scope applied in T2 | **409** `scope_changed_rerun`: the caller's scope (or token) differs from the one the rows were trimmed with |
| 5 | The run is `succeeded` (pages, export create) | 409 `run_not_ready` or `run_failed` with the reason |

- **Which checks each read runs**, as the contract declares them: run GET runs 1, 2 and 4. Pages
  run 1 to 5. Export create runs 1, 2, 4 and 5, and an expired run there starts a re-run rather
  than failing check 5. The creator's file download needs its route permission `reports.export`, runs 2
  and 4 on the export's run (§7.1), and answers 410 `report-result-expired` once the file has
  expired.
- Check 4 runs on every request, so a scope revoke or a narrower token stops reads at once, not 7
  days later. It costs one producer call per request; the result is not cached across requests.
- A token request carries the token layer in its fingerprint. A run created in a session is
  therefore not readable through a narrower token, and the reverse also holds. That costs a
  re-run, never a leak.
- **Expired run, export requested:** the handler creates a new run as the **caller**, with the
  caller's current scope, and the export follows that run.
- **Scheduled runs** have `runner_account` = the schedule owner. Only the owner can open them
  through the run API. Recipients get files only through §7.2.
- **`reports.schedule.manage_all`** shows schedule metadata (definition, preset, owner, recipients,
  state, last fire, last run state and row count). It never opens a run's rows or files.
- Every refusal at checks 2, 3 and 4 appends `reports.run.read_denied {run_id, check}` (§10).
- **History list** (`GET /reports/runs`, `listReportRuns`, T-0891) is not a run read, so it does not go
  through `run.ReadAccess`. It selects `WHERE runner_account = chain.Requester` ordered by
  `(created_at DESC, id DESC)` and takes no parameter that names another runner. It makes **one**
  `ReadScopes.For` call per request and sets each item's `scopeCurrent` to "fingerprint equals the
  stored one" (check 4 as data, not as a 409). Where it is false the item's `rowCount` is null. No
  refusal here, so no `read_denied` event.
- **Retry** (`POST /reports/runs/{id}/retry`, `retryReportRun`, T-0891) passes checks 1 and 2 only. It
  is not blocked by 3 or 4, which is its purpose. It resolves the stored `definition_id`, version,
  preset and `params` again under the caller's current scope, then takes the §6.1 create path
  (reuse window, job limit) with `rerun_of` = the source run. A source in `queued` or `running` is a 409
  `run_in_progress`.

**Test RP9** (row B4, listed by T-0873): `Test_run_read_bound_to_runner_and_scope`:
- a second account holding `reports.run` and `reports.export` gets 404 on GET, page and export
  create of the first account's run, by ID;
- the runner, after an assignment is narrowed or revoked, gets 409 on page and export create;
- the runner, through a token narrower than the session that created the run, gets 409;
- a `manage_all` holder gets schedule metadata and 404 on the schedule's runs;
- every refusal leaves a `reports.run.read_denied` event.

## 7. Export (spec §8.3, FR-16 to FR-22)

### 7.1 Creating and downloading an export

- **Request.** `POST /reports/runs/{id}/exports {format}` passes `run.ReadAccess` (§6.6) first:
  same runner, `reports.run` and `reports.export`, same scope fingerprint, run `succeeded`.
  - For an expired run, the handler creates a new run as the caller (§6.6). The export follows
    that run and says so: `ReportExport.rerun = true`, `runId` = the new run, `rerunOfRunId` = the
    expired one. Its file carries the new run's `as_of`.
  - The format's cap is checked against `row_count` **before** the job is enqueued. Above the cap
    the request is refused and explained (AC-24); at the cap it succeeds (AC-25).
- **Job.** `reports.export` (`ModeManagedTx`) streams `report_run_rows` in `ordinal` order through
  `export.RunToBlob`, with an adapter `run.StoredSource` (an `export.Source` and `export.Counter`).
  - The blob key is tenant-prefixed, and its expiry equals the run's.
  - **Export code never calls `reportsql`** (RP3; ADR-0010 rule 4).
- **About block.** XLSX gets a first sheet; PDF and HTML get a header. CSV carries none. The block
  is built from the run record only: report and preset, scope applied, filters, freshness, DC
  coverage, generated by and at, row count, **the run's stored digest**. The GRP-02 effective views
  add the evidence-pack summary (AC-27).
- **Digest.** Row B9 implements the canonical form of spec §8.3 **once**, in `platform/export`:
  `export.Digest(columns []string, rows iter.Seq[[]export.Typed]) [32]byte`, with test vectors. The
  run path computes it; export and API recompute it only in tests (RP5, AC-50).
- **`report_exports`:** `tenant_id, id, run_id, format, blob_key, size, file_sha256, created_by,
  state (pending|ready|failed|deleted|expired), expires_at`.
- **Download by the creator.** `GET /reports/exports/{export_id}/file` is authenticated. The
  export is looked up **by its ID** under RLS. The caller must be its `created_by`, and
  `run.ReadAccess` must pass for its run (§6.6), so a scope change stops downloads too. Otherwise
  404; after expiry 410. The creator can delete an export early. That is bookkeeping: an audit
  event, not an Action (ADR-0005 rule 10).
- **`blob_key` never leaves the server.** No URL, API response or mail carries it. Every download
  resolves the export ID to the row first, and only the row names the blob.
- Every download appends `reports.export.downloaded`; every refusal appends
  `reports.export.download_denied {export_id, check}`.

- **Encoders.** Bytes come only from the P7 encoders (FR-19, FF-SP10). PDF and HTML are row B10,
  and the UI offers only formats that exist (FR-16).

### 7.2 Delivery-link downloads: authorised by the DM-84 Delivery row

A link in a scheduled mail is `GET /reports/exports/{export_id}/file` as well, and the recipient
is not the export's creator (the schedule owner is). The recipient's right comes from **the
delivery, not from the schedule's current recipient list**:

1. At fire time (§8 step 5), for each account recipient with `link` delivery, `notify` writes one
   DM-84 Delivery row: `source_ref = (report_export, export_id)`, `recipient = (account,
   account_id)`. This is the record of who was sent what.
2. On download, when the caller is not `created_by`, the handler asks
   `notify.Deliveries.ForSource(ctx, tx, source, recipient) (Delivery, bool)` for a row with this
   export ID and the caller's account. The lookup runs under RLS in the caller's tenant.
3. It then re-checks that the caller **currently** holds `reports.export` (spec FR-24) and that the
   account is enabled.
4. It serves the stored owner-scope artefact byte for byte (AC-47). The recipient was sent the
   owner's view on purpose: §6.6 does not apply to the recipient, and the delivery row is the
   authority.
5. No delivery row, a row for another account, a missing permission, or a signed-out request: 404
   (401 when signed out), plus `reports.export.download_denied`. After expiry: 410.

Consequences:
- A recipient removed from the schedule after a fire can still open what that fire sent them, and
  nothing later.
- An account holding `reports.export` that was never sent the file gets 404, even with the export
  ID.

**Test RP10** (row B11, listed by T-0873): `Test_delivery_link_authorised_by_delivery_row`:
- the named recipient downloads, and the bytes equal the artefact;
- another account in the tenant holding `reports.export` gets 404;
- the recipient after losing `reports.export` gets 404;
- the recipient after removal from the schedule still gets the earlier fire's file;
- an export ID from another tenant gets 404;
- each refusal leaves `reports.export.download_denied`.

## 8. Schedules and delivery (spec §8.4, FR-23 to FR-29)

- **Tables.**
  - `report_schedules` (DM-73): definition, preset, `RunParams`, `schedule_id` (DM-44, owned by
    `platform/jobs`), `owner_account`, `notify_only_if_data`, `state` (`active | paused |
    archived`), `pause_reason`.
  - `report_schedule_versions`: the before-image used for undo.
  - `report_schedule_recipients`: an account or an address, formats, `attachment | link`.
- **Writes are Actions** (ADR-0005 rule 10): `reports.schedule.create | update | pause | resume |
  reassign | delete`.
  - Target `Store`, inline preview diff, gate, step-up per policy, audit, and undo to the previous
    version.
  - The external-recipient confirmation is part of the preview.
  - `Plan` refuses a per-DC report more often than daily (AC-38) and an interval below 1 hour.
  - `reassign` needs `reports.schedule.manage_all` and leaves the schedule paused.
- **Preview and undo over HTTP** (ADR-0004 rule 14, ADR-0005 rule 10 as amended by T-0892).
  - Each of the six writes has a preview twin under `…/previews/<verb>`. A plan refusal is a `200` with `outcome: refused` and the codes below. The external-recipient confirmation is `requiredConfirmations` of kind `external_recipients`, and the write carries it as `confirmedExternal`.
  - Every write answers `ActiveDIQ-Operation-Id`. The family's undo pair is `POST /reports/schedules/operations/{operationId}/undo` and `…/previews/undo`, bound to `reports.schedule`.
  - Every inverse is **`reports.schedule.restore`** `{scheduleId, version}`. It is planned for the principal undoing, and is refused as `superseded` when the schedule's current version is not the one the operation wrote:

    | Undo of | Restores | Class | Checks for the undoing principal (blocked code) |
    | --- | --- | --- | --- |
    | `create` | archives the schedule ("Schedule removed. Nothing was sent." when it has not fired) | `Reversible` | owner, or `manage_all` |
    | `update` | the previous version | `Reversible` | the checks of `update` for the restored content: `reports.deliver.external` and the confirmation for every external recipient it restores (`external_not_permitted`), and the scope refusals when the result is active (`report_scope_empty`, `report_scope_unsupported`) |
    | `delete` | the schedule as it was, active or paused | `Reversible` | as for `update`, over the whole restored version |
    | `pause` | active | `Reversible` | only the owner, as for `resume` (`owner_only`), plus the scope refusals |
    | `resume` | paused | `Reversible` | owner, or `manage_all` |
    | `reassign` | the previous owner, **still paused** | `Lossy`: the earlier active state is not restored, and the previous owner resumes it | `reports.schedule.manage_all` (`manage_all_required`) |

  - An undo never sends anything. A fire that ran between the change and its undo stays sent and is not recalled.
- **Fire.** A DM-44 tick enqueues `reports.schedule.fire`, which runs the owner-authority checks
  of spec §8.4 in order:
  1. Owner state and permissions. A failure gives a system pause plus `reports.schedule.paused`
     with the reason, notifies the tenant owners, and sends nothing.
  2. Create a run with the runner set to the owner. The owner's `ReadScope` is computed now, so a
     shrunk scope applies (AC-30).
  3. Export each format the recipients need.
  4. Re-evaluate every recipient against the current allowed domains and the owner's current
     `reports.deliver.external`. A failing recipient fails alone, with its reason (AC-33, AC-46).
  5. Hand one DM-84 Delivery per recipient to `notify`. For a link, the Delivery row carries the
     export ID as `source_ref` and the recipient account (§7.2).
- **Delivery.**
  - A ZIP is built when there are several attachments.
  - "Notify only if data" with zero rows sends nothing and records "ran, nothing to send".
  - A **link** serves the stored owner-scope artefact, byte for byte, to the named recipient
    account only, signed in and holding `reports.export` (AC-47). It is authorised against the
    DM-84 Delivery row written at fire time (§7.2).
  - Attachments above the size limit (`[PROPOSED]` 10 MB) go as a link to account recipients and
    fail for external ones.
- **Allowed recipient domains (spec Q3, decided here).** This is a tenant setting owned by
  `platform/notify` beside the SMTP settings (row P3), changed by a `notify.settings.update`
  Action. Any later mail sender reuses it. Reports only read it.

## 9. Fitness functions

The job is `fitness-reports` (`tools/fitness/reports`, **T-0873**), plus the FF-SP2 amendment.
Every check has a failing fixture.

| ID | Kind | Fails when | Enforces |
| --- | --- | --- | --- |
| RP1 | static (FF-SP2 `sqlconst`) | a conversion to `reportsql.CompiledSQL`, or a composite literal of `reportsql.Query`, appears outside `store/reportsql`; or `report.SQL` is called with a non-constant argument | P5 rule 3; §3.3 |
| RP2 | static | `(authz.ReadScope).Terms` or `.Token` is called outside `authz` and `store/reportsql`, or `authz.NewReadScope` outside `rbac` and `authz` (non-test files) | one producer, one renderer (§4) |
| RP3 | static | under `internal/modules/reports/**`, a package other than `…/reports/run` calls `reportsql.Compile`, `CompileCount` or `Exec` | ADR-0010 rule 4 |
| RP4 | test (B4) | `Test_expired_run_is_not_served`; also: the row trigger refuses an insert or update once the run is `succeeded`, and the state trigger refuses every edge not in §6.2 | ADR-0010 rules 2 and 5; §6.2 |
| RP5 | test (B9) | `Test_export_digest_equals_run_digest` | ADR-0010 rule 4, AC-50 |
| RP6 | test (B2) | `Test_compiled_scope_matches_read_oracle` (property; oracle `authz.Evaluator.AuthorizeRead`, trees through the inventory writer with OU moves; §4.6) | FR-07, spec §8.1, LF-39 |
| RP7 | static | a file listed in `library/LOCK` changed | FR-03 |
| RP8 | test (B3) | `Test_derived_columns_match_reference` | FR-09, AC-49 |
| RP9 | test (B4) | `Test_run_read_bound_to_runner_and_scope` (§6.6) | §6.6; FR-07, FR-30 |
| RP10 | test (B11) | `Test_delivery_link_authorised_by_delivery_row` (§7.2) | FR-24, AC-47 |
| RP11 | test (B3, B6) | `Test_dataset_reveals_nothing_outside_scope`, run for every registered dataset (§3.3) | LF-39, FR-07 |

FF-SP4 (report-AST vectors) and FF-SP10 (output structure) already exist in safe-primitives §8, and
`fitness-tenancy` covers RLS on the new tables.

**Note for T-0873:** RP1 also covers the constant-only `report.SQL`; RP2 also covers
`ReadScope.Token`. The job lists the test names of RP4, RP5, RP6, RP8, RP9, RP10 and RP11 and fails
when one is missing or skipped. RP11 must run once per dataset that `report.Host` registers, so
the job compares the dataset list with the test's subtests.

**As built (T-0873, runbook `reports-fitness.md`):** RP1 lives in the `sqlconst` analyzer and also
rejects the address of a `CompiledSQL` (an unmarshal target). RP2 also allows `authz/authztest`
(the test double must call `NewReadScope`) and fails non-test code that imports it. `library/LOCK`
is `sha256sum` format, covers every `*.json` under `library/`, and is append-only against the base
ref. The dataset list is every `report.Dataset` literal in non-test code, whose `ID` must be a
string constant; the RP11 subtest for a dataset is named by that ID. A check whose code has not
landed prints `pending`; the owning build ticket flips `Landed` in `tools/fitness/reports/bindings.go`.

## 10. Contributions (what `Register` registers)

| Kind | ID | Notes |
| --- | --- | --- |
| API (EP-2) | tag `reports` | `api/openapi/reports.yaml`, T-0866 |
| Action (EP-3) | `reports.schedule.create`, `.update`, `.pause`, `.resume`, `.reassign`, `.delete` | `Target: Store`; undo restores the previous version |
| Permission (EP-6) | `reports.run`, `reports.export`, `reports.schedule`, `reports.schedule.manage_all`, `reports.deliver.external` | spec §8.5; reads apply over the directory scope kinds of §4 |
| AuditKind (EP-7) | `reports.run.completed`, `reports.run.failed`, `reports.run.read_denied`, `reports.export.created`, `.downloaded`, `.download_denied`, `.expired`, `.deleted`, `reports.schedule.*` (the Actions), `reports.schedule.paused` (system), `reports.schedule.fired`, `reports.delivery.sent`, `reports.delivery.failed` | see below |
| Dataset (EP-8) | none | consumes `inventory.*` |
| Job (EP-5) | `reports.run`, `reports.export`, `reports.schedule.fire`, `reports.retention` (daily per tenant) | all tenant-carrying |

**What every reports audit event records** (FR-22):
- the **full initiator chain** (`authority.Chain`): the requester, then every principal acted
  through, with typed references. A token request records the token ID. A scheduled run records
  the schedule ID, with the owner as the requester. The recorder writes this as on-behalf-of: the
  schedule or token acted on behalf of the account;
- the report ID and version, the preset, the scope summary and `scope_fingerprint`,
  `Query.Hash()`, the row count and the digest, as applicable;
- for `read_denied` and `download_denied`: the run or export ID, the operation (run GET, page,
  export create, download) and the failed check from §6.6 or §7.2;
- never cell values, filter values or file contents.

## 11. Retention

- Runs, rows and exports expire 7 days after `finished_at`. This is fixed at 2a (`[PROPOSED]`).
- `reports.retention`:
  - flips runs past `expires_at` to `expired`;
  - deletes their rows in batches of 10,000;
  - marks their exports `expired`.
- `blob.Sweep` removes the expired artefact blobs.
- The tenant setting of 1 to 30 days (spec §8.1) is row B15, after 2a.

## 12. Build-ticket breakdown (for the project-manager, T-0869)

**P rows** are prerequisites outside the reports module that are missing from the board. File them
with the same owners. Existing tickets are named by ID. "AC" means reports-2a §14.

| Row | Title | Owner | Depends on | Spec FRs / ACs consumed |
| --- | --- | --- | --- | --- |
| T-0880 | `authz.ReadScope` types with the token layer and `Fingerprint` (§4.2), `authztest.ReadScope`, EP-6 `ScopeEvaluator` host, `delegation` evaluators (filed) | backend-engineer | — | FR-07; AC-06 |
| T-0881 | `ou_one_level` assignment root kind: migration and per-target `Authorize` (filed) | backend-engineer | — | FR-07; AC-06 |
| T-0882 | `rbac.ReadScopes.For` producer, read oracle `authz.Evaluator.AuthorizeRead` (§4.6), delete the old per-object post-filter (done) | backend-engineer | T-0880, T-0881 | FR-07; AC-06, AC-07 |
| T-0873 | `fitness-reports` RP1 to RP11 and the FF-SP2 amendment (filed) | devops-engineer | B1, B2 stubs | FR-03, FR-05, FR-19 (guards) |
| T-0866 | OpenAPI contract for the 2a report operations (exists) | api-engineer | this page | FR-31; AC-43 |
| P1 | inventory: per-NC sync passes and the **last-successful-pass watermark** (D6); `inventory.Freshness`; staleness threshold | directory-engineer | — | FR-08; AC-09, AC-10, AC-11 |
| P2 | inventory: rewrite descendants' `ancestry` in the move transaction; `ancestry_complete` column, set and repaired by the writer; move test (§4.5) | directory-engineer | — | FR-07; AC-06 |
| P3 | `platform/notify`: SMTP delivery through egress, DM-84 Delivery with per-recipient state and retries, `source_ref` and account `recipient` for links, `Deliveries.ForSource` lookup (§7.2), allowed-recipient-domains setting (`notify.settings.update` Action) | backend-engineer | EP-3 (exists) | FR-24, FR-27; AC-36, AC-47 |
| P4 | `platform/jobs`: DM-44 Schedule (recurrence, IANA zone, DST skip and repeat, missed run fires once, 1 h floor) | backend-engineer | — | FR-23, FR-28; AC-37 |
| P5 | `directory/client.ReadPerDC` plus `report.PerDCReader` implementation (bounded concurrency, coverage) | directory-engineer | B1; live connector reads (fleet tunnel mount) | FR-10; AC-39, AC-40 |
| **B1** | `platform/report`: EP-8 host (`Dataset`, `Column`, `Fragment`, `Definition`, `Query`, `Resolve`, `Cell` with the `u` tag, `Column.UnknownWhen`, `SortKey`, `Label`, `PerDCReader`), `Registrar.Dataset`, Boot table-ownership check, `Deps.Report`, flip the `ReportAst` gen binding | reporting-engineer | — | FR-03 (version fields), FR-05; AC-05 |
| **B2** | `store/reportsql`: `NewRegistry` (pre-quoting, table-name and rel checks), `Compile`, `CompileCount`, `Exec` (cursor), anchor and rel expansion (§3.3), the `UnknownWhen` checks and filter guard (§3.3), scope with token layer and narrowing rendering (§4.3, §4.4), SQL vectors, **RP6** | reporting-engineer (security-architect reviews) | B1, T-0880; RP6 also needs T-0882 (oracle) and P2 | FR-05, FR-07, FR-12; AC-05, AC-06, AC-07 |
| **B3** | inventory: `inventory.users` and `inventory.computers` datasets, D4 policy-input tables and sync, D7 inputs, GIN index on `ancestry`, derived-state fragments, PSO `MaskAnchor` for `policy_source`, service-account signal, secret-key refusal, **RP8**, **RP11** for its datasets | directory-engineer (ad-expert consult) | B1, B2, P2 | FR-09, FR-14, FR-21; AC-12, AC-13, AC-14, AC-15, AC-29, AC-49 |
| **B4** | `modules/reports` run path: module skeleton and page, `report_runs`/`report_run_rows` migrations and both triggers, `run.State`/`run.FailureReason`, `reports.run` job with row lock, `attempt` and interrupted rule, reuse window, concurrency cap, `run.ReadAccess` (§6.6), page queries, freshness label, permissions, run audit kinds with the full chain, retention job, run API handlers, **RP4**, **RP9** | reporting-engineer (backend-engineer reviews) | B1, B2, T-0882, P1, P2, T-0866 | FR-06, FR-07, FR-08, FR-11, FR-12, FR-13 (server-side sort and filter), FR-22 (run), FR-30, FR-31; AC-06–AC-11, AC-42, AC-48 |
| **B5** | Library batch 1: loader, `LOCK`, crosswalk search index, USR-01, USR-02, USR-03, USR-05 with presets and hidden groups, sync-interval-0 narrowing | reporting-engineer | B3, B4 | FR-01, FR-02, FR-03, FR-04, FR-06, FR-09, FR-14; AC-01–AC-04, AC-12, AC-16, AC-17, AC-18, AC-49 |
| **B6** | inventory: `inventory.groups`, `.group_members` (`grp` and `mbr` row anchors, primary-group edges, effective closure, cycle findings, FSP rows, `Via` hop as `MaskAnchor`), `.ous` (in-scope subtree counts over a `FilterAnchor`), `.contacts`, **RP11** for its datasets | directory-engineer | B1, B2, P2 | FR-15, FR-06; AC-19, AC-20, AC-21 |
| **B7** | Library batch 2: PWD-01, PWD-02, GRP-01–GRP-04, CMP-01, CMP-02, OU-01, CTC-01 | reporting-engineer | B5, B6 | FR-01, FR-02, FR-09, FR-14, FR-15; AC-13, AC-19, AC-20, AC-22, AC-23 |
| **B8** | Per-DC runs: the §6.5 stages, read cap, coverage labels, `EvalPerDC`; USR-04, PWD-03 | reporting-engineer | B4, B5, P5 | FR-10; AC-39, AC-40, AC-41 |
| **B9** | Export: `export.Digest` (canonical form and vectors, `u` tag included), `export.Unknown()`, `run.StoredSource`, About block, CSV and XLSX export jobs, `report_exports`, creator download through `run.ReadAccess` (§7.1), 410, delete, caps, export audit kinds, **RP5** | reporting-engineer | B4 | FR-16, FR-17, FR-18, FR-19, FR-20, FR-21, FR-22 (export), FR-31; AC-24–AC-28, AC-50 |
| **B10** | PDF and HTML encoders and export formats (before M2 exit) | reporting-engineer | B9 | FR-16, FR-19 |
| **B11** | Schedules: DM-73 tables, `reports.schedule.*` Actions, fire job, owner-authority checks, delivery links authorised by the Delivery row (§7.2), ZIP, notify-only-if-data, `manage_all` metadata view, delivery audit kinds, **RP10** | reporting-engineer (backend-engineer reviews) | B4, B9, P3, P4 | FR-22 (delivery), FR-23–FR-29, FR-31; AC-30–AC-38, AC-45, AC-46, AC-47 |
| **B12** | Screens: library and `/` search, run and results grid (sort, column filters, column chooser, row count, freshness, coverage, hidden-group banner), export dialog, schedule sheet; empty, error, stale and loading states | frontend-engineer | T-0866, T-0867, B4 (then B9, B11 per screen) | FR-01, FR-02, FR-04, FR-13, FR-32; AC-44 |
| **B13** | Scale-tier calibration: row caps, sort p95 on 1M rows (ADR-0010 budget), per-DC read cap, report accuracy | test-engineer | B7, B8, B9 | FR-12, FR-18; AC-21, AC-22, AC-23, AC-39 |
| **B14** | ADR-0010 to `accepted`: confirm RP3–RP5 are green in CI and update the ADR status | solution-architect | T-0873, B4, B9 | none (ADR ladder) |
| **B15** | (after 2a) Report retention tenant setting, 1–30 days, as a configuration Action | reporting-engineer | B4 | spec §8.1 retention |

**Coverage check:** every FR-01 to FR-32 appears in at least one row above.

**Sequencing.** Do not run two tickets on the same package in parallel:
- B1, then B2 (B3 and B6 can run in parallel with each other);
- B2 needs T-0880 to start; RP6 inside B2 needs T-0882 and P2;
- B4 needs P1, P2 and T-0882;
- B5, B7 and B8 run in order;
- B9 can run in parallel with B5;
- B11 is last of the server rows.

## 13. Open items

None for a 2a ticket. Calibration numbers marked `[PROPOSED]` (caps, timeouts, the 60-minute
threshold, the 10 MB limit) are confirmed by row B13, and the defaults apply until then.

## 14. Decisions made on this page

1. **Live per-DC reads** behind `report.PerDCReader` (spec Q2). These are reversible behind the
   port.
2. **Allowed recipient domains** are a `platform/notify` tenant setting (spec Q3).
3. **Effective password and lockout policy is resolved in the query** from the D4 tables (spec
   §6.4). This refines "policy bound as arguments", which cannot express PSOs.
4. **Edge rows need every row anchor in scope, and every other directory relation is a
   compiler-scoped anchor** (filter or mask, §3.3). Counts, `Via` labels and PSO names count and
   name only in-scope objects; RP11 checks every dataset.
5. **Hidden groups are counted, not stored.** "Show" starts a new run.
6. **A read scope has a separate token layer** AND-ed with the grant union, as per-target
   `Authorize` already does (§4.2).
7. **Scope rendering is fail-closed by construction**: parenthesised, `COALESCE` on every term
   and on the whole scope, `NULL` excludes count as excluded, zero roots and incomplete ancestry
   render `FALSE`, and narrowing has its own renderer (§4.3–§4.5).
8. **Run reads are bound to the runner and the applied scope fingerprint**; delivery links are
   bound to the DM-84 Delivery row (§6.6, §7.2).
9. **A run found `running` by a job retry is failed `interrupted`**, never resumed (§6.3).
10. **Result storage** is rows in PostgreSQL ([ADR-0010](../../decisions/0010-report-results-stored-as-rows-in-postgres.md),
   `proposed`).
11. **Unknown is its own cell, never absent or inferred** (`"u"`, §6.2). State enums keep
   `unknown_input_missing` for filtering, and dependent columns name their state in `UnknownWhen`, so
   one stored shape, one digest tag and one API kind say "input missing" (§3.3).

## Changelog

- 2026-10-30 · T-0865 · created as the build contract ahead of the module.
- 2026-10-30 · T-0865 rework (review M1–M9): run-read gate and RP9 (§6.6); token layer in
  `ReadScope` (§4.2); parenthesised, fail-closed scope rendering and separate narrowing renderer
  (§4.3, §4.4); ancestry rewrite and `ancestry_complete` (§4.5, row P2); filter and mask anchors
  and RP11 (§3.3); delivery-row authorisation and RP10 (§7.2); RP6 oracle `AuthorizeRead` (§4.6);
  `run.State`, `run.FailureReason`, transitions and the interrupted rule (§6.2, §6.3); T-0872
  replaced by T-0880, T-0881, T-0882; audit records the full chain and denied reads (§10).
- 2026-10-30 · T-0894 · aligned with the T-0866 OpenAPI contract: `report.Cell` gains `"u"`
  (unknown, FR-09) with its own digest tag, `export.Unknown()` and an API-kind column (§6.2);
  `Column.UnknownWhen` and the no-inference filter guard (§3.1, §3.3); an expired run's record stays
  readable (200, state `expired`) while pages and downloads answer 410 `report-result-expired`
  (§6.2, §6.6 check 3 and the per-read check list); export re-run fields `rerun`/`rerunOfRunId` (§7.1);
  rows B1, B2, B9.
- 2026-10-30 · T-0956 · row B1 built: `internal/platform/report` (types, `Resolve`, strict `DecodeRunParams`,
  `Cell` with the `u` tag, `Label`, `PerDCReader` port, `Host`, `CheckTables`), `Registrar.Dataset`,
  `module.WithTableOwners`, `platform.Deps.Report`, `compose/server.bootReport`; the `ReportAst` gen
  binding now points at `report.Query`. As built, against §3:
  - `Cmp` carries `Values []Value` for `OpIn`; `RunParams.Filters` takes any `Expr` (wire filters
    have groups); there is no `Period` field (the API adapter maps it to the `days` Param).
  - `DecodeRunParams(data, def)` returns `(RunParams, preset, error)` and refuses an undeclared name
    before reading its value (`unknown_parameter`).
  - Per-DC terms are split from top-level conjuncts; a mixed term is `per_dc_misplaced`.
  - `report.SortKey` is the type; the page sort-key encoder is `CellSortKey`, built in B4.
  - Fragment validation rejects `;`, `--`, `/*`, `$`, `\`, quoted identifiers, unknown slots and
    unbalanced parentheses. The check that a fragment names no table is B2 (needs the ownership map).
  - `store/owners.Lookup` is an **empty** map: no generator exists yet, so any dataset fails Boot
    (fail closed, ADR-0003 rule 6). A `tools/gen/modules` ticket fills it; B3 needs it.
