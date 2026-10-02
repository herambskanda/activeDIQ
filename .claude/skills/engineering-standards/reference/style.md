# Language style — provisional until ADR-0001

Formatters and linters decide style; humans and agents do not argue about it. Everything here is
enforced in CI where a tool can enforce it.

## Go (backend, connectors, CLI)

- `gofmt`/`goimports`; `golangci-lint` with at least `govet staticcheck errcheck gosec revive
  errorlint bodyclose sqlclosecheck` and a `depguard` rule: only the connector root
  `internal/connector/` may import the raw LDAP and Graph libraries; only `internal/platform/store`
  (plus sqlc-generated `sqlcdb/` packages) may import the SQL driver (blueprint §2, FF-SP1).
- `context.Context` is the first parameter of anything that does I/O; honour cancellation.
- Errors: `fmt.Errorf("reset password for %s: %w", guid, err)` for **messages only** — never to
  build LDAP, SQL, shell, PowerShell or SDDL values. Sentinel or typed errors for anything a caller
  branches on; `errors.Is/As`, never string matching.
- No mutable package-level state (PatchIQ NC3: a raced global JWT key). Dependencies are passed in.
- Concurrency: every goroutine has an owner and a stop path; `go test -race` in CI.
- Database: parameterised queries only (generated with `sqlc` or `pgx` placeholders); tenant
  context via `set_config($1, true)` inside the transaction.
- Tests: table-driven; `t.Parallel()` where safe; native fuzzing (`go test -fuzz`) for every
  parser, encoder and builder.
- Package names short, lower-case, no `util`/`common`/`helpers`. Name packages by what they
  provide (`ldapfilter`, `dn`, `audit`).

## TypeScript / React (web)

- `strict: true`, `noUncheckedIndexedAccess: true`; no `any` (use `unknown` + narrowing); ESLint
  + Prettier; no `// @ts-ignore` without a linked ticket.
- **Server state through the generated API client and TanStack Query only.** No hand-written
  `fetch` to undocumented endpoints; no data constants in `src/` — fixtures live in tests,
  Storybook stories and the demo seed only.
- Components from the design system (`design-system` skill); tokens from
  `web/src/ds/tokens.css` (`--diq-*`, activeDIQ's own; never skenzeriq's), never raw colours or pixel values.
- Every data view handles loading, empty, error and partial (some DCs unreachable) states.
- Tables over large directories are virtualised and server-paged; never load 50k rows.
- No `dangerouslySetInnerHTML`; user and directory strings are text, always.
- Dates displayed in the admin's time zone with the UTC instant in a tooltip.

## SQL (PostgreSQL)

- Migrations: `NNNN_short_description.sql`, forward-only, idempotent guards where possible.
- Every domain table: primary key, `created_at`, `updated_at`, and the tenant key if multi-tenant.
- Directory objects keyed by `(directory_id, object_guid)`, never by DN.
- Indexes justified by a query in the same change; `EXPLAIN` on the 50k fixture for list queries.

## PowerShell and Windows-native (windows-engineer)

- PowerShell is invoked with arguments, never with script text built from input. Data crosses
  the boundary as JSON via stdin or `-EncodedCommand` of a **fixed** script; parameters are bound,
  not interpolated.
- Code running in LSASS (password filter) or on the logon screen (credential provider) does no
  blocking network I/O and cannot crash its host: minimal surface, queue work to a service.
- All binaries and MSIs are Authenticode-signed in the release pipeline (`security-baseline`).

## Comments and docs

Comment *why*, not *what*. Every exported identifier in a module's public package has a doc
comment. A TODO without a ticket ID is a review finding.
