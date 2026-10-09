---
title: Lessons learned
updated: 2026-10-02
budget: 120 lines
---

# Lessons learned

Gotchas that cost time. Newest first. `date · lesson · source`.

## Tooling and Claude Code (verified on 2.1.287)
- 2026-10-02 · Ticket ACs, body, summary and parity cannot change after `ticket new`. `ticket set` changes only priority, owner, epic, milestone, effort_override, tags, depends_on and decisions → get the ACs right before creating. Afterwards, amend with a note that starts "AC AMENDMENT (binding…)", or split into a new ticket. (T-0031 rework)
- 2026-10-02 · A grooming note said "do not touch store", but the dependency it named (River) needs the pgx pool and pgx.Tx that only store holds (ADR-0002 T5), so T-0084 blocked on its first run → before binding a "do not touch X" scope, check the library's entry points (constructor and transaction types) against the package boundaries. (T-0084 → T-0209)
- 2026-10-02 · When a plan creates dozens of tickets, a hand check missed 4 whose dependency closure lacked ADR-0001/0002 → before advancing, script it over `ticket list --json`: every product-code ticket's transitive depends_on includes T-0002 and T-0003, with no cycles. (T-0031 review)
- 2026-10-02 · Validate an epic's parity refs against the matrix before `epic new`, conditional rows included (for example ADM-045, partly in M2 under FD-04). To fix one later, use `epic set E-… parity_refs+=X` (or `-=`), never a full `parity_refs=` retype — it cannot drop the others by accident. (T-0031 review, T-0127)
- 2026-10-02 · The grooming trigger counts raw `ready` tickets, dependency-blocked ones included (factory/lib/candidates.mjs), so marking waiting tickets `ready` starves grooming while the dispatcher idles → make ready only tickets whose dependencies are done; keep DoR-complete tickets in `backlog` until then. (T-0031)
- 2026-10-02 · `--autocompact 300000` compacts at ≈250k (it keeps an output/buffer reserve), so context warnings must fire below that: thresholds are 60/72/80 % (180k/216k/240k). At 85 % the worker was auto-compacted before it could write a graceful handoff. (T-0005 run, factory/config.json)
- 2026-10-02 · WebSearch has a budget of 200 searches per session, shared by all its subagents. Parallel research inside one session starves; run each research stream as its own headless worker (own budget).
- 2026-10-02 · macOS has no `timeout` binary — implement timeouts in Node, not the shell.
- 2026-10-02 · The CEO's zsh defines an alias `g`; shell functions named `g` fail to parse. Use descriptive function names in scripts.
- 2026-10-02 · Hook scripts: a module-level `const` declared after the top-level `safely()` call is in the temporal dead zone — the hook throws and silently no-ops. Declare constants first; debug with FACTORY_HOOK_DEBUG=1.
- 2026-10-02 · Hooks fire for tool calls inside subagents; input carries `agent_id`/`agent_type`; the subagent transcript is `<transcript dir>/<session_id>/subagents/agent-<agent_id>.jsonl`.
- 2026-10-02 · Context in use = input + cache_creation + cache_read (+ output) tokens of the latest assistant message in the transcript JSONL.
- 2026-10-02 · Sonnet 5.5 has a 1M-token window in Claude Code; the 300k budget is self-imposed (`--autocompact 300000`, `autoCompactWindow`, plus the context-guard hook).
- 2026-10-02 · Built-in `Explore` runs on Haiku; `.claude/agents/Explore.md` overrides it. A brand-new `.claude/agents/` directory is not watched until the session restarts.
- 2026-10-02 · `claude -p --agent <name>` applies the agent's model, tools, skills and prompt; `--effort` overrides the frontmatter effort.
- 2026-10-02 · User-level `modelSettings.<model>.effortLevel` overrides agent frontmatter `effort`; the dispatcher therefore always passes `--effort` (override, else frontmatter), and project settings pin `modelSettings` so subagents default to policy effort.
- 2026-10-02 · The host disk is shared with other projects and filled up (ENOSPC). The dispatcher and 5 workers died, and OrbStack crashed. There were two causes. Our own: `docker rm -f` without `-v` leaked one anonymous postgres volume per test server, about 735 volumes and 77 GB in one day (fix T-0206). Another project: `helm-*` temp dirs. → Container teardown always passes `-v`. Never run `docker volume prune` or `docker system prune` (other projects' data). The dispatcher now holds launches below `min_free_disk_gb` (10). If the disk runs out, block with the exact command for a human; never use `dangerouslyDisableSandbox`.

## Domain and security
- 2026-10-02 · RLS does not cover integrity checks or whole-table ops: FK and unique checks "always bypass row security", `TRUNCATE` ignores it, a partition named directly uses only its own policies, and `COPY FROM` is refused on RLS tables → tenant_id leads every unique index, FKs are composite on tenant_id, every partition carries the policy, the runtime role has no TRUNCATE, bulk ingest uses batched INSERT (ADR-0002 T2–T4). Source: https://www.postgresql.org/docs/current/ddl-rowsecurity.html, https://www.postgresql.org/docs/current/sql-copy.html
- 2026-10-02 · A PostgreSQL view applies the *view owner's* RLS context unless created with `security_invoker = true`, and River's own tables cannot carry our tenant policy → views over tenant tables must set `security_invoker`, and job tenancy rests on the job wrapper (ADR-0002 checks T2, T5). Source: https://www.postgresql.org/docs/current/sql-createview.html
- 2026-10-02 · MinIO server is AGPL-3.0 and its repo was archived on 2026-04-25 → never bundle an object-store server; blobs go to the filesystem or a customer-supplied S3-API store (ADR-0001 rule 3). Source: https://github.com/minio/minio
- 2026-10-02 · go-msrpc does Kerberos through its own gokrb5 fork → a connector using go-ldap + go-krb5/krb5 *and* go-msrpc carries two Kerberos stacks; unify behind one `GSSAPIClient` when MS-RPC is adopted. Source: https://github.com/oiweiwei/go-msrpc, ADR-0001 Consequences
- 2026-10-02 · PowerShell treats curly quotes U+2018–U+201B as single quotes: an escaper that only doubles ASCII `'` lets a crafted name break out of the string (found in PatchIQ's `escapePSPath`). Our PowerShell primitive must escape all of them, with a test. Source: feasibility doc §risks.
- 2026-10-02 · go-ldap's Kerberos bind can't sign/seal or channel-bind on Linux, and gokrb5 has been dormant since 2023 — plan an adapter on go-krb5/krb5 and use LDAPS. Source: `knowledge/development/architecture/build-feasibility/ad-technical-feasibility.md`.
- 2026-10-02 · `AddCommand`/`AddParameter` does not make query-language parameters safe: AD-module `-Filter` and Exchange OPATH filters are parsed languages, and `-Identity` resolves strings as a DN, GUID, SID or sAMAccountName. Pass GUIDs to `-Identity` and only builder output to filters. Source: `knowledge/development/architecture/safe-primitives.md` §6.1
- 2026-10-02 · AD compares names ignoring case, width, kana type and accents (MS-ADTS sort keys), so a Samba-only test can false-pass a uniqueness check (José vs Jose). Ask the DC and run uniqueness tests on Windows. Source: `safe-primitives.md` §4.4, §9
- 2026-10-02 · Go's `encoding/json` (v1) silently replaces invalid UTF-8 and lone-surrogate escapes with U+FFFD, so a primitive's "reject invalid UTF-8" check never fires. A password reset could then set a password nobody typed. Decode strictly at the API boundary (`encoding/json/v2` rejects by default), and decode `Secret` from raw bytes. Source: https://pkg.go.dev/encoding/json#Unmarshal
- 2026-10-02 · An LDAP filter only narrows results, but the request around it can widen them. ASQ, phantom-root search options, show-deleted/recycled, DirSync and the GC port all return objects outside an OU base. Feature code gets `ScopedSearch(delegation, …)` only; escape controls exist only in named operations. Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea
- 2026-10-02 · Samba rejects any `pwdLastSet` except 0/-1 (even via offline `ldbadd`), so seeded password ages need a set-back clock (libfaketime) while adding users; `lastLogon`, `lastLogonTimestamp`, `accountExpires` write directly. Source: T-0012, `knowledge/development/runbooks/ad-lab.md` §3
- 2026-10-02 · Samba returns all values of a >1500-value attribute unranged on a plain read, where Windows ranges it, so a connector that forgets to page passes on the Samba lab and fails on Windows. Request `member;range=…` explicitly and loop. Source: T-0012 (measured), runbook §5
- 2026-10-02 · A reset/restore proof needs its baseline digest taken before any check that binds: binds change `lastLogon`, `logonCount`, `badPwdCount`, and the reset rightly undoes them. Source: T-0012 `lab/tests/verify.sh`

## From PatchIQ (see ../UEM/knowledge/development/legacy/patchiq-postmortem.md §11)
- 2026-08-12 · Blind AI iteration destroys comprehension: document architecture before code; keep the architecture map current.
- 2026-08-12 · An extension interface that is not the only on-ramp from day one becomes decoration.
- 2026-08-12 · Security-relevant strings built with string formatting recur as a bug class — use shared safe primitives and lint against raw construction.
- 2026-08-12 · Fabricated UI data and dead buttons slipped through — QA traces every number to the API and clicks every control.
