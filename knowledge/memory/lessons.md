---
title: Lessons learned
updated: 2026-10-02
budget: 120 lines
---

# Lessons learned

Gotchas that cost time. Newest first. `date · lesson · source`.

## Tooling and Claude Code (verified on 2.1.287)
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

## Domain and security
- 2026-10-02 · MinIO server is AGPL-3.0 and its repo was archived on 2026-04-25 → never bundle an object-store server; blobs go to the filesystem or a customer-supplied S3-API store (ADR-0001 rule 3). Source: https://github.com/minio/minio
- 2026-10-02 · go-msrpc does Kerberos through its own gokrb5 fork → a connector using go-ldap + go-krb5/krb5 *and* go-msrpc carries two Kerberos stacks; unify behind one `GSSAPIClient` when MS-RPC is adopted. Source: https://github.com/oiweiwei/go-msrpc, ADR-0001 Consequences
- 2026-10-02 · PowerShell treats curly quotes U+2018–U+201B as single quotes: an escaper that only doubles ASCII `'` lets a crafted name break out of the string (found in PatchIQ's `escapePSPath`). Our PowerShell primitive must escape all of them, with a test. Source: feasibility doc §risks.
- 2026-10-02 · go-ldap's Kerberos bind can't sign/seal or channel-bind on Linux, and gokrb5 has been dormant since 2023 — plan an adapter on go-krb5/krb5 and use LDAPS. Source: `knowledge/development/architecture/build-feasibility/ad-technical-feasibility.md`.
- 2026-10-02 · `AddCommand`/`AddParameter` does not make query-language parameters safe: AD-module `-Filter` and Exchange OPATH filters are parsed languages, and `-Identity` resolves strings as a DN, GUID, SID or sAMAccountName. Pass GUIDs to `-Identity` and only builder output to filters. Source: `knowledge/development/architecture/safe-primitives.md` §6.1
- 2026-10-02 · AD compares names ignoring case, width, kana type and accents (MS-ADTS sort keys), so a Samba-only test can false-pass a uniqueness check (José vs Jose). Ask the DC and run uniqueness tests on Windows. Source: `safe-primitives.md` §4.4, §9

## From PatchIQ (see ../UEM/knowledge/development/legacy/patchiq-postmortem.md §11)
- 2026-08-12 · Blind AI iteration destroys comprehension: document architecture before code; keep the architecture map current.
- 2026-08-12 · An extension interface that is not the only on-ramp from day one becomes decoration.
- 2026-08-12 · Security-relevant strings built with string formatting recur as a bug class — use shared safe primitives and lint against raw construction.
- 2026-08-12 · Fabricated UI data and dead buttons slipped through — QA traces every number to the API and clicks every control.
