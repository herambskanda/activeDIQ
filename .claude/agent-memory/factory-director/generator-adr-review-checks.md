---
name: generator-adr-review-checks
description: Codegen/contract ADR review — read the generator's templates for every construct the dialect allows; check a new decode path against safe-primitives analyzers
metadata:
  type: feedback
---

When an ADR picks a code generator and also bans imports in generated code, read the generator's actual
templates (`gh api repos/<o>/<r>/contents/<path>/templates/...`) for every schema construct the ADR's
dialect allows. Don't trust "models only" to be clean.

**Why:** On T-0046 (ADR-0004, 2026-10-02), the ADR let oapi-codegen emit models only, allowed discriminated
`oneOf`, and banned `encoding/json` v1 and `oapi-codegen/runtime` in generated code. But oapi-codegen's
`union.tmpl` uses v1 `json.Unmarshal` and `runtime.JSONMerge`, and formats such as uuid and date pull in
`runtime/types`. Because json/v2 calls a type's own `UnmarshalJSON`, the strict options never reach nested
union members. The filter AST would have been the hole. The ADR was rejected once.

**How to apply:**
- For each allowed construct (unions, nullable, PATCH wrappers, formats), ask which Go type it becomes and
  what that type imports. Demand a mapping table.
- A strictness corpus must test at every nesting level, not only the top-level body.
- When a new boundary decode path is introduced, grep safe-primitives for analyzers that constrain decoding
  (`secretjson`, FF-SP2) and for who owns and zeroes the buffer. Two fitness functions must not fail
  each other.
- Check the `Build`/composition signature for import cycles: a kernel package that serves API imports its
  generated `api` package, which imports the host. The host then needs ports, not imports.
- On the re-review, check the *fix* against the analyzers too. ADR-0004's rework routed every body
  through `secretjson.Decode`, but its generated nested decoders still call `UnmarshalDecode` into
  Secret-bearing types, which FF-SP2 as written reports. That was closed with a one-line ADR clarification
  plus a note on the analyzer ticket, not a second reject.
- For a "no copy of the secret" claim, ask how the decoder is constructed. `jsontext.NewDecoder` parses
  in place only over a `*bytes.Buffer`; any other reader copies internally.

Related: [[spike-review-checks]], [[adr-review-allowlist-and-ownership]], [[adr-ratification-flow]]
