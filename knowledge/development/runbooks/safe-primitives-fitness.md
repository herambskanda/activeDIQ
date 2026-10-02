---
title: "Runbook: safe-primitives corpus, fuzz and oracles (FF-SP4 to FF-SP6, FF-SP8)"
date: 2026-10-02
updated: 2026-10-02
status: draft
owner: devops-engineer
ticket: T-0034
---

# Runbook: safe-primitives corpus, fuzz and oracles

Spec: `knowledge/development/architecture/safe-primitives.md` §8 (corpus, FF-SP table) and §9
(verification status). Gate list: `knowledge/development/standards/ci-gates.md`.

## 1. What runs where

| Target | What it enforces | When |
| --- | --- | --- |
| `make fitness-corpus` | FF-SP4 (schema, every unit >= 10 `hostile` records, `records.lock.json` ratchet, every declared implementation runs every runtime record, Go code in a primitive's home must be declared); FF-SP5 declarations (a fuzz target exists, calls `corpustest.Seed`, covers the properties the unit requires); FF-SP8 (the declared `TestConstantArgv`) | `make ci`, every merge |
| `make fitness-oracles` | FF-SP6 on Linux: `pslit` output through PowerShell's own parser (`pwsh`, or the digest-pinned container with `--network none`; needs Docker), `ldapfilter` through go-ldap's compile / decompile / compile | `make ci` |
| `make fitness-fuzz-nightly` | FF-SP5 long run: every declared target for >= 10 min (`-nightly` refuses less). Log: `.safeprim-reports/fuzz.log` | nightly |
| `make fitness-oracles-lab` | FF-SP6 Samba row for P1: the DC accepts every rendered filter. Passing records get `"verified": "samba"` (commit the change) | nightly, needs the Samba lab (`ad-lab.md`) |
| `make fitness-oracles-windows` | FF-SP6 Windows rows: PowerShell 5.1 parses `pslit` output; SID and GUID text/bytes through `ConvertStringSidToSidW`, `ConvertSidToStringSidW`, `Guid.Parse`, `StringFromGUID2` | Windows runner or lab, nightly |
| `make fitness-nightly` | `fitness-fuzz-nightly` and `fitness-oracles-lab` | nightly |

An oracle that cannot run (no `pwsh`/Docker, no lab, no Windows) exits 2. It is a failure, never a skip.
Until an implementation has reported, the oracles check the corpus's expected values (`-source golden`);
afterwards they check the implementation's actual outputs (`-source report`, `auto` picks).

## 2. Adding an implementation of a unit

1. **Declare it** in `testdata/safe-primitives/implementations.json`:
   `{"name":"go/ldapfilter","language":"go","tier":"S","units":["ldapfilter"],"package":"internal/directory/ldapfilter"}`.
   `psx` and `proc` also need `"argvTest":"TestConstantArgv"`. Non-Go implementations give
   `"command"` / `"argvCommand"` and write the same report JSON (`internal/platform/corpus/report.go`)
   into `$SAFEPRIM_REPORT_DIR`; the Rust tier N (`native/shared`) does this.
2. **Run the corpus** in the package (`internal/platform/corpus/corpustest`; product tests may not import `tools/`):

   ```go
   func TestCorpus(t *testing.T) {
       corpustest.Run(t, "go/ldapfilter", "ldapfilter", func(r corpus.Record) (corpus.Result, error) { … })
   }
   ```

   Every runtime record must be handled. `corpustest.Skip(...)` fails the gate; only `static`, `lab`
   and `e2e` records are not run here.
3. **Fuzz**: a `Fuzz…` target that begins with `corpustest.Seed(f, "<unit>")`, declared under `"fuzz"`
   with its `properties` (`roundtrip`, `noUnescapedSpecial`, the P7 ones). A unit with nothing to fuzz
   goes under `"fuzzExempt"` with a reason, which is printed on every run.
4. **Constant argv** (`psx`, `proc`): `corpustest.ConstantArgv` with a `Gen` of random requests
   (`HostileStrings` and `Mutate` supply hostile values), `Observe` returning the argv the child gets,
   and `Template` listing constant elements (`C`) and typed value slots (`Slot`, `Joined`).
5. **Home**: `tools/analyzers/policy/policy.go` `UnitHomes` maps a unit to its package directory. Go code
   there that no manifest entry declares fails with `undeclared-implementation`. That is what keeps the
   gate non-vacuous while no implementation exists. `sd.read` and `sd.write` get an entry when
   T-0118 / T-0135 name the packages.
6. `make fitness-corpus fitness-oracles`.

## 3. Changing the corpus

- Add records freely. Run `go run ./tools/fitness/corpus -update-lock` and commit `records.lock.json`.
- **Removing or reclassifying a hostile record**: add the replacement in the same change, then retire the
  old ID (`retired` entry with `supersededBy` and a reason). `-update-lock` refuses to downgrade
  anything else. A removed ID without a retirement fails with `record-removed`.
- `verified` is written by the lab runs (`-set-verified`), not by hand. Values: `doc`, `samba`, `windows`,
  `samba+windows`. The `pslit` parser oracle does not change it.
- A corpus change is a security-relevant change: security-architect reviews the diff.

## 4. Reading a failure

- `FF-SP4 [min-hostile]` a unit fell below 10 hostile records.
- `FF-SP4 [skipped-record]` / `[unknown-record]` / `[stale-corpus]` the implementation skipped a record, failed one (record-failed), reported an ID that is not in the file, ran against another copy of the corpus (the report carries the file's SHA-256: rerun its test).
- `FF-SP4 [undeclared-implementation]` Go code in a primitive's home with no manifest entry.
- `FF-SP5 [no-fuzz-target]` / `[fuzz-target]` (declared target missing or not calling `corpustest.Seed`) / `[fuzz-properties]` (a property the unit requires is not declared) / `[fuzz-time]` (nightly shorter than 10 min) / `[fuzz-failed]`: see step 3.
- `FF-SP8 [argv-differs]` / `[constant-argv]` / `[too-few-requests]` / `[no-report]` the message names the request index, the seed and the argv difference. Rerun the test with the printed seed.
- `oracles pslit` the record ID, the input, and what PowerShell's parser said. Never fix by editing the oracle: fix the implementation or, if the corpus is wrong, the corpus.
- A fuzz crasher is written to `testdata/fuzz/<Target>/` of the package: commit it with the fix.

## 5. Nightly and Windows runners

There is no hosted CI and no scheduler yet, so the nightly log (AC3) and the Windows 5.1 / SID / GUID /
Samba-lab logs are produced by hand until the follow-up tickets land. Manual run:

```bash
make fitness-nightly                       # Linux host with Docker and the Samba lab
# Windows host: Go, PowerShell 5.1, a checkout of the commit under test
make fitness-oracles-windows               # or run the go run … lines of the target from PowerShell
```

The Windows scripts are constant PowerShell text with the data on stdin. They are parse-checked in
`tools/fitness/oracles` tests but only executed on Windows. Windows lab credentials, if a run ever needs
any, are generated per run and never committed (`ad-lab.md`).

## 6. Tooling and licences

`github.com/go-ldap/ldap/v3` v3.4.13 (MIT; `tools/fitness/oracles` only; do not bump to v3.4.14, it moves
`x/tools`, `x/net` and `x/sys`) and the PowerShell container `mcr.microsoft.com/powershell` (MIT, pinned by
digest in `tools/fitness/oracles/engine.go`). Both are rows in
`knowledge/business/licensing/open-source-license-register.md`. To move the container digest, update the
constant, run `go test ./tools/fitness/oracles`, and re-run the PowerShell version note in the oracle output.
