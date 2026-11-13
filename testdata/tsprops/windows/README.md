# Windows userParameters fixtures (T-1890)

Captured on `dc1`, Windows Server 2025 build 26100 (version-scoped; 2019/2022 pending). Findings: `knowledge/development/domain/userparameters-windows-findings.md`.

- `records.jsonl`: TSP-W01..W18, corpus shape of safe-primitives §8 (`primitive attr.tsprops`, `call Decode`, `args.value.hex` = the LDAP octets, `hostile false`, `verified windows`). `expect.value` is read from the blob and checked against Windows' own readback. `windows_effective` says whether Windows honours the blob (W18 does not). `expect` is in blob terms (both text twins kept); mapping to the decoder's typed output is T-1566's.
- `probes.jsonl`: 39 probes (duplicates, inherit bits, gates, encodings). Not corpus records; evidence for the findings.
- `captures.json`: raw capture output.
- Regenerate: `lab/windows/bin/with-dc1-lock lab/windows/bin/capture-tsprops capture` then `lab/windows/bin/capture-tsprops derive` (derive needs no DC).
No credentials, SIDs or secrets are in these files; the accounts are disabled with no password.
