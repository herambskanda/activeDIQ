---
name: replxml-lessons
description: T-1721 replxml decoder - encoding/xml alloc per element breaks the 8x bound, one value per call, RX2 grep traps
metadata:
  type: feedback
---

- encoding/xml allocates ~190 B per `<a/>` (4 input bytes), so "allocation within 8 x input" fails long before the 20,000-element X3 cap. Effective cap is `min(20000, (8*len+8KiB)/256)` (parse.go `elementLimit`); contract X3 carries the note.
- `20,001 elements` and `10,000-deep` seed files exceed the 64 KiB value cap (too_large first). Deep file is unclosed (30 KB) so it reaches too_deep; the hard 20,000 cap is tested through the internal `limits` struct with comment padding.
- Do not write `d.CharsetReader = nil` / `d.Entity = nil`: RX2 flags any assignment of those fields. Defaults are nil; comment instead.
- Go reports a non-UTF-8 declared encoding only as an error string containing "CharsetReader"; map it to bad_encoding. Pre-scan bytes (UTF-16, C0, invalid UTF-8) before the XML decoder so codes are stable.
- Decode* take ONE attribute value and return `*DecodeError` (not `error`): nil-interface trap documented in doc.go. Own `Guid`/`Time`/`U32` types keep the package free of proto/guid imports (X6); proto mapping is the RPC ticket's job.
- Element/field names are [UNVERIFIED] (MS-DRSR DS_REPL_*); `uuidObjectGuid` for the link target GUID is my guess. Windows capture is CC-REPLXML-01.
