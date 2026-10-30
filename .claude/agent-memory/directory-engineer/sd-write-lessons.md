---
name: sd-write-lessons
description: sd.write (T-0583) — corpus gate runs one named test per implementation, oracle pitfalls, insert-position rule
metadata:
  type: feedback
---

- The FF-SP4 gate runs only `-run ^<testName>$` per implementation; a second unit's `corpustest.Run` must be called from that same test (here `TestCorpus` calls `corpusWrite`). A separate TestCorpusWrite gives `no-report`.
- Each unit needs its own FF-SP5 fuzz entry (`corpustest.Seed(f, "<unit>")` first); units outside `requiredProps` need only one property.
- `python3 -I` generators cannot import siblings: copy helpers.
- Whole-object ACE inserts before the first scoped ACE of the same decision type (not at the block end); oracle got this wrong first.
- `-update-lock` also records hostile false->true upgrades made in the corpus file earlier (SD-W10/W18 via T-0728); it only moves up, so its diff is not strictly additions.
- dn corpus (T-0886): `corpustest` import path is `internal/platform/corpus/corpustest`; `=` renders `\3D` (a hand-written expectation of `OU=HR` inside an escaped value is wrong). Pre-existing red left: cellsafe/csv/xlsx undeclared-implementation.
**Why:** cost several debugging rounds. **How to apply:** adding any new corpus unit to an existing implementation.
