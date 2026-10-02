---
name: attr-codec-lessons
description: Craft lessons from building the attr codecs (T-0070) and the corpus gate they run under
metadata:
  type: reference
---

- Corpus gate oracle shapes: for GUID/SID the Windows oracle only reads records `text input + bytes_hex` (parse) and
  `hex input + render` (format). A render record with hex input that is not a plain text form (e.g. ObjectRef) would be
  sent to Windows and fail: feed such calls a text input instead.
- Spec vectors can be unsatisfiable: GT-14 (`261002101112Z` must fail Generalized Time) is a valid year-2610 value.
  Compute expectations independently (Python), run, and fix the spec row in the same change with the reason.
- `make fitness-corpus` runs each package test with cwd = package dir; a relative -report-dir used to land under the
  package (fixed T-0070). `.safeprim-reports/` is gitignored; stray copies under packages are not.
- Go time: `Format(".9999999")` truncates to 100 ns; use 9 digits when testing nanosecond fractions.
- Fuzz seeds come from `corpustest.Seed` as []byte: keep corpus inputs small (GUID-16 is 4 KiB, 1 MiB is a unit test).
- No Docker on the dev Mac (OrbStack off): Samba/pwsh oracles cannot run locally; say so and file a lab ticket.
