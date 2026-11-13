# replxml seed corpus (connector-contract §5.7 X8)

`valid/` is **synthetic**: written by hand from the `DS_REPL_*` structures of MS-DRSR
(https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/0597aff6-0177-4d52-99f2-14a5441bc3c1).
Element names and value formats are `[UNVERIFIED]` until XML captured from Windows Server 2016, 2022 and
2025 replaces or joins them (CC-REPLXML-01, `[LAB: Windows]`). GUIDs, DNs and hosts are made up.

`hostile/` is the X8 list: billion laughs, external entity by file and URL, parameter entity, undeclared
entity, a deep nest, text nodes of 2 KiB and 1 MiB, 20,001 elements, a 64 KiB document of tiny elements,
17 attributes, attribute-heavy and namespace-heavy documents within 64 KiB (the allocation bound), a 7,000-attribute start tag, invalid UTF-8, NUL, a C0 control, UTF-16 with and without BOM, a non-UTF-8 declaration, a
stray processing instruction, a truncated document, duplicate and unknown elements, a second root, an empty
document. `corpus_test.go` pins the exact code each one must produce from all five decoders (it rewrites the root and the repeated field name to each decoder's own, so the structural refusal is what is asserted, never `bad_root`). Add a file here and an entry in
`hostileWant`; a crash input found by a fuzz run is committed here before its fix merges (RX4).
