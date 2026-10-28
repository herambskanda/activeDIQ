package cellsafe

// FormulaLeadTable holds every code point whose NFKC normalisation starts with '=', '+', '-', '@' or
// U+2212 MINUS SIGN, sorted ascending. NFKC is used only to build this table (R4). It is generated:
// TestTableMatchesNFKC rebuilds it with golang.org/x/text/unicode/norm in CI and fails when the
// output differs from this committed list (§12.2). Unicode 15.0 data, 22 entries, the same set
// Python's unicodedata gives.
var FormulaLeadTable = []rune{
	0x002B, 0x002D, 0x003D, 0x0040,
	0x207A, 0x207B, 0x207C,
	0x208A, 0x208B, 0x208C,
	0x2212,
	0x2A75, 0x2A76,
	0xFB29,
	0xFE62, 0xFE63, 0xFE66, 0xFE6B,
	0xFF0B, 0xFF0D, 0xFF1D, 0xFF20,
}
