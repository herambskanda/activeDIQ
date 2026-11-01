package report

import (
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// MaxSortKeyText bounds the text a sort key keeps. A longer value is cut on a rune boundary: two values
// that share their first 256 runes then tie and fall to the run order, which is still deterministic.
const MaxSortKeyText = 256

// neverTimeKey sorts before every real time key (years 1000 to 9999 are all four digits and start
// with "1" to "9"), so "never" is the earliest value of a time column.
const neverTimeKey = "0000-00-00T00:00:00Z"

// CellSortKey is the one encoder of a stored cell's sort key (contract §6.2): an order-preserving
// text that a page sorts by byte order (COLLATE "C"), so a stored result needs no per-column index
// and no locale. The second result is false when the cell has no key, and such a cell sorts last in
// both directions:
//   - text is NFC and case-folded, cut at MaxSortKeyText runes;
//   - an integer has its sign bit flipped and is zero-padded to 20 digits;
//   - a time is fixed-width RFC 3339 UTC; never is the earliest time;
//   - an enum is its SortRank, zero-padded to 10 digits, and an ID the column does not declare has no key;
//   - a boolean is "0" or "1", and a GUID its canonical text;
//   - absent, unknown, a list and a column that is not sortable have no key.
func CellSortKey(c Cell, col Column) (string, bool) {
	if !col.Sortable {
		return "", false
	}
	switch c.kind {
	case CellText:
		return foldText(c.s), true
	case CellInt:
		return pad20(uint64(c.i) ^ (1 << 63)), true
	case CellBool:
		if c.b {
			return "1", true
		}
		return "0", true
	case CellTime:
		return c.t.UTC().Format(time.RFC3339), true
	case CellNever:
		if col.Type == TypeTime {
			return neverTimeKey, true
		}
	case CellEnum:
		for _, e := range col.Enum {
			if e.ID == c.s {
				return pad10(e.SortRank), true
			}
		}
	case CellGUID:
		return GUIDString(c.g), true
	}
	return "", false
}

func foldText(s string) string {
	s = cases.Fold().String(norm.NFC.String(s))
	if len(s) > MaxSortKeyText {
		n := 0
		for i := range s {
			if n == MaxSortKeyText {
				return s[:i]
			}
			n++
		}
	}
	return s
}

func pad20(u uint64) string {
	d := strconv.FormatUint(u, 10)
	return strings.Repeat("0", 20-len(d)) + d
}

func pad10(n int) string {
	if n < 0 {
		n = 0
	}
	d := strconv.Itoa(n)
	if len(d) >= 10 {
		return d
	}
	return strings.Repeat("0", 10-len(d)) + d
}
