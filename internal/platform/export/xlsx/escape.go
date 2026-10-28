package xlsx

import (
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/export"
)

// escape encodes s for an XML text node or attribute value as ST_Xstring ([MS-OI29500]): characters
// XML 1.0 cannot carry (C0 except TAB and LF, U+FFFE, U+FFFF) and CR become _xHHHH_, and the
// underscore of a literal _xHHHH_ in the data is itself escaped as _x005F_, so data can never spell
// an escape. & < > " ' become entities. Input is valid UTF-8 (export.Sanitize ran).
func escape(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '_' && isXEscape(s[i:]):
			b.WriteString("_x005F_")
		case r == '&':
			b.WriteString("&amp;")
		case r == '<':
			b.WriteString("&lt;")
		case r == '>':
			b.WriteString("&gt;")
		case r == '"':
			b.WriteString("&quot;")
		case r == '\'':
			b.WriteString("&apos;")
		case r == '\t' || r == '\n':
			b.WriteRune(r)
		case r < 0x20 || r == 0xFFFE || r == 0xFFFF || r == '\r':
			b.WriteString("_x")
			h := strings.ToUpper(strconv.FormatInt(int64(r), 16))
			b.WriteString(strings.Repeat("0", 4-len(h)) + h + "_")
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

// isXEscape reports whether s starts with "_xHHHH_".
func isXEscape(s string) bool {
	if len(s) < 7 || s[0] != '_' || (s[1] != 'x' && s[1] != 'X') || s[6] != '_' {
		return false
	}
	for _, c := range []byte(s[2:6]) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

var excelEpoch = time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC)

// serial is the Excel date serial (1900 system) of a UTC instant.
func serial(r export.Resolved) string {
	d := r.Time.Sub(excelEpoch).Seconds() / 86400
	return strconv.FormatFloat(math.Round(d*1e9)/1e9, 'f', -1, 64)
}

// colName is the A1-style column letters for a zero-based index.
func colName(i int) string {
	var out []byte
	for i++; i > 0; i = (i - 1) / 26 {
		out = append([]byte{byte('A' + (i-1)%26)}, out...)
	}
	return string(out)
}
