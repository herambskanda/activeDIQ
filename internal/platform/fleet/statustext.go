package fleet

import (
	"strconv"
	"strings"
	"unicode"

	"google.golang.org/grpc/codes"
)

// MaxStatusMessage is the bound on a component's CallClose text (TM-D24 C1).
const MaxStatusMessage = 1024

// maxScan limits how much of an oversized message is looked at: enough to fill MaxStatusMessage even
// when every byte is escaped, without walking a megabyte.
const maxScan = 4 * MaxStatusMessage

// SanitizeStatusText makes a component's CallClose.status_message safe to log, store and return as a
// structured field (TM-D24 C1, C2). Invalid UTF-8 is replaced with U+FFFD; C0 and C1 controls, the
// bidi controls and marks, the line and paragraph separators, backslash and the HTML metacharacters
// become \uXXXX escapes. The result is at most MaxStatusMessage bytes and is cut on an escape or rune
// boundary. It is still untrusted text: nothing may decide on it, and it is never a format string.
func SanitizeStatusText(s string) string {
	if len(s) > maxScan {
		s = s[:maxScan]
	}
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	b.Grow(min(len(s), MaxStatusMessage))
	for _, r := range s {
		var piece string
		if needsEscape(r) {
			piece = escapeRune(r)
		} else {
			piece = string(r)
		}
		if b.Len()+len(piece) > MaxStatusMessage {
			break
		}
		b.WriteString(piece)
	}
	return b.String()
}

func needsEscape(r rune) bool {
	switch {
	case unicode.Is(unicode.Cc, r): // C0, DEL, C1
		return true
	case r == '\\', r == '<', r == '>', r == '&', r == '"', r == '\'':
		return true
	case r == 0x2028, r == 0x2029, r == 0x061C, r == 0x200E, r == 0x200F, r == 0xFEFF:
		return true
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

const hexDigits = "0123456789abcdef"

func escapeRune(r rune) string {
	if r > 0xFFFF {
		return "\\u{" + strconv.FormatInt(int64(r), 16) + "}"
	}
	return "\\u" + string([]byte{hexDigits[(r>>12)&0xF], hexDigits[(r>>8)&0xF], hexDigits[(r>>4)&0xF], hexDigits[r&0xF]})
}

// NormalizeCode maps a peer's status_code to a google.rpc.Code. Anything outside 0 to 16 is UNKNOWN
// (TM-D24 C3).
func NormalizeCode(c int32) codes.Code {
	if c < 0 || c > int32(codes.Unauthenticated) {
		return codes.Unknown
	}
	return codes.Code(c)
}

// FixedText is the text the server sends for a code (TM-D24 C4): never an internal error string.
func FixedText(c codes.Code) string {
	switch c {
	case codes.OK:
		return ""
	case codes.Canceled:
		return "call canceled"
	case codes.InvalidArgument:
		return "invalid argument"
	case codes.DeadlineExceeded:
		return "deadline exceeded"
	case codes.NotFound:
		return "not found"
	case codes.AlreadyExists:
		return "already exists"
	case codes.PermissionDenied:
		return "method not available"
	case codes.ResourceExhausted:
		return "resource exhausted"
	case codes.FailedPrecondition:
		return "failed precondition"
	case codes.Aborted:
		return "aborted"
	case codes.OutOfRange:
		return "out of range"
	case codes.Unimplemented:
		return "not implemented"
	case codes.Unavailable:
		return "unavailable"
	case codes.DataLoss:
		return "data loss"
	case codes.Unauthenticated:
		return "unauthenticated"
	default:
		return "call failed"
	}
}
