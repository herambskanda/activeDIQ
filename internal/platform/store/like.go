package store

import (
	"database/sql/driver"
	"errors"
	"strings"
	"unicode/utf8"
)

// Errors returned by LikePattern construction (safe-primitives §7 rule 7). Their messages never carry
// the offending text.
var (
	// ErrNulInText is returned for text containing a NUL byte, which PostgreSQL text cannot hold.
	ErrNulInText = errors.New("store: text contains a NUL byte")
	// ErrInvalidUTF8 is returned for text that is not well-formed UTF-8.
	ErrInvalidUTF8 = errors.New("store: text is not valid UTF-8")
)

// LikePattern is user text rendered as a LIKE/ILIKE pattern with `\`, `%` and `_` escaped (safe-primitives
// §7 rule 4). The only way to use it is as a bind argument of `col LIKE $n ESCAPE '\'`: it implements
// driver.Valuer, which pgx honours, and exposes no string form to concatenate.
type LikePattern struct{ pattern string }

// Contains matches values that contain s literally: store.LikePattern{}.Contains(text).
func (LikePattern) Contains(s string) (LikePattern, error) { return newLike(s, "%", "%") }

// Prefix matches values that start with s literally.
func (LikePattern) Prefix(s string) (LikePattern, error) { return newLike(s, "", "%") }

func newLike(s, lead, trail string) (LikePattern, error) {
	if strings.IndexByte(s, 0) >= 0 {
		return LikePattern{}, ErrNulInText
	}
	if !utf8.ValidString(s) {
		return LikePattern{}, ErrInvalidUTF8
	}
	var b strings.Builder
	b.Grow(len(s) + len(lead) + len(trail) + 4)
	b.WriteString(lead)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\', '%', '_':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteString(trail)
	return LikePattern{pattern: b.String()}, nil
}

// Value implements driver.Valuer so the pattern binds as a text parameter.
func (p LikePattern) Value() (driver.Value, error) { return p.pattern, nil }
