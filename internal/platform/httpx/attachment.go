// Package httpx holds the HTTP response primitives that must not be hand-built: today the download
// headers (safe-primitives P7, §12.5 rule 5). httpx.Attachment and Headers are the only code in the
// product that sets Content-Disposition; FF-SP2 (content-disposition-literal) fails the build for
// any other package that does.
package httpx

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Format is the closed set of download formats. The file extension and media type come from it and
// never from the caller's file name (§12.5 rule 5). The zero value is not a format.
type Format uint8

const (
	CSV Format = iota + 1
	XLSX
	HTML
	PDF
)

var formats = map[Format]struct{ ext, mediaType string }{
	CSV:  {".csv", "text/csv; charset=utf-8"},
	XLSX: {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
	HTML: {".html", "text/html; charset=utf-8"},
	PDF:  {".pdf", "application/pdf"},
}

// Typed errors. Both are returned before any header is written.
var (
	// ErrUnknownFormat: the Format is not one of the constants above.
	ErrUnknownFormat = errors.New("httpx: unknown download format")
	// ErrMissingStyleHash: an HTML download needs the SHA-256 of its single <style> block for its CSP.
	ErrMissingStyleHash = errors.New("httpx: an HTML attachment needs WithStyleSHA256")
)

// MaxBaseRunes caps the base name (R5). A longer base is cut on a rune boundary: a label, not an input.
const MaxBaseRunes = 120

// defaultBase names a download whose base is empty.
const defaultBase = "download"

// Option adjusts Attachment and Headers.
type Option func(*options)

type options struct {
	styleHash    [sha256.Size]byte
	hasStyleHash bool
}

// WithStyleSHA256 supplies the SHA-256 of the HTML export's <style> contents, which the CSP of an
// HTML attachment pins (§12.5 rule 4 and 5).
func WithStyleSHA256(sum [sha256.Size]byte) Option {
	return func(o *options) { o.styleHash, o.hasStyleHash = sum, true }
}

// Attachment sets the download headers (see Headers) and copies body to w. A nil body writes the
// headers only. The status is the default 200; callers that must choose one use Headers.
func Attachment(w http.ResponseWriter, base string, f Format, body io.Reader, opts ...Option) error {
	if err := Headers(w.Header(), base, f, opts...); err != nil {
		return err
	}
	if body == nil {
		return nil
	}
	_, err := io.Copy(w, body)
	return err
}

// Headers sets Content-Disposition (attachment, never inline), Content-Type and
// X-Content-Type-Options: nosniff, plus, for HTML, a sandboxing Content-Security-Policy. On error
// it sets nothing.
func Headers(h http.Header, base string, f Format, opts ...Option) error {
	spec, ok := formats[f]
	if !ok {
		return ErrUnknownFormat
	}
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if f == HTML && !o.hasStyleHash {
		return ErrMissingStyleHash
	}
	name := fileName(base) + spec.ext
	h.Set("Content-Disposition", `attachment; filename="`+asciiFallback(name)+`"; filename*=UTF-8''`+pctEncode(name))
	h.Set("Content-Type", spec.mediaType)
	h.Set("X-Content-Type-Options", "nosniff")
	if f == HTML {
		h.Set("Content-Security-Policy", "sandbox; default-src 'none'; style-src 'sha256-"+
			base64.StdEncoding.EncodeToString(o.styleHash[:])+"'; img-src data:")
	}
	return nil
}

// fileName is the O3 mapping for file names: Cc, Cf, \ / : * ? " < > | and % become "_", visibly and
// never by deletion. Invalid UTF-8 bytes become "_" too.
func fileName(base string) string {
	var b strings.Builder
	n := 0
	for i := 0; i < len(base) && n < MaxBaseRunes; n++ {
		r, size := utf8.DecodeRuneInString(base[i:])
		i += size
		switch {
		case r == utf8.RuneError && size <= 1,
			unicode.Is(unicode.Cc, r), unicode.Is(unicode.Cf, r),
			strings.ContainsRune(`\/:*?"<>|%`, r):
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return defaultBase
	}
	return b.String()
}

// asciiFallback is the quoted filename parameter: printable ASCII only, so it can hold neither a
// quote, a backslash nor a control character (fileName removed those) and older clients get a name.
func asciiFallback(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			r = '_'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// pctEncode is the RFC 8187 value-chars encoding of the UTF-8 bytes: everything outside attr-char
// is %XX with upper-case hex.
func pctEncode(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if attrChar(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

// attrChar is RFC 8187 attr-char: ALPHA / DIGIT / "!" / "#" / "$" / "&" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~".
func attrChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$&+-.^_`|~", c) >= 0
}
