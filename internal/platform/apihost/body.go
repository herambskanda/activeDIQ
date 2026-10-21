package apihost

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
)

// Limits of the validation pass (ADR-0004 rule 6 step 2).
const (
	maxDepth        = 32
	maxValues       = 10000
	classBulk       = "bulk"
	mediaJSON       = "application/json"
	mediaMergePatch = "application/merge-patch+json"
)

var (
	errTooLarge  = errors.New("apihost: body over the cap")
	errMalformed = errors.New("apihost: malformed body")
)

// readBody reads the request body into a buffer apihost owns, allocated once and never grown
// (rule 6 step 1): Content-Length if present and within the cap, else the cap plus one byte so an
// overflow is detectable. The caller clears the buffer when the request ends.
func readBody(r *http.Request, limit int64) ([]byte, error) {
	if r.ContentLength > limit {
		return nil, errTooLarge
	}
	size := limit + 1
	if r.ContentLength >= 0 {
		size = r.ContentLength
	}
	buf := make([]byte, size)
	n, err := io.ReadFull(io.LimitReader(r.Body, size), buf)
	switch {
	case err == nil, errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
	default:
		clear(buf)
		return nil, errMalformed
	}
	if int64(n) > limit {
		clear(buf)
		return nil, errTooLarge
	}
	if r.ContentLength >= 0 && int64(n) != r.ContentLength {
		clear(buf)
		return nil, errMalformed // the client sent less than it declared
	}
	return buf[:n], nil
}

// checkJSON walks the whole buffer with a default-options jsontext.Decoder, which rejects invalid
// UTF-8, escaped lone surrogates, duplicate names and trailing data. It adds the depth and value
// limits and refuses a \u0000 escape in any string or member name. Strings are read with
// ReadValue and scanned as bytes, so a secret never becomes a Go string.
func checkJSON(buf []byte, bulk bool) error {
	d := jsontext.NewDecoder(bytes.NewReader(buf))
	values := 0
	for {
		kind := d.PeekKind()
		if kind == 0 {
			break
		}
		values++
		if !bulk && values > maxValues {
			return errMalformed
		}
		switch kind {
		case '{', '[':
			if _, err := d.ReadToken(); err != nil {
				return errMalformed
			}
			if d.StackDepth() > maxDepth {
				return errMalformed
			}
		case '}', ']':
			if _, err := d.ReadToken(); err != nil {
				return errMalformed
			}
		default:
			v, err := d.ReadValue()
			if err != nil {
				return errMalformed
			}
			if kind == '"' && hasNULEscape(v) {
				return errMalformed
			}
		}
		if d.StackDepth() == 0 {
			break // one complete top-level value
		}
	}
	if values == 0 {
		return errMalformed
	}
	if _, err := d.ReadToken(); !errors.Is(err, io.EOF) {
		return errMalformed // trailing data
	}
	return nil
}

// hasNULEscape reports a \u0000 escape in a raw JSON string. An escaped backslash followed by
// "u0000" is legal text and is skipped as a pair.
func hasNULEscape(s jsontext.Value) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			continue
		}
		if i+5 < len(s) && s[i+1] == 'u' && s[i+2] == '0' && s[i+3] == '0' && s[i+4] == '0' && s[i+5] == '0' {
			return true
		}
		i++ // skip the escaped character
	}
	return false
}

// mediaTypeOK accepts the declared request media type, with no parameter or charset=utf-8.
func mediaTypeOK(header, want string) bool {
	mt, params, err := mime.ParseMediaType(header)
	if err != nil || mt != want {
		return false
	}
	for k, v := range params {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			return false
		}
	}
	return true
}
