package apitypes

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/mail"
	"strconv"
	"unicode/utf8"
)

// The functions below are the vocabulary of generated decoders and validators. They are exported
// because generated code in other packages calls them; handlers have no use for them.

// ObjectStart consumes '{'. Anything else, null included, is a type violation: an object member
// that is null is recorded by the caller before it reaches here.
func ObjectStart(d *jsontext.Decoder) error {
	tok, err := d.ReadToken()
	if err != nil {
		return err
	}
	if tok.Kind() != '{' {
		return violation(d, CodeType, "expected an object")
	}
	return nil
}

// NextMember reads the next member name, or consumes '}' and reports ok=false. The decoder itself
// refuses duplicate names.
func NextMember(d *jsontext.Decoder) (name string, ok bool, err error) {
	if d.PeekKind() == '}' {
		_, err = d.ReadToken()
		return "", false, err
	}
	tok, err := d.ReadToken()
	if err != nil {
		return "", false, err
	}
	return tok.String(), true, nil
}

// UnknownMember is the error for a member name outside the schema, including a wrong-case name.
// The pointer names the member; the name itself is not echoed in the detail.
func UnknownMember(d *jsontext.Decoder) error {
	return violation(d, CodeUnknownMember, "unknown member")
}

// BadKind is the error for a union value whose kind is missing, unknown or the wrong type.
func BadKind(d *jsontext.Decoder, detail string) error { return violation(d, CodeKind, detail) }

// TakeNull consumes a JSON null if that is the next value, and reports whether it did.
func TakeNull(d *jsontext.Decoder) (bool, error) {
	if d.PeekKind() != 'n' {
		return false, nil
	}
	_, err := d.ReadValue()
	return true, err
}

// DecodeArray decodes a JSON array element by element through each element's own decoder, so the
// caller's options reach it. v2's built-in slice decoding turns a null element into the zero value;
// here a null element is a violation.
func DecodeArray[T any](d *jsontext.Decoder, out *[]T) error {
	tok, err := d.ReadToken()
	if err != nil {
		return err
	}
	if tok.Kind() != '[' {
		return violation(d, CodeType, "expected an array")
	}
	s := []T{}
	for d.PeekKind() != ']' {
		if d.PeekKind() == 'n' {
			_, _ = d.ReadValue()
			return violation(d, CodeNull, "null is not allowed here")
		}
		var e T
		if err := json.UnmarshalDecode(d, &e); err != nil {
			return err
		}
		s = append(s, e)
	}
	_, err = d.ReadToken()
	*out = s
	return err
}

// DecodeMap decodes a JSON object with one value schema, as DecodeArray does for arrays.
func DecodeMap[T any](d *jsontext.Decoder, out *map[string]T) error {
	if err := ObjectStart(d); err != nil {
		return err
	}
	m := map[string]T{}
	for {
		name, ok, err := NextMember(d)
		if err != nil {
			return err
		}
		if !ok {
			*out = m
			return nil
		}
		if d.PeekKind() == 'n' {
			_, _ = d.ReadValue()
			return violation(d, CodeNull, "null is not allowed here")
		}
		var e T
		if err := json.UnmarshalDecode(d, &e); err != nil {
			return err
		}
		m[name] = e
	}
}

// Index returns the pointer of element i under at.
func Index(at jsontext.Pointer, i int) jsontext.Pointer { return at.AppendToken(strconv.Itoa(i)) }

// Required records a missing required member.
func (e *Errors) Required(at jsontext.Pointer, name string) {
	e.AddBody(at.AppendToken(name), CodeRequired, "required member is missing")
}

// NullNotAllowed records null on a member that is not nullable.
func (e *Errors) NullNotAllowed(at jsontext.Pointer, name string) {
	e.AddBody(at.AppendToken(name), CodeNull, "null is not allowed here")
}

// CheckLen validates a string's length in Unicode code points, as JSON Schema counts them.
// A negative max means unbounded.
func CheckLen(e *Errors, in string, at jsontext.Pointer, s string, minLen, maxLen int) {
	if minLen <= 0 && maxLen < 0 {
		return
	}
	n := utf8.RuneCountInString(s)
	if n < minLen {
		e.Add(in, at, CodeMinLength, "value is too short")
	}
	if maxLen >= 0 && n > maxLen {
		e.Add(in, at, CodeMaxLength, "value is too long")
	}
}

// CheckInt validates an integer's bounds.
func CheckInt(e *Errors, in string, at jsontext.Pointer, n, lo, hi int64) {
	if n < lo {
		e.Add(in, at, CodeMinimum, "value is below the minimum")
	}
	if n > hi {
		e.Add(in, at, CodeMaximum, "value is above the maximum")
	}
}

// CheckCount validates an array's item count or a map's property count. A negative max means unbounded.
func CheckCount(e *Errors, in string, at jsontext.Pointer, n, minCount, maxCount int, code string) {
	if n < minCount {
		e.Add(in, at, minCode(code), "too few items")
	}
	if maxCount >= 0 && n > maxCount {
		e.Add(in, at, code, "too many items")
	}
}

func minCode(code string) string {
	if code == CodeMaxItems {
		return CodeMinItems
	}
	return code
}

// CheckEmail accepts an addr-spec only: no display name, no angle brackets, no comments.
func CheckEmail(s string) bool {
	if len(s) == 0 || len(s) > 254 {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && a.Name == ""
}
