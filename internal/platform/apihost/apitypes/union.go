package apitypes

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
)

// ErrUnionVariants is returned when a sum type is encoded with zero or several variants set.
var ErrUnionVariants = errors.New("apitypes: a union value must have exactly one variant set")

// UnionKind finds the top-level "kind" member of a union value without decoding the rest. A missing
// kind, a wrong-case Kind or a non-string kind is a violation at prefix.
func UnionKind(prefix jsontext.Pointer, val jsontext.Value) (string, error) {
	bad := func(detail string) error {
		return &ViolationError{Violation{In: InBody, Pointer: prefix.AppendToken("kind"), Code: CodeKind, Detail: detail}}
	}
	if val.Kind() != '{' {
		return "", &ViolationError{Violation{In: InBody, Pointer: prefix, Code: CodeType, Detail: "expected an object"}}
	}
	dec := jsontext.NewDecoder(bytes.NewReader(val))
	if _, err := dec.ReadToken(); err != nil {
		return "", err
	}
	for dec.PeekKind() != '}' {
		name, err := dec.ReadToken()
		if err != nil {
			return "", err
		}
		if name.String() != "kind" {
			if err := dec.SkipValue(); err != nil {
				return "", err
			}
			continue
		}
		tok, err := dec.ReadToken()
		if err != nil {
			return "", err
		}
		if tok.Kind() != '"' {
			return "", bad("kind must be a string")
		}
		return tok.String(), nil
	}
	return "", bad("kind is missing")
}

// UnknownKind is the violation for a kind no variant has.
func UnknownKind(prefix jsontext.Pointer) error {
	return &ViolationError{Violation{In: InBody, Pointer: prefix.AppendToken("kind"), Code: CodeKind, Detail: "unknown kind"}}
}

// ViolationOf maps a decode error onto a violation: our own ViolationError, or v2's semantic error
// (a wrong JSON type), whose text is never returned to clients.
func ViolationOf(err error) (Violation, bool) {
	var ve *ViolationError
	if errors.As(err, &ve) {
		return ve.V, true
	}
	var se *json.SemanticError
	if errors.As(err, &se) {
		return Violation{In: InBody, Pointer: se.JSONPointer, Code: CodeType, Detail: "value has the wrong type"}, true
	}
	return Violation{}, false
}

// Rebase re-roots an error from decoding a nested value that was read on its own: its pointer is
// relative to that value, so prefix puts it back in the whole body.
func Rebase(prefix jsontext.Pointer, err error) error {
	if v, ok := ViolationOf(err); ok {
		v.Pointer = prefix + v.Pointer
		return &ViolationError{v}
	}
	return err
}

// ParseInt parses a decimal integer parameter.
func ParseInt(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }

// ParseBool accepts exactly "true" and "false".
func ParseBool(s string) (bool, error) {
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("not a boolean")
}
