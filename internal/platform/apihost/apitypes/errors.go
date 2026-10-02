package apitypes

import (
	"encoding/json/jsontext"
	"fmt"
)

// Locations a Violation can point at.
const (
	InBody   = "body"
	InPath   = "path"
	InQuery  = "query"
	InHeader = "header"
)

// Violation codes. The set is closed: clients and the A7 corpus match on these strings.
const (
	CodeRequired      = "required"
	CodeNull          = "null"
	CodeUnknownMember = "unknown-member"
	CodeType          = "type"
	CodeFormat        = "format"
	CodeEnum          = "enum"
	CodePattern       = "pattern"
	CodeMinLength     = "min-length"
	CodeMaxLength     = "max-length"
	CodeMinimum       = "minimum"
	CodeMaximum       = "maximum"
	CodeMinItems      = "min-items"
	CodeMaxItems      = "max-items"
	CodeMaxProperties = "max-properties"
	CodeKind          = "kind"
	CodeConst         = "const"
)

// Violation is one schema violation. Detail is fixed text that never echoes the offending value:
// a rejected value may be a secret.
type Violation struct {
	In      string
	Pointer jsontext.Pointer // a JSON Pointer inside the body, or the parameter name for path, query and header
	Code    string
	Detail  string
}

// Errors collects every violation of one request (ADR-0004 rule 6 step 4: collect, never stop at
// the first). The zero value is ready to use.
type Errors struct{ list []Violation }

// Add records a violation.
func (e *Errors) Add(in string, ptr jsontext.Pointer, code, detail string) {
	e.list = append(e.list, Violation{In: in, Pointer: ptr, Code: code, Detail: detail})
}

// AddBody records a violation at a pointer inside the request body.
func (e *Errors) AddBody(ptr jsontext.Pointer, code, detail string) {
	e.Add(InBody, ptr, code, detail)
}

// Merge adds the violation a decoder reported.
func (e *Errors) Merge(v Violation) { e.list = append(e.list, v) }

// Len reports how many violations were collected.
func (e *Errors) Len() int {
	if e == nil {
		return 0
	}
	return len(e.list)
}

// All returns the collected violations in the order they were found.
func (e *Errors) All() []Violation {
	if e == nil {
		return nil
	}
	return e.list
}

// ViolationError is what a generated decoder returns when it must stop: an unknown member, a
// missing or unknown kind, a value of the wrong JSON type. apihost renders it as the validation
// problem. It never carries input text.
type ViolationError struct{ V Violation }

func (e *ViolationError) Error() string {
	return fmt.Sprintf("api: %s at %q: %s", e.V.Code, string(e.V.Pointer), e.V.Detail)
}

func violation(d *jsontext.Decoder, code, detail string) *ViolationError {
	return &ViolationError{Violation{In: InBody, Pointer: d.StackPointer(), Code: code, Detail: detail}}
}
