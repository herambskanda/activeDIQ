// Package filter is a stand-in for the filter primitive (P1) in the generator's fixture: the type a
// shared wire form is bound to. It implements both v2 methods and no v1 method.
package filter

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
)

// Filter is the bound type of FilterAst.
type Filter struct{ Op string }

type wire struct {
	Op string `json:"op"`
}

// UnmarshalJSONFrom decodes the wire form strictly through the caller's options.
func (f *Filter) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	var w wire
	if err := json.UnmarshalDecode(d, &w); err != nil {
		return err
	}
	f.Op = w.Op
	return nil
}

// MarshalJSONTo writes the wire form.
func (f Filter) MarshalJSONTo(e *jsontext.Encoder) error {
	return json.MarshalEncode(e, wire{Op: f.Op})
}
