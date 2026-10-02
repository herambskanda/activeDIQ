package apitypes

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
)

type optState uint8

const (
	optAbsent optState = iota
	optNull
	optSet
)

// Opt is a merge-patch member (RFC 7396) with three states: absent, null and a value. The zero
// value is absent, and omitzero drops it on encode. Generated PATCH bodies use Opt for every member.
type Opt[T any] struct {
	state optState
	val   T
}

// Some returns an Opt holding v.
func Some[T any](v T) Opt[T] { return Opt[T]{state: optSet, val: v} }

// Null returns an Opt that is present and null (the merge-patch "remove this member").
func Null[T any]() Opt[T] { return Opt[T]{state: optNull} }

// IsZero reports whether the member is absent. encoding/json/v2 uses it for omitzero.
func (o Opt[T]) IsZero() bool { return o.state == optAbsent }

// Present reports whether the member appeared on the wire, as null or as a value.
func (o Opt[T]) Present() bool { return o.state != optAbsent }

// IsNull reports whether the member was present and null.
func (o Opt[T]) IsNull() bool { return o.state == optNull }

// Value returns the value and true when the member carried one.
func (o Opt[T]) Value() (T, bool) { return o.val, o.state == optSet }

// Ptr returns a pointer to the held value, or nil when the member is absent or null. The generated
// validators and secret clean-up use it.
func (o *Opt[T]) Ptr() *T {
	if o.state != optSet {
		return nil
	}
	return &o.val
}

// UnmarshalJSONFrom decodes null, or a T through the caller's options.
func (o *Opt[T]) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	var zero T
	if d.PeekKind() == 'n' {
		if _, err := d.ReadValue(); err != nil {
			return err
		}
		*o = Opt[T]{state: optNull, val: zero}
		return nil
	}
	o.val = zero
	if err := json.UnmarshalDecode(d, &o.val); err != nil {
		return err
	}
	o.state = optSet
	return nil
}

// MarshalJSONTo encodes null or the value. An absent Opt is never encoded when the field has omitzero.
func (o Opt[T]) MarshalJSONTo(e *jsontext.Encoder) error {
	if o.state != optSet {
		return e.WriteToken(jsontext.Null)
	}
	return json.MarshalEncode(e, o.val)
}
