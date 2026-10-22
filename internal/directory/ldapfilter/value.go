package ldapfilter

import (
	"strconv"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/filetime"
	"github.com/skenzeriq/activediq/internal/directory/attr/gentime"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
)

// DN is a distinguished name rendered canonically by P2 (§4.2). The filter escapes it a second time,
// so a DN is never a free string here. internal/directory/dn implements it.
type DN interface {
	// CanonicalString returns the RFC 4514 text with every RDN-value escape applied.
	CanonicalString() string
}

type kind int

const (
	kString kind = iota + 1
	kBytes
	kGUID
	kSID
	kDN
	kInt32
	kInt64
	kFileTime
	kGenTime
	kBool
)

// Value is one typed assertion value. Constructors never fail; Render reports a bad value.
type Value struct {
	kind kind
	raw  []byte // the octets that are escaped into the filter
	err  error  // set when the typed constructor could not encode its input
}

// String is a Unicode string. NUL and invalid UTF-8 are refused at render (R3); binary goes via Bytes.
func String(s string) Value { return Value{kind: kString, raw: []byte(s)} }

// Bytes is an opaque octet string, for SynOctet attributes only.
func Bytes(b []byte) Value { return Value{kind: kBytes, raw: append([]byte(nil), b...)} }

// GUID is a 16-octet objectGUID in stored (mixed-endian) byte order, every octet escaped.
func GUID(g guid.GUID) Value { return Value{kind: kGUID, raw: g.Bytes()} }

// SID is a binary objectSid, every octet escaped.
func SID(s sid.SID) Value { return Value{kind: kSID, raw: s.Bytes()} }

// DNValue is a distinguished name: canonical DN text, then filter-escaped.
func DNValue(d DN) Value {
	if d == nil {
		return Value{kind: kDN, err: fail(InvalidValue)}
	}
	return Value{kind: kDN, raw: []byte(d.CanonicalString())}
}

// Int32 is a signed 32-bit integer in RFC 4517 decimal.
func Int32(i int32) Value { return Value{kind: kInt32, raw: strconv.AppendInt(nil, int64(i), 10)} }

// Int64 is a signed 64-bit integer in RFC 4517 decimal.
func Int64(i int64) Value { return Value{kind: kInt64, raw: strconv.AppendInt(nil, i, 10)} }

// FileTime is an instant as 100 ns ticks since 1601 (Integer8).
func FileTime(t time.Time) Value {
	v, err := filetime.FromTime(t)
	if err != nil {
		return Value{kind: kFileTime, err: fail(InvalidValue)}
	}
	return Value{kind: kFileTime, raw: strconv.AppendInt(nil, v.Ticks, 10)}
}

// GeneralizedTime is an instant in Generalized Time (syntax 2.5.5.11).
func GeneralizedTime(t time.Time) Value {
	s, err := gentime.Format(t)
	if err != nil {
		return Value{kind: kGenTime, err: fail(InvalidValue)}
	}
	return Value{kind: kGenTime, raw: []byte(s)}
}

// Bool is TRUE or FALSE.
func Bool(b bool) Value {
	if b {
		return Value{kind: kBool, raw: []byte("TRUE")}
	}
	return Value{kind: kBool, raw: []byte("FALSE")}
}

// accepts reports whether a value of this kind may be asserted against an attribute of the syntax.
func (v Value) accepts(s Syntax) bool {
	switch v.kind {
	case kString:
		return s == SynString
	case kBytes:
		return s == SynOctet
	case kGUID:
		return s == SynGUID
	case kSID:
		return s == SynSID
	case kDN:
		return s == SynDN
	case kInt32:
		return s == SynInt32 || s == SynInt64
	case kInt64, kFileTime:
		return s == SynInt64
	case kGenTime:
		return s == SynGenTime
	case kBool:
		return s == SynBool
	}
	return false
}

// check validates the value's octets: textual kinds must be well-formed UTF-8 without NUL.
func (v Value) check() error {
	if v.err != nil {
		return v.err
	}
	if v.kind == 0 {
		return fail(InvalidValue)
	}
	if len(v.raw) > MaxValueBytes {
		return fail(ValueTooLong)
	}
	switch v.kind {
	case kString, kDN:
		if err := checkText(v.raw); err != nil {
			return err
		}
	}
	if len(v.raw) == 0 {
		return fail(EmptyAssertion)
	}
	return nil
}
