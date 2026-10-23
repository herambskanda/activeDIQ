// Package canon implements adq-canon/1, the deterministic encoding the audit chain hashes (ADR-0005
// rule 11). A message is a sequence of fields, each uvarint(tag) uvarint(length) value. Tags are strictly
// increasing, varints are minimal, strings are exact UTF-8 bytes, UUIDs are 16 bytes, timestamps are int64
// microseconds UTC, lists keep their order, there are no maps and an absent field is omitted. The decoder
// refuses anything the encoder could not have produced, so one value has exactly one encoding.
//
// The package imports only the standard library: cmd/auditverify links it, and an auditor can write an
// independent verifier from the format alone.
package canon

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

// ErrNonCanonical is wrapped by every error the decoder and the typed readers return for input that is
// not the canonical form of any value.
var ErrNonCanonical = errors.New("canon: not canonical")

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrNonCanonical, fmt.Sprintf(format, a...))
}

// Encoder builds one message. Fields must be added in strictly increasing tag order; the first violation
// is kept and returned by Result.
type Encoder struct {
	buf  []byte
	last uint64
	any  bool
	err  error
}

func (e *Encoder) field(tag uint64, v []byte) {
	if e.err != nil {
		return
	}
	if tag == 0 || (e.any && tag <= e.last) {
		e.err = fmt.Errorf("canon: tag %d out of order", tag)
		return
	}
	e.any, e.last = true, tag
	e.buf = appendUvarint(e.buf, tag)
	e.buf = appendUvarint(e.buf, uint64(len(v)))
	e.buf = append(e.buf, v...)
}

// Bytes adds a raw byte string.
func (e *Encoder) Bytes(tag uint64, v []byte) { e.field(tag, v) }

// String adds a UTF-8 string. Invalid UTF-8 is refused.
func (e *Encoder) String(tag uint64, s string) {
	if !utf8.ValidString(s) {
		e.err = fmt.Errorf("canon: tag %d: invalid UTF-8", tag)
		return
	}
	e.field(tag, []byte(s))
}

// UUID adds a 16-byte UUID.
func (e *Encoder) UUID(tag uint64, u [16]byte) { e.field(tag, u[:]) }

// Uint adds an unsigned integer as a minimal varint.
func (e *Encoder) Uint(tag uint64, v uint64) { e.field(tag, appendUvarint(nil, v)) }

// Time adds a timestamp as int64 microseconds since the Unix epoch, UTC.
func (e *Encoder) Time(tag uint64, t time.Time) {
	us := t.UTC().UnixMicro()
	e.field(tag, appendUvarint(nil, zigzag(us)))
}

// Message adds a nested message.
func (e *Encoder) Message(tag uint64, m []byte) { e.field(tag, m) }

// List adds an ordered list of byte strings (each element is length-prefixed).
func (e *Encoder) List(tag uint64, items [][]byte) {
	var b []byte
	for _, it := range items {
		b = appendUvarint(b, uint64(len(it)))
		b = append(b, it...)
	}
	e.field(tag, b)
}

// Result returns the encoding, or the first error.
func (e *Encoder) Result() ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	return append([]byte(nil), e.buf...), nil
}

// Field is one decoded field.
type Field struct {
	Tag   uint64
	Value []byte
}

// Decode parses a message, refusing non-canonical input: out-of-order or repeated tags, non-minimal
// varints, truncation and trailing bytes.
func Decode(b []byte) ([]Field, error) {
	var out []Field
	var last uint64
	for len(b) > 0 {
		tag, n, err := readUvarint(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		if tag == 0 || (len(out) > 0 && tag <= last) {
			return nil, bad("tag %d out of order", tag)
		}
		ln, n, err := readUvarint(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		if ln > uint64(len(b)) {
			return nil, bad("tag %d truncated", tag)
		}
		out = append(out, Field{Tag: tag, Value: b[:ln:ln]})
		b = b[ln:]
		last = tag
	}
	return out, nil
}

// Get returns the value of tag in fields, which Decode returned in tag order.
func Get(fields []Field, tag uint64) ([]byte, bool) {
	for _, f := range fields {
		if f.Tag == tag {
			return f.Value, true
		}
	}
	return nil, false
}

// AsString reads a string value, refusing invalid UTF-8.
func AsString(v []byte) (string, error) {
	if !utf8.Valid(v) {
		return "", bad("invalid UTF-8")
	}
	return string(v), nil
}

// AsUUID reads a 16-byte UUID.
func AsUUID(v []byte) ([16]byte, error) {
	var u [16]byte
	if len(v) != 16 {
		return u, bad("uuid length %d", len(v))
	}
	copy(u[:], v)
	return u, nil
}

// AsUint reads a minimal varint that fills the whole value.
func AsUint(v []byte) (uint64, error) {
	x, n, err := readUvarint(v)
	if err != nil {
		return 0, err
	}
	if n != len(v) {
		return 0, bad("trailing bytes after integer")
	}
	return x, nil
}

// AsTime reads a timestamp written by Encoder.Time.
func AsTime(v []byte) (time.Time, error) {
	x, err := AsUint(v)
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMicro(unzigzag(x)).UTC(), nil
}

// AsList reads a list written by Encoder.List.
func AsList(v []byte) ([][]byte, error) {
	var out [][]byte
	for len(v) > 0 {
		ln, n, err := readUvarint(v)
		if err != nil {
			return nil, err
		}
		v = v[n:]
		if ln > uint64(len(v)) {
			return nil, bad("list element truncated")
		}
		out = append(out, v[:ln:ln])
		v = v[ln:]
	}
	return out, nil
}

func zigzag(x int64) uint64   { return uint64(x<<1) ^ uint64(x>>63) }
func unzigzag(u uint64) int64 { return int64(u>>1) ^ -int64(u&1) }

func appendUvarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// readUvarint reads a minimal LEB128 varint of at most 64 bits.
func readUvarint(b []byte) (uint64, int, error) {
	var x uint64
	for i := 0; i < len(b) && i < 10; i++ {
		c := b[i]
		if i == 9 && c > 1 {
			return 0, 0, bad("varint overflows 64 bits")
		}
		x |= uint64(c&0x7f) << (7 * uint(i))
		if c < 0x80 {
			if c == 0 && i > 0 {
				return 0, 0, bad("non-minimal varint")
			}
			return x, i + 1, nil
		}
	}
	if len(b) >= 10 {
		return 0, 0, bad("varint overflows 64 bits")
	}
	return 0, 0, bad("truncated varint")
}
