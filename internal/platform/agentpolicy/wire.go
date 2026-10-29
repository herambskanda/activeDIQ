package agentpolicy

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

// ErrMalformed is returned for bytes that are not exactly one canonical document. It names no field.
var ErrMalformed = errors.New("agentpolicy: malformed document")

type enc struct{ b []byte }

func (e *enc) u8(v uint8)   { e.b = append(e.b, v) }
func (e *enc) u32(v uint32) { e.b = binary.BigEndian.AppendUint32(e.b, v) }
func (e *enc) u64(v uint64) { e.b = binary.BigEndian.AppendUint64(e.b, v) }
func (e *enc) bytes(v []byte) {
	e.u32(uint32(len(v)))
	e.b = append(e.b, v...)
}
func (e *enc) str(v string) {
	e.u32(uint32(len(v)))
	e.b = append(e.b, v...)
}

// dec reads what enc wrote. The first failure sticks; callers check err once at the end.
type dec struct {
	b   []byte
	err error
}

func (d *dec) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || n > len(d.b) {
		d.err = ErrMalformed
		return nil
	}
	out := d.b[:n]
	d.b = d.b[n:]
	return out
}

func (d *dec) u8() uint8 {
	if p := d.take(1); p != nil {
		return p[0]
	}
	return 0
}

func (d *dec) u32() uint32 {
	if p := d.take(4); p != nil {
		return binary.BigEndian.Uint32(p)
	}
	return 0
}

func (d *dec) u64() uint64 {
	if p := d.take(8); p != nil {
		return binary.BigEndian.Uint64(p)
	}
	return 0
}

// bytes reads a length-prefixed value of at most max bytes. The bound is checked before any copy.
func (d *dec) bytes(max int) []byte {
	n := d.u32()
	if d.err != nil {
		return nil
	}
	if uint64(n) > uint64(max) {
		d.err = ErrMalformed
		return nil
	}
	p := d.take(int(n))
	if p == nil {
		return nil
	}
	return append([]byte(nil), p...)
}

func (d *dec) str(max int) string {
	b := d.bytes(max)
	if d.err == nil && !utf8.Valid(b) {
		d.err = ErrMalformed
	}
	return string(b)
}

// done reports ErrMalformed when decoding failed or bytes are left over: a document has one encoding.
func (d *dec) done() error {
	if d.err != nil {
		return d.err
	}
	if len(d.b) != 0 {
		return ErrMalformed
	}
	return nil
}
