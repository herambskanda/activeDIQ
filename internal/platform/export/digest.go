package export

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"iter"
)

// Canonical form of the result digest (reports-2a spec §8.3, ADR-0010 rule 4, AC-50). It is defined once,
// here, and used by the run path (which stores the digest with the run), by every export format (which
// prints the stored digest in its About block) and by the tests that recompute it from the run's rows.
//
//	digest = SHA-256( uint32(len(columns)) ‖ frame(ColumnTag, id)… ‖ frame(tag, value)… for every cell of
//	                  every row, rows in run order, cells in column order )
//	frame  = tag (1 byte) ‖ length of value (4 bytes, big endian) ‖ value
//
// Every value is framed, so no concatenation is ambiguous: "ab"+"c" and "a"+"bc" differ. The value is the
// typed text form (UTF-8 as stored, base-10 integer, "true"/"false", RFC 3339 UTC with whole seconds, the
// enum's stable ID, canonical GUID, a list as length-prefixed elements). Absent, never and unknown each
// have their own tag and length 0, so a null differs from an empty string and a run whose inputs were
// missing never shares a digest with one where the value was absent. The digest is over typed values, so
// it does not change with CSV or XLSX formatting or the viewer's time zone.

// ColumnTag frames a column ID in the digest. It is not a cell tag.
const ColumnTag byte = 0xFF

// Typed is one value in canonical form: the type tag and the bytes after it. Only the report package
// builds one (report.Cell.Typed); the digest never sees a raw string.
type Typed struct {
	Tag   byte
	Value []byte
}

// Digester is the streaming form of Digest: feed rows in run order, then Sum.
type Digester struct{ h hash.Hash }

// NewDigester starts a digest over the exported columns, in their exported order.
func NewDigester(columns []string) *Digester {
	d := &Digester{h: sha256.New()}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(columns)))
	d.h.Write(n[:])
	for _, c := range columns {
		d.frame(ColumnTag, []byte(c))
	}
	return d
}

func (d *Digester) frame(tag byte, v []byte) {
	var hdr [5]byte
	hdr[0] = tag
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(v)))
	d.h.Write(hdr[:])
	d.h.Write(v)
}

// Row adds one row's cells.
func (d *Digester) Row(cells []Typed) {
	for _, c := range cells {
		d.frame(c.Tag, c.Value)
	}
}

// Sum returns the digest of everything added so far; the Digester may keep going.
func (d *Digester) Sum() [32]byte {
	var out [32]byte
	copy(out[:], d.h.Sum(nil))
	return out
}

// Digest is the canonical digest of a result: the exported column IDs in order, then every row.
func Digest(columns []string, rows iter.Seq[[]Typed]) [32]byte {
	d := NewDigester(columns)
	for r := range rows {
		d.Row(r)
	}
	return d.Sum()
}
