package run

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"

	"github.com/skenzeriq/activediq/internal/platform/report"
)

// digester is the streaming form of the canonical digest of spec §8.3: SHA-256 over the ordered column
// IDs, then every row's cells in run order, each value as tag (1 byte) ‖ length (4 bytes big-endian) ‖
// typed bytes. Absent, never and unknown have their own tags and length 0.
//
// B9 owns the one canonical implementation (export.Digest) and the vectors; until it lands this is the
// single place the run record's digest is computed, and B9 moves it. The framing here is the framing of
// §8.3, so the move changes no digest.
type digester struct{ h hash.Hash }

func newDigester(columns []string) *digester {
	d := &digester{h: sha256.New()}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(columns)))
	d.h.Write(n[:])
	for _, c := range columns {
		d.frame(0xFF, []byte(c))
	}
	return d
}

func (d *digester) frame(tag byte, v []byte) {
	var hdr [5]byte
	hdr[0] = tag
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(v)))
	d.h.Write(hdr[:])
	d.h.Write(v)
}

func (d *digester) row(cells []report.Cell) {
	for _, c := range cells {
		d.frame(c.DigestTag(), c.DigestValue())
	}
}

func (d *digester) sum() []byte { return d.h.Sum(nil) }
