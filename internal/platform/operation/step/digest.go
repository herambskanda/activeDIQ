package step

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"

	"github.com/skenzeriq/activediq/internal/platform/authority"
)

// Digest is the SHA-256 of one planned write: operation kind, target, attributes and values. A Step
// authorises this write and no other (ADR-0005 rule 2); the write API recomputes the digest of the
// operation it is handed and refuses a mismatch.
type Digest [sha256.Size]byte

// Attr is one attribute of the planned write. A secret value is never hashed: only its presence is.
type Attr struct {
	Name   string
	Values []string
	Secret bool
}

// Compute returns the digest of (kind, target, attrs). Attributes are ordered by name and every field
// is length-prefixed, so no two different writes share an encoding.
func Compute(kind string, t authority.TargetRef, attrs []Attr) Digest {
	h := sha256.New()
	put := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	put("adq-step-digest/1")
	put(kind)
	for _, f := range []string{t.Connection, t.GUID, t.Class, t.Parent, t.RDN} {
		put(f)
	}
	sorted := append([]Attr(nil), attrs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, a := range sorted {
		put(a.Name)
		if a.Secret {
			put("secret")
			continue
		}
		put("plain")
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(a.Values)))
		h.Write(n[:])
		for _, v := range a.Values {
			put(v)
		}
	}
	var d Digest
	copy(d[:], h.Sum(nil))
	return d
}
