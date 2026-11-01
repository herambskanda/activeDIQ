package export_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/export"
)

func ty(tag byte, v string) export.Typed { return export.Typed{Tag: tag, Value: []byte(v)} }

func rows(rs ...[]export.Typed) func(func([]export.Typed) bool) {
	return func(yield func([]export.Typed) bool) {
		for _, r := range rs {
			if !yield(r) {
				return
			}
		}
	}
}

// ref is an independent, written-out encoder of the canonical form (spec §8.3), so the vectors below do
// not test the implementation against itself.
func ref(cols []string, rs [][]export.Typed) [32]byte {
	var b []byte
	b = append(b, 0, 0, 0, byte(len(cols)))
	fr := func(tag byte, v string) {
		b = append(b, tag, byte(len(v)>>24), byte(len(v)>>16), byte(len(v)>>8), byte(len(v)))
		b = append(b, v...)
	}
	for _, c := range cols {
		fr(0xFF, c)
	}
	for _, r := range rs {
		for _, c := range r {
			fr(c.Tag, string(c.Value))
		}
	}
	return sha256.Sum256(b)
}

func TestDigestVectors(t *testing.T) {
	cols := []string{"sam", "enabled"}
	one := [][]export.Typed{{ty(1, "ann"), ty(3, "true")}}
	// A pinned vector: the bytes are 00000002 ff00000003 "sam" ff00000007 "enabled" 01 00000003 "ann" 03 00000004 "true".
	// Computed once with an independent encoder (Python hashlib over the bytes above) and pinned here.
	const want = "af1cf5edbe3c6db183956db9acbe405396815aa45e59b2853dd55ba6f6233c22"
	got := export.Digest(cols, rows(one...))
	if got != ref(cols, one) {
		t.Fatalf("Digest differs from the reference encoder")
	}
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("digest = %x, want %s", got, want)
	}
}

func TestDigestIsSensitive(t *testing.T) {
	cols := []string{"a", "b"}
	base := [][]export.Typed{{ty(1, "x"), ty(1, "y")}, {ty(1, "z"), ty(2, "7")}}
	d0 := export.Digest(cols, rows(base...))
	if d0 != ref(cols, base) {
		t.Fatal("not canonical")
	}
	variants := map[string]struct {
		cols []string
		rows [][]export.Typed
	}{
		"value changes":        {cols, [][]export.Typed{{ty(1, "x"), ty(1, "Y")}, base[1]}},
		"row order changes":    {cols, [][]export.Typed{base[1], base[0]}},
		"column order changes": {[]string{"b", "a"}, base},
		"column renamed":       {[]string{"a", "c"}, base},
		"row dropped":          {cols, base[:1]},
		"type tag changes":     {cols, [][]export.Typed{{ty(5, "x"), ty(1, "y")}, base[1]}},
		"null vs empty":        {cols, [][]export.Typed{{ty(0, ""), ty(1, "y")}, base[1]}},
		"concat is framed":     {cols, [][]export.Typed{{ty(1, "xy"), ty(1, "")}, base[1]}},
	}
	// "null differs from empty string" needs the empty-string base to exist as well.
	empty := [][]export.Typed{{ty(1, ""), ty(1, "y")}}
	if export.Digest(cols, rows(empty...)) == export.Digest(cols, rows([][]export.Typed{{ty(0, ""), ty(1, "y")}}...)) {
		t.Fatal("absent and the empty string share a digest")
	}
	seen := map[[32]byte]string{d0: "base"}
	for name, v := range variants {
		d := export.Digest(v.cols, rows(v.rows...))
		if prev, dup := seen[d]; dup {
			t.Errorf("%s has the digest of %s", name, prev)
		}
		seen[d] = name
	}
}

func TestAbsentNeverUnknownDiffer(t *testing.T) {
	cols := []string{"c"}
	ds := map[string][32]byte{}
	for name, tag := range map[string]byte{"absent": 0, "never": 8, "unknown": 9} {
		d := export.Digest(cols, rows([]export.Typed{{Tag: tag}}))
		for other, od := range ds {
			if d == od {
				t.Errorf("%s and %s share a digest", name, other)
			}
		}
		ds[name] = d
	}
}

func TestDigesterStreamsLikeDigest(t *testing.T) {
	cols := []string{"a"}
	rs := [][]export.Typed{{ty(1, "p")}, {ty(1, "q")}}
	d := export.NewDigester(cols)
	for _, r := range rs {
		d.Row(r)
	}
	if d.Sum() != export.Digest(cols, rows(rs...)) {
		t.Fatal("streaming digest differs")
	}
	if d.Sum() != d.Sum() {
		t.Fatal("Sum is not repeatable")
	}
}

func TestUnknownCellIsVisibleText(t *testing.T) {
	r, err := export.Unknown().Resolve()
	if err != nil || r.Kind != export.KindText || r.Text != export.UnknownText {
		t.Fatalf("Unknown() = %+v, %v", r, err)
	}
	if n, _ := export.Never().Resolve(); n.Text == r.Text {
		t.Fatal("unknown and never read the same")
	}
}
