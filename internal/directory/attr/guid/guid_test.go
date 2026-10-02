package guid

import (
	"bytes"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
)

func TestCorpus(t *testing.T) {
	corpustest.Run(t, "go/attr-guid", "attr.guid", func(r corpus.Record) (corpus.Result, error) {
		in, err := r.Arg("value")
		if err != nil {
			return corpus.Result{}, err
		}
		switch r.Call {
		case "FromBytes":
			g, err := FromBytes(in.Raw)
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.Render(g.String()), nil
		case "Parse":
			g, err := Parse(in.Text())
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.BytesHex(g.Bytes()), nil
		case "Canonical":
			g, err := Parse(in.Text())
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.Render(g.String()), nil
		case "ObjectRef":
			g, err := Parse(in.Text())
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.Render(g.ObjectRef()), nil
		}
		return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
	})
}

// The octet string is mixed-endian (gotcha 24): Data1..Data3 little-endian, the rest as is.
func TestMixedEndianLayout(t *testing.T) {
	b := []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	g, err := FromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := g.String(), "12345678-9abc-def0-0123-456789abcdef"; got != want {
		t.Fatalf("String = %s, want %s", got, want)
	}
	if !bytes.Equal(g.Bytes(), b) {
		t.Fatalf("Bytes = %x, want %x", g.Bytes(), b)
	}
}

// Bytes returns a copy: a caller cannot change the identity through the slice.
func TestBytesIsACopy(t *testing.T) {
	g, _ := Parse("04030201-0605-0807-090a-0b0c0d0e0f10")
	b := g.Bytes()
	b[0] = 0xff
	if g.Bytes()[0] != 0x01 {
		t.Fatal("Bytes aliases the GUID")
	}
}

// GUID-16: a megabyte of hex digits and dashes is refused without work or allocation proportional to
// it: the allocations (the typed error) are the same as for a 40-character refusal.
func TestHostileLengthIsNotRead(t *testing.T) {
	big := strings.Repeat("0123456789abcdef-", 1<<20/17)
	small := strings.Repeat("a", 40)
	run := func(in string) float64 {
		return testing.AllocsPerRun(20, func() {
			if _, err := Parse(in); codec.Code(err) != BadFormat {
				t.Fatalf("got %v", err)
			}
		})
	}
	if b, s := run(big), run(small); b != s {
		t.Fatalf("Parse allocates %v times on 1 MiB but %v on 40 characters", b, s)
	}
}

func FuzzGUID(f *testing.F) {
	corpustest.Seed(f, "attr.guid")
	f.Fuzz(func(t *testing.T, in []byte) {
		if g, err := Parse(string(in)); err == nil { // roundtrip: text -> GUID -> text -> GUID
			s := g.String()
			g2, err := Parse(s)
			if err != nil || g2 != g {
				t.Fatalf("Parse(String()) = %v, %v; want %v", g2, err, g)
			}
			checkRendered(t, g)
		}
		if g, err := FromBytes(in); err == nil { // roundtrip: octets -> GUID -> octets
			if !bytes.Equal(g.Bytes(), in) {
				t.Fatalf("Bytes() = %x, want %x", g.Bytes(), in)
			}
			g2, err := Parse(g.String())
			if err != nil || g2 != g {
				t.Fatalf("Parse(String()) = %v, %v; want %v", g2, err, g)
			}
			checkRendered(t, g)
		}
	})
}

// noUnescapedSpecial: the text and the ObjectRef carry only hex digits and their own structure, so
// nothing in them can end a DN, a filter or an extended-DN reference early.
func checkRendered(t *testing.T, g GUID) {
	t.Helper()
	const specials = "*()\\\x00<>,;\"+= #{}\r\n\t"
	corpustest.NoUnescapedSpecial(t, g.String(), specials)
	ref := g.ObjectRef()
	if !strings.HasPrefix(ref, "<GUID=") || !strings.HasSuffix(ref, ">") {
		t.Fatalf("ObjectRef = %q", ref)
	}
	corpustest.NoUnescapedSpecial(t, ref[len("<GUID="):len(ref)-1], specials+"-")
}
