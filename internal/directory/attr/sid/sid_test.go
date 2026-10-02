package sid

import (
	"bytes"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
)

func TestCorpus(t *testing.T) {
	corpustest.Run(t, "go/attr-sid", "attr.sid", func(r corpus.Record) (corpus.Result, error) {
		in, err := r.Arg("value")
		if err != nil {
			return corpus.Result{}, err
		}
		switch r.Call {
		case "FromBytes":
			s, err := FromBytes(in.Raw)
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.Render(s.String()), nil
		case "Parse":
			s, err := Parse(in.Text())
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.BytesHex(s.Bytes()), nil
		case "Canonical":
			s, err := Parse(in.Text())
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.Render(s.String()), nil
		case "DomainRID":
			s, err := Parse(in.Text())
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			d, ok1 := s.DomainSID()
			rid, ok2 := s.RID()
			if !ok1 || !ok2 {
				return corpustest.Err("NoDomain"), nil
			}
			return corpustest.Value(map[string]any{"domain": d.String(), "rid": rid})
		}
		return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
	})
}

func TestNoDomainForASingleSubAuthority(t *testing.T) {
	s, err := Parse("S-1-5-18")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.DomainSID(); ok {
		t.Fatal("S-1-5-18 has no domain part")
	}
	if _, ok := s.RID(); ok {
		t.Fatal("S-1-5-18 has no RID")
	}
}

func TestMaximumSIDRoundTrips(t *testing.T) {
	text := "S-1-0xffffffffffff" + strings.Repeat("-4294967295", 15)
	s, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if s.String() != text {
		t.Fatalf("String = %s", s.String())
	}
	b := s.Bytes()
	if len(b) != 68 {
		t.Fatalf("len = %d", len(b))
	}
	s2, err := FromBytes(b)
	if err != nil || s2 != s {
		t.Fatalf("FromBytes(Bytes()) = %v, %v", s2, err)
	}
	if len(text) > maxTextLen {
		t.Fatalf("maxTextLen %d is smaller than the longest valid SID text %d", maxTextLen, len(text))
	}
}

func TestZeroSubAuthorityBytesRefused(t *testing.T) {
	if _, err := FromBytes([]byte{1, 0, 0, 0, 0, 0, 0, 5}); codec.Code(err) != NoSubAuthority {
		t.Fatalf("got %v", err)
	}
}

func FuzzSID(f *testing.F) {
	corpustest.Seed(f, "attr.sid")
	f.Fuzz(func(t *testing.T, in []byte) {
		if s, err := Parse(string(in)); err == nil { // roundtrip: text -> SID -> text -> SID
			s2, err := Parse(s.String())
			if err != nil || s2 != s {
				t.Fatalf("Parse(String()) = %v, %v; want %v", s2, err, s)
			}
			b2, err := FromBytes(s.Bytes())
			if err != nil || b2 != s {
				t.Fatalf("FromBytes(Bytes()) = %v, %v; want %v", b2, err, s)
			}
			checkRendered(t, s)
		}
		if s, err := FromBytes(in); err == nil { // roundtrip: octets -> SID -> octets
			if !bytes.Equal(s.Bytes(), in) {
				t.Fatalf("Bytes() = %x, want %x", s.Bytes(), in)
			}
			s2, err := Parse(s.String())
			if err != nil || s2 != s {
				t.Fatalf("Parse(String()) = %v, %v; want %v", s2, err, s)
			}
			checkRendered(t, s)
		}
	})
}

// noUnescapedSpecial: the text is S, x, hex digits, digits and dashes, nothing else.
func checkRendered(t *testing.T, s SID) {
	t.Helper()
	body := strings.NewReplacer("S-1-", "", "0x", "", "-", "").Replace(s.String())
	corpustest.NoUnescapedSpecial(t, body, "*()\\\x00<>,;\"+= #{}\r\n\t")
	for _, c := range body {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("String() %q holds %q", s.String(), c)
		}
	}
}
