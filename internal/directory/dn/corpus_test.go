package dn

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
)

// Corpus handlers for testdata/safe-primitives/dn.jsonl (safe-primitives §4.5, FF-SP4). Each call
// below is the public API; a record names its inputs as text or hex and expects one outcome.

func corpusDN(r corpus.Record, name string, mode Mode) (DN, error) {
	in, err := r.Arg(name)
	if err != nil {
		return DN{}, err
	}
	return Parse(in.Text(), mode)
}

func corpusMode(r corpus.Record) (Mode, error) {
	in, err := r.Arg("mode")
	if err != nil {
		return 0, err
	}
	switch in.Text() {
	case "strict":
		return Strict, nil
	case "lenient":
		return Lenient, nil
	}
	return 0, corpustest.Skip("unknown mode " + in.Text())
}

func corpusRDNType(name string) (RDNType, error) {
	t, err := ParseRDNType(name)
	if err != nil {
		return 0, corpustest.Skip("unknown RDN type " + name)
	}
	return t, nil
}

func TestCorpus(t *testing.T) {
	corpustest.Run(t, "go/dn", "dn", func(r corpus.Record) (corpus.Result, error) {
		fail := func(err error) (corpus.Result, error) {
			if k := KindOf(err); k != "" {
				return corpustest.Err(string(k)), nil
			}
			return corpus.Result{}, err
		}
		switch r.Call {
		case "Child":
			parent, err := corpusDN(r, "parent", Strict)
			if err != nil {
				return corpus.Result{}, err
			}
			tn, err := r.Arg("type")
			if err != nil {
				return corpus.Result{}, err
			}
			typ, err := corpusRDNType(tn.Text())
			if err != nil {
				return corpus.Result{}, err
			}
			v, err := r.Arg("value")
			if err != nil {
				return corpus.Result{}, err
			}
			d, err := Child(parent, typ, v.Text())
			if err != nil {
				return fail(err)
			}
			return corpustest.Render(string(d.Render())), nil
		case "ParseRDNType":
			n, err := r.Arg("name")
			if err != nil {
				return corpus.Result{}, err
			}
			if _, err := ParseRDNType(n.Text()); err != nil {
				return fail(err)
			}
			return corpus.Result{}, fmt.Errorf("ParseRDNType(%q) accepted", n.Text())
		case "Parse":
			mode, err := corpusMode(r)
			if err != nil {
				return corpus.Result{}, err
			}
			d, err := corpusDN(r, "dn", mode)
			if err != nil {
				return fail(err)
			}
			return corpustest.Render(string(d.Render())), nil
		case "Equal":
			a, err := corpusDN(r, "a", Strict)
			if err != nil {
				return corpus.Result{}, err
			}
			b, err := corpusDN(r, "b", Strict)
			if err != nil {
				return corpus.Result{}, err
			}
			return corpustest.Value(Equal(a, b))
		case "IsDescendantOf":
			d, err := corpusDN(r, "dn", Strict)
			if err != nil {
				return corpus.Result{}, err
			}
			anc, err := corpusDN(r, "ancestor", Strict)
			if err != nil {
				return corpus.Result{}, err
			}
			return corpustest.Value(IsDescendantOf(d, anc))
		case "ParseObjectRef":
			in, err := r.Arg("ref")
			if err != nil {
				return corpus.Result{}, err
			}
			ref, err := ParseObjectRef(in.Text())
			if err != nil {
				return fail(err)
			}
			out, err := ref.ForRequest()
			if err != nil {
				return fail(err)
			}
			return corpustest.Render(out), nil
		case "ParseExtendedDN":
			in, err := r.Arg("ref")
			if err != nil {
				return corpus.Result{}, err
			}
			e, err := ParseExtendedDN(in.Text())
			if err != nil {
				return fail(err)
			}
			out := map[string]any{"guid": e.GUID.ObjectRef(), "dn": string(e.DN.Render())}
			if e.HasSID {
				out["sid"] = e.SID.String()
			}
			return corpustest.Value(out)
		}
		return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
	})
}

// neutralEscapes replaces every escape sequence (`\X` or `\HH`) of an escaped RDN value with a
// plain letter, leaving only what a DC would read as unescaped structure.
func neutralEscapes(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] != '\\' {
			b.WriteByte(v[i])
			continue
		}
		if i+2 < len(v) && isHex(v[i+1]) && isHex(v[i+2]) {
			i += 2
		} else {
			i++
		}
		b.WriteByte('x')
	}
	return b.String()
}

// FuzzDN (FF-SP5, unit dn): any value Child accepts renders with no unescaped special character and
// no unescaped edge space or '#', and parses (Strict) back to the identical value; any text Parse
// accepts is a fixed point of render then parse. Seeds come from the corpus.
func FuzzDN(f *testing.F) {
	corpustest.Seed(f, "dn")
	f.Fuzz(func(t *testing.T, in []byte) {
		if d, err := ChildMax(DN{}, CN, string(in), 0); err == nil {
			text := string(d.Render())
			data := neutralEscapes(strings.TrimPrefix(text, "CN="))
			if data == text {
				t.Fatalf("structure lost: %q", text)
			}
			corpustest.NoUnescapedSpecial(t, data, ",+\"<>;=\x00\n\r\\")
			if data[0] == '#' || data[0] == ' ' || data[len(data)-1] == ' ' {
				t.Fatalf("unescaped edge character in %q", text)
			}
			back, err := Parse(text, Strict)
			if err != nil || back.Len() != 1 || back.RDNs()[0].Value() != string(in) {
				t.Fatalf("roundtrip: %q -> %q -> %v", in, text, err)
			}
		}
		d, err := Parse(string(in), Strict)
		if err != nil {
			return
		}
		for _, r := range d.RDNs() {
			if !utf8.ValidString(r.Value()) {
				t.Fatalf("invalid UTF-8 value from %q", in)
			}
		}
		text := d.Render()
		back, err := Parse(text, Strict)
		if err != nil || !Equal(back, d) || back.Render() != text {
			t.Fatalf("not a fixed point: %q -> %q (%v)", in, text, err)
		}
	})
}
