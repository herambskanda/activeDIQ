package secretjson

import (
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
)

// body is the shape the corpus records decode into: a password member and a nested copy of itself.
type body struct {
	Password string `json:"password"`
	Nested   *body  `json:"nested"`
}

// code names the failure by the stable codes the corpus uses. The classification reads the decoder's
// own error text, which is the only place v2 says which rule fired; the test pins it per Go release.
func code(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "duplicate object member"):
		return "DuplicateMember"
	case strings.Contains(msg, "invalid surrogate pair"):
		return "InvalidUTF16"
	case strings.Contains(msg, "invalid UTF-8"):
		return "InvalidUTF8"
	case strings.Contains(msg, "unknown object member"):
		return "UnknownMember"
	}
	var syn *jsontext.SyntacticError
	if errors.As(err, &syn) {
		return "MalformedJSON"
	}
	var sem *jsonv2.SemanticError
	if errors.As(err, &sem) {
		return "WrongType"
	}
	return "Other"
}

func TestCorpus(t *testing.T) {
	corpustest.Run(t, "go/secretjson", "attr.unicodepwd", func(r corpus.Record) (corpus.Result, error) {
		in, err := r.Arg("body")
		if err != nil {
			return corpus.Result{}, err
		}
		if r.Call != "DecodeSecretBody" {
			return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
		}
		var v body
		if err := Decode(in.Raw, &v); err != nil {
			return corpustest.Err(code(err)), nil
		}
		return corpustest.Value(v)
	})
}

func FuzzSecretJSON(f *testing.F) {
	corpustest.Seed(f, "attr.unicodepwd")
	f.Fuzz(func(t *testing.T, in []byte) {
		var v body
		if err := Decode(in, &v); err != nil {
			if code(err) == "Other" {
				t.Fatalf("unclassified decode error: %v", err)
			}
			return
		}
		// roundtrip: what decodes re-encodes to a body that decodes to the same value, and the
		// decoded text is well-formed UTF-8 (a lone surrogate never becomes U+FFFD).
		for p := &v; p != nil; p = p.Nested {
			if !utf8.ValidString(p.Password) {
				t.Fatalf("decoded password is not valid UTF-8: %q", p.Password)
			}
		}
		out, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		// noUnescapedSpecial: the re-encoded body carries no raw control byte; they leave as escapes.
		corpustest.NoUnescapedSpecial(t, string(out), controlBytes)
		var v2 body
		if err := Decode(out, &v2); err != nil || !equal(v, v2) {
			t.Fatalf("Decode(Marshal(v)) = %+v, %v; want %+v", v2, err, v)
		}
	})
}

func equal(a, b body) bool {
	if a.Password != b.Password || (a.Nested == nil) != (b.Nested == nil) {
		return false
	}
	return a.Nested == nil || equal(*a.Nested, *b.Nested)
}

// controlBytes is every C0 control byte: JSON requires them escaped inside strings.
const controlBytes = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
