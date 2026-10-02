package gentime

import (
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
)

const rfc3339 = "2006-01-02T15:04:05.999999999Z07:00"

func TestCorpus(t *testing.T) {
	corpustest.Run(t, "go/attr-gentime", "attr.gentime", func(r corpus.Record) (corpus.Result, error) {
		in, err := r.Arg("value")
		if err != nil {
			return corpus.Result{}, err
		}
		switch r.Call {
		case "Parse", "ParseUTCTime":
			parse := Parse
			if r.Call == "ParseUTCTime" {
				parse = ParseUTCTime
			}
			tm, err := parse(in.Text())
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.Render(tm.Format(rfc3339)), nil
		case "Format":
			tm, err := time.Parse(time.RFC3339Nano, in.Text())
			if err != nil {
				return corpus.Result{}, err
			}
			s, err := Format(tm)
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.Render(s), nil
		}
		return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
	})
}

func TestDecodeChoosesBySchemaSyntax(t *testing.T) {
	const text = "261002101112Z"
	gt, err := Decode(OMSyntaxGeneralizedTime, text)
	if err != nil || gt.Year() != 2610 {
		t.Fatalf("generalized: %v, %v", gt, err)
	}
	ut, err := Decode(OMSyntaxUTCTime, text)
	if err != nil || ut.Year() != 2026 {
		t.Fatalf("utc: %v, %v", ut, err)
	}
	if _, err := Decode(25, text); codec.Code(err) != UnknownSyntax {
		t.Fatalf("got %v", err)
	}
}

func TestFractionIsExact(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"2026100210.25Z", "2026-10-02T10:15:00Z"},  // quarter of an hour
		{"202610021011.5Z", "2026-10-02T10:11:30Z"}, // half a minute
		{"20261002101112.123456789Z", "2026-10-02T10:11:12.123456789Z"},
		{"20261002101112.1234567899999999999999Z", "2026-10-02T10:11:12.123456789Z"}, // truncated, never rounded up
		{"20261002101112.000000000000000000000001Z", "2026-10-02T10:11:12Z"},
	} {
		tm, err := Parse(c.in)
		if err != nil || tm.Format(rfc3339) != c.want {
			t.Errorf("Parse(%q) = %v, %v; want %s", c.in, tm, err, c.want)
		}
	}
}

func TestFormatRefusesFiveDigitYears(t *testing.T) {
	if _, err := Format(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)); codec.Code(err) != OutOfRange {
		t.Fatalf("got %v", err)
	}
	if s, err := Format(time.Date(2026, 10, 2, 15, 41, 12, 0, time.FixedZone("x", 5*3600+1800))); err != nil || s != "20261002101112.0Z" {
		t.Fatalf("Format = %q, %v (it must convert to UTC)", s, err)
	}
}

func FuzzGeneralizedTime(f *testing.F) {
	corpustest.Seed(f, "attr.gentime")
	f.Fuzz(func(t *testing.T, in []byte) {
		for _, parse := range []func(string) (time.Time, error){Parse, ParseUTCTime} {
			tm, err := parse(string(in))
			if err != nil {
				continue
			}
			s, err := Format(tm) // roundtrip: parse -> format -> parse (sub-seconds truncated by design)
			if err != nil {
				t.Fatalf("Format(%v): %v", tm, err)
			}
			checkEncoded(t, s)
			back, err := Parse(s)
			if err != nil || !back.Equal(tm.Truncate(time.Second)) {
				t.Fatalf("Parse(Format(%v)) = %v, %v", tm, back, err)
			}
		}
	})
}

// noUnescapedSpecial: the encoding is exactly 14 digits, ".0" and Z.
func checkEncoded(t *testing.T, s string) {
	t.Helper()
	if len(s) != len("20261002101112.0Z") || s[14:] != ".0Z" {
		t.Fatalf("encoding %q has the wrong shape", s)
	}
	corpustest.NoUnescapedSpecial(t, s[:14], "*()\\\x00<>,;\"+= #{}\r\n\t.Z-:")
	for i := 0; i < 14; i++ {
		if s[i] < '0' || s[i] > '9' {
			t.Fatalf("encoding %q holds %q", s, s[i])
		}
	}
}
