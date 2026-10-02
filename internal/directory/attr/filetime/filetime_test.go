package filetime

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
)

func TestCorpus(t *testing.T) {
	corpustest.Run(t, "go/attr-filetime", "attr.filetime", func(r corpus.Record) (corpus.Result, error) {
		in, err := r.Arg("value")
		if err != nil {
			return corpus.Result{}, err
		}
		attr := ""
		if a, err := r.Arg("attr"); err == nil {
			attr = a.Text()
		}
		switch r.Call {
		case "Decode":
			f, err := FieldFor(attr)
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			v, err := Decode(f, in.Text())
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.Value(v)
		case "DecodeInterval":
			f, err := IntervalFieldFor(attr)
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			i, err := DecodeInterval(f, in.Text())
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.Value(i)
		case "EncodeInstant":
			tm, err := time.Parse(time.RFC3339Nano, in.Text())
			if err != nil {
				return corpus.Result{}, err
			}
			v, err := FromTime(tm)
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			f, err := FieldFor(attr)
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			raw, err := f.Encode(v)
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.Render(raw), nil
		case "EncodePwdLastSet":
			return corpustest.Render(EncodePwdLastSet(in.Text() == "true")), nil
		}
		return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
	})
}

func TestBoundaryInstants(t *testing.T) {
	for _, c := range []struct {
		ticks int64
		want  string
	}{
		{1, "1601-01-01T00:00:00.0000001Z"},
		{MaxInstantTicks, "9999-12-31T23:59:59.9999999Z"},
	} {
		tm, ok := Value{Kind: KindInstant, Ticks: c.ticks}.Time()
		if !ok || tm.Format("2006-01-02T15:04:05.9999999Z07:00") != c.want {
			t.Errorf("ticks %d: %v", c.ticks, tm)
		}
		v, err := FromTime(tm)
		if err != nil || v.Ticks != c.ticks {
			t.Errorf("FromTime(%v) = %+v, %v; want ticks %d", tm, v, err, c.ticks)
		}
	}
	for _, tm := range []time.Time{
		time.Date(1600, 12, 31, 23, 59, 59, 0, time.UTC),
		time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC), // tick 0 is the sentinel, not an instant
		time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Unix(1<<62, 0),
	} {
		if _, err := FromTime(tm); codec.Code(err) != OutOfRange {
			t.Errorf("FromTime(%v) = %v, want OutOfRange", tm, err)
		}
	}
}

func TestIntervalDuration(t *testing.T) {
	d, ok := Interval{Ticks: 36288000000000}.Duration()
	if !ok || d != 42*24*time.Hour {
		t.Fatalf("got %v %v", d, ok)
	}
	if _, ok := (Interval{Forever: true}).Duration(); ok {
		t.Fatal("Forever has no duration")
	}
	if _, ok := (Interval{Ticks: 1<<63 - 1}).Duration(); ok {
		t.Fatal("a span beyond time.Duration must not wrap")
	}
}

func TestEncodeRefusals(t *testing.T) {
	for _, c := range []struct {
		f Field
		v Value
	}{
		{LastLogon, Value{Kind: KindNoValue}},
		{AccountExpires, Value{Kind: KindOutOfRange, Ticks: -1}},
		{LastLogon, Value{Kind: KindNever}},
		{AccountExpires, Value{Kind: KindMustChange}},
		{AccountExpires, Value{Kind: KindInstant, Ticks: 0}},
		{AccountExpires, Value{Kind: KindInstant, Ticks: MaxInstantTicks + 1}},
	} {
		if _, err := c.f.Encode(c.v); codec.Code(err) != NotEncodable {
			t.Errorf("Encode(%v, %+v) = %v, want NotEncodable", c.f, c.v, err)
		}
	}
	for _, c := range []struct {
		f IntervalField
		i Interval
	}{
		{LockoutDuration, Interval{}}, {MaxPwdAge, Interval{}}, {PlainInterval, Interval{Forever: true}}, {PlainInterval, Interval{Ticks: -1}},
	} {
		if _, err := c.f.EncodeInterval(c.i); codec.Code(err) != NotEncodable {
			t.Errorf("EncodeInterval(%v, %+v) = %v, want NotEncodable", c.f, c.i, err)
		}
	}
}

func FuzzFileTime(f *testing.F) {
	corpustest.Seed(f, "attr.filetime")
	fields := []Field{AccountExpires, PwdLastSet, LastLogon, LockoutTime, PasswordExpiryComputed}
	intervals := []IntervalField{MaxPwdAge, LockoutDuration, PlainInterval}
	f.Fuzz(func(t *testing.T, in []byte) {
		raw := string(in)
		for _, fld := range fields {
			v, err := Decode(fld, raw)
			if err != nil {
				continue
			}
			if v.Raw() != strconv.FormatInt(v.Ticks, 10) {
				t.Fatalf("Raw %q for ticks %d", v.Raw(), v.Ticks)
			}
			js, err := json.Marshal(v)
			if err != nil || !json.Valid(js) {
				t.Fatalf("Marshal = %s, %v", js, err)
			}
			if v.Kind == KindInstant { // noRoundTripLoss: instant -> time -> instant
				tm, _ := v.Time()
				if back, err := FromTime(tm); err != nil || back != v {
					t.Fatalf("FromTime(Time()) = %+v, %v; want %+v", back, err, v)
				}
			}
			enc, err := fld.Encode(v) // roundtrip: decode -> encode -> decode
			if err != nil {
				continue
			}
			checkRaw(t, enc)
			v2, err := Decode(fld, enc)
			if err != nil || v2.Kind != v.Kind || (v.Kind == KindInstant && v2.Ticks != v.Ticks) {
				t.Fatalf("Decode(Encode(%+v)) = %+v, %v", v, v2, err)
			}
		}
		for _, fld := range intervals {
			i, err := DecodeInterval(fld, raw)
			if err != nil {
				continue
			}
			if js, err := json.Marshal(i); err != nil || !json.Valid(js) {
				t.Fatalf("Marshal = %s, %v", js, err)
			}
			enc, err := fld.EncodeInterval(i)
			if err != nil {
				continue
			}
			checkRaw(t, enc)
			i2, err := DecodeInterval(fld, enc)
			if err != nil || i2 != i {
				t.Fatalf("DecodeInterval(EncodeInterval(%+v)) = %+v, %v", i, i2, err)
			}
		}
	})
}

// noUnescapedSpecial: an encoded value is an optional minus sign and ASCII digits, so it cannot
// carry a filter or DN metacharacter into a request.
func checkRaw(t *testing.T, enc string) {
	t.Helper()
	body := enc
	if len(body) > 0 && body[0] == '-' {
		body = body[1:]
	}
	if body == "" {
		t.Fatal("empty encoding")
	}
	for i := 0; i < len(body); i++ {
		if body[i] < '0' || body[i] > '9' {
			t.Fatalf("encoding %q holds %q", enc, body[i])
		}
	}
	corpustest.NoUnescapedSpecial(t, body, "*()\\\x00<>,;\"+= #{}\r\n\t")
}
