package canon

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestRoundTripAndFixedBytes(t *testing.T) {
	var e Encoder
	e.String(1, "ab")
	e.Uint(2, 300)
	e.Time(3, time.UnixMicro(-5))
	e.UUID(4, [16]byte{1})
	e.List(5, [][]byte{[]byte("x"), nil, []byte("yz")})
	got, err := e.Result()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{1, 2, 'a', 'b', 2, 2, 0xac, 0x02, 3, 1, 9, 4, 16, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 6, 1, 'x', 0, 2, 'y', 'z'}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoding = %v\nwant       %v", got, want)
	}
	fs, err := Decode(got)
	if err != nil || len(fs) != 5 {
		t.Fatalf("decode = %v, %v", fs, err)
	}
	v, _ := Get(fs, 3)
	if tm, err := AsTime(v); err != nil || tm.UnixMicro() != -5 {
		t.Fatalf("time = %v, %v", tm, err)
	}
	v, _ = Get(fs, 5)
	l, err := AsList(v)
	if err != nil || len(l) != 3 || string(l[2]) != "yz" || len(l[1]) != 0 {
		t.Fatalf("list = %q, %v", l, err)
	}
	v, _ = Get(fs, 2)
	if n, err := AsUint(v); err != nil || n != 300 {
		t.Fatalf("uint = %d, %v", n, err)
	}
}

func TestEncoderRefusesDisorderAndBadUTF8(t *testing.T) {
	var e Encoder
	e.Uint(2, 1)
	e.Uint(2, 1)
	if _, err := e.Result(); err == nil {
		t.Fatal("repeated tag accepted")
	}
	var f Encoder
	f.String(1, "\xff")
	if _, err := f.Result(); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	var g Encoder
	g.Uint(0, 1)
	if _, err := g.Result(); err == nil {
		t.Fatal("tag 0 accepted")
	}
}

func TestDecoderRefusesNonCanonical(t *testing.T) {
	cases := map[string][]byte{
		"decreasing tags":     {2, 0, 1, 0},
		"repeated tags":       {1, 0, 1, 0},
		"tag zero":            {0, 0},
		"non-minimal tag":     {0x81, 0x00, 0},
		"non-minimal length":  {1, 0x80, 0x00},
		"truncated value":     {1, 3, 'a'},
		"truncated varint":    {1, 0x80},
		"overflowing varint":  {1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		"missing length byte": {1},
	}
	for name, in := range cases {
		if _, err := Decode(in); !errors.Is(err, ErrNonCanonical) {
			t.Errorf("%s: err = %v; want ErrNonCanonical", name, err)
		}
	}
	if _, err := AsUint([]byte{0x80, 0x00}); !errors.Is(err, ErrNonCanonical) {
		t.Error("non-minimal integer accepted")
	}
	if _, err := AsUint([]byte{1, 1}); !errors.Is(err, ErrNonCanonical) {
		t.Error("integer with trailing bytes accepted")
	}
	if _, err := AsString([]byte{0xc3}); !errors.Is(err, ErrNonCanonical) {
		t.Error("invalid UTF-8 string accepted")
	}
	if _, err := AsUUID([]byte{1}); !errors.Is(err, ErrNonCanonical) {
		t.Error("short uuid accepted")
	}
}

func FuzzDecodeReencodes(f *testing.F) {
	f.Add([]byte{1, 2, 'a', 'b'})
	f.Fuzz(func(t *testing.T, in []byte) {
		fs, err := Decode(in)
		if err != nil {
			return
		}
		var e Encoder
		for _, fl := range fs {
			e.Bytes(fl.Tag, fl.Value)
		}
		out, err := e.Result()
		if err != nil || !bytes.Equal(out, in) {
			t.Fatalf("accepted input does not re-encode identically: %v", in)
		}
	})
}
