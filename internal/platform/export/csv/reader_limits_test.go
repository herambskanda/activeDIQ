package csv

import (
	"errors"
	"strings"
	"testing"
)

func TestReaderDoubledQuoteFieldLimit(t *testing.T) {
	in := `"` + strings.Repeat(`""`, 4096) + `"`
	r, _ := NewReader(strings.NewReader(in), Options{}, Limits{MaxFieldBytes: 100})
	if _, err := r.Row(); !errors.Is(err, ErrFieldTooLong) {
		t.Fatalf("want ErrFieldTooLong, got %v", err)
	}
}

func TestReaderRecordByteLimit(t *testing.T) {
	f := strings.Repeat("a", 1000)
	in := strings.TrimSuffix(strings.Repeat(f+",", 1000), ",")
	r, _ := NewReader(strings.NewReader(in), Options{}, Limits{MaxRecordBytes: 100000})
	if _, err := r.Row(); !errors.Is(err, ErrRecordTooLong) {
		t.Fatalf("want ErrRecordTooLong, got %v", err)
	}
	// a record under the cap, and the counter resets per record
	ok := strings.Repeat("a", 50) + "\n" + strings.Repeat("b", 50) + "\n"
	r, _ = NewReader(strings.NewReader(ok), Options{}, Limits{MaxRecordBytes: 60})
	for i := 0; i < 2; i++ {
		if _, err := r.Row(); err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
	}
}

func FuzzReaderLimits(f *testing.F) {
	f.Add(`"` + strings.Repeat(`""`, 50) + `"`)
	f.Add("a,b\n\"x\"\"y\",c\n")
	f.Fuzz(func(t *testing.T, s string) {
		r, _ := NewReader(strings.NewReader(s), Options{}, Limits{MaxFieldBytes: 16, MaxRecordBytes: 40, MaxFields: 8, MaxRows: 8})
		for {
			rec, err := r.Row()
			if err != nil {
				return
			}
			n := 0
			for _, c := range rec {
				if len(c) > 16 {
					t.Fatalf("field %d bytes exceeds limit", len(c))
				}
				n += len(c)
			}
			if n > 40 {
				t.Fatalf("record %d bytes exceeds limit", n)
			}
		}
	})
}
