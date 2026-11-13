package replxml

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// checkInvariants is the X8 oracle shared by the five fuzz targets: returns within 100 ms for input
// up to 64 KiB, nothing populated on error, and a successful output obeys X3 (bounded clean text)
// and X5 (typed fields: real times, canonical GUIDs).
func checkInvariants(t *testing.T, name string, dec func([]byte) (any, *DecodeError), data []byte) {
	t.Helper()
	before := totalAlloc()
	start := time.Now()
	v, e := dec(data)
	if d := time.Since(start); len(data) <= MaxValueBytes && d > 100*time.Millisecond {
		t.Fatalf("%s: %v for %d bytes", name, d, len(data))
	}
	// X6: allocation within 8 x the input. TotalAlloc is process-wide and the fuzz engine allocates
	// on its own goroutines, so small inputs are noise (a first version tripped on 500-byte inputs);
	// from 16 KiB up a regression is a multiple of the input and far above the 64 KiB allowance.
	if n := min(len(data), MaxValueBytes); n >= 16<<10 {
		if used, bound := totalAlloc()-before, uint64(8*n+64<<10); used > bound {
			t.Fatalf("%s: allocated %d bytes for %d-byte input (bound %d)", name, used, len(data), bound)
		}
	}
	rv := reflect.ValueOf(v)
	if e != nil {
		if !rv.IsZero() {
			t.Fatalf("%s: populated on error %s: %+v", name, e.Code, v)
		}
		if e.Error() != "replxml: "+string(e.Code) || e.Code == "" {
			t.Fatalf("%s: error text %q", name, e.Error())
		}
		return
	}
	if len(data) > MaxValueBytes {
		t.Fatalf("%s: accepted %d bytes", name, len(data))
	}
	walk(t, name, rv)
}

func walk(t *testing.T, name string, rv reflect.Value) {
	t.Helper()
	switch v := rv.Interface().(type) {
	case string:
		if len(v) > MaxText || !utf8.ValidString(v) {
			t.Fatalf("%s: bad display string (%d bytes)", name, len(v))
		}
		for i := 0; i < len(v); i++ {
			if !allowed(v[i]) {
				t.Fatalf("%s: control byte %#x in text", name, v[i])
			}
		}
		return
	case Time:
		switch v.Kind {
		case TimeUnset, TimeZero:
			if !v.At.IsZero() {
				t.Fatalf("%s: time %v on kind %d", name, v.At, v.Kind)
			}
		case TimeAt:
			if v.At.Year() < 1601 || v.At.Location() != time.UTC || v.At.IsZero() {
				t.Fatalf("%s: time %v", name, v.At)
			}
		default:
			t.Fatalf("%s: time kind %d", name, v.Kind)
		}
		return
	case Guid:
		if !v.set && v.b != [16]byte{} {
			t.Fatalf("%s: unset guid with bytes", name)
		}
		if v.set && len(v.String()) != 36 {
			t.Fatalf("%s: guid text", name)
		}
		return
	case U32:
		if !v.Set && v.V != 0 {
			t.Fatalf("%s: unset number with value", name)
		}
		return
	case U64:
		if !v.Set && v.V != 0 {
			t.Fatalf("%s: unset number with value", name)
		}
		return
	}
	if rv.Kind() == reflect.Struct {
		for i := 0; i < rv.NumField(); i++ {
			walk(t, name+"."+rv.Type().Field(i).Name, rv.Field(i))
		}
		return
	}
	if rv.Kind() == reflect.Int {
		if n := rv.Int(); n < 0 || n > int64(MaxElements) {
			t.Fatalf("%s: count %d", name, n)
		}
		return
	}
	t.Fatalf("%s: unexpected field kind %s: a decoded struct may hold only X5 types", name, rv.Kind())
}

func seed(f *testing.F) {
	for _, dir := range []string{"valid", "hostile"} {
		files, _ := filepath.Glob(filepath.Join("testdata", dir, "*.xml"))
		for _, p := range files {
			f.Add(readFile(f, filepath.Join(dir, filepath.Base(p))))
		}
	}
}

func FuzzDecodeNeighbors(f *testing.F) {
	seed(f)
	f.Fuzz(func(t *testing.T, b []byte) { checkInvariants(t, "DecodeNeighbors", decoders["DecodeNeighbors"], b) })
}
func FuzzDecodePendingOps(f *testing.F) {
	seed(f)
	f.Fuzz(func(t *testing.T, b []byte) { checkInvariants(t, "DecodePendingOps", decoders["DecodePendingOps"], b) })
}
func FuzzDecodeFailures(f *testing.F) {
	seed(f)
	f.Fuzz(func(t *testing.T, b []byte) { checkInvariants(t, "DecodeFailures", decoders["DecodeFailures"], b) })
}
func FuzzDecodeAttrMetaData(f *testing.F) {
	seed(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		checkInvariants(t, "DecodeAttrMetaData", decoders["DecodeAttrMetaData"], b)
	})
}
func FuzzDecodeValueMetaData(f *testing.F) {
	seed(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		checkInvariants(t, "DecodeValueMetaData", decoders["DecodeValueMetaData"], b)
	})
}

// Every corpus file and every table input also runs the oracle as a plain test, so a unit-test run
// (not only a fuzz run) enforces X3/X5 on the whole seed corpus.
func TestInvariants_over_corpus(t *testing.T) {
	for _, dir := range []string{"valid", "hostile"} {
		files, _ := filepath.Glob(filepath.Join("testdata", dir, "*.xml"))
		for _, p := range files {
			data := readFile(t, filepath.Join(dir, filepath.Base(p)))
			for dn, dec := range decoders {
				checkInvariants(t, dn+"/"+filepath.Base(p), dec, data)
			}
		}
	}
}

// Property: random valid values round-trip through the XML text (both directions of the codecs).
func TestRoundTrip_property(t *testing.T) {
	rng := rand.New(rand.NewSource(1721))
	for i := 0; i < 2000; i++ {
		var gb [16]byte
		rng.Read(gb[:])
		gb[0] |= 1 // a GUID is never the all-zero value
		text := fmt.Sprintf("%x-%x-%x-%x-%x", gb[0:4], gb[4:6], gb[6:8], gb[8:10], gb[10:16])
		if rng.Intn(2) == 0 {
			text = strings.ToUpper(text)
		}
		at := time.Date(1601+rng.Intn(8000), time.Month(1+rng.Intn(12)), 1+rng.Intn(28), rng.Intn(24), rng.Intn(60), rng.Intn(60), 0, time.UTC)
		if at.Equal(time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)) {
			continue
		}
		frac := ""
		if rng.Intn(2) == 0 {
			ns := rng.Intn(10_000_000) * 100
			at = at.Add(time.Duration(ns))
			frac = fmt.Sprintf(".%07d", ns/100)
		}
		stamp := at.Format("2006-01-02T15:04:05") + frac + "Z"
		usn := rng.Uint64()
		ver := rng.Uint32()
		doc := fmt.Sprintf("<DS_REPL_ATTR_META_DATA><pszAttributeName>attr%d</pszAttributeName><dwVersion>%d</dwVersion><ftimeLastOriginatingChange>%s</ftimeLastOriginatingChange><uuidLastOriginatingDsaInvocationID>%s</uuidLastOriginatingDsaInvocationID><usnOriginatingChange>%d</usnOriginatingChange><usnLocalChange>%d</usnLocalChange></DS_REPL_ATTR_META_DATA>", i, ver, stamp, text, usn, usn/2)
		m, e := DecodeAttrMetaData([]byte(doc))
		if e != nil {
			t.Fatalf("%s: %v", doc, e)
		}
		if m.Version.V != ver || m.OriginatingUSN.V != usn || m.LocalUSN.V != usn/2 || !m.OriginTime.At.Equal(at) ||
			m.OriginatingDSA.String() != strings.ToLower(text) || !reflect.DeepEqual(m.OriginatingDSA.Bytes(), gb[:]) {
			t.Fatalf("round trip failed for %s: %+v", doc, m)
		}
	}
}
