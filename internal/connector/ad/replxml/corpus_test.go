package replxml

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

// decoders is the five public functions behind one signature, for table tests. Each returns the
// result as an any plus the error.
var decoders = map[string]func([]byte) (any, *DecodeError){
	"DecodeNeighbors":     func(b []byte) (any, *DecodeError) { v, e := DecodeNeighbors(b); return v, e },
	"DecodePendingOps":    func(b []byte) (any, *DecodeError) { v, e := DecodePendingOps(b); return v, e },
	"DecodeFailures":      func(b []byte) (any, *DecodeError) { v, e := DecodeFailures(b); return v, e },
	"DecodeAttrMetaData":  func(b []byte) (any, *DecodeError) { v, e := DecodeAttrMetaData(b); return v, e },
	"DecodeValueMetaData": func(b []byte) (any, *DecodeError) { v, e := DecodeValueMetaData(b); return v, e },
}

func readFile(t testing.TB, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// hostileWant is the exact code each committed hostile file must produce (every decoder: the
// documents are hostile for all five, and the root check never runs before the structural ones).
var hostileWant = map[string]Code{
	"attrs_17.xml":               CodeTooManyAttrs,
	"billion_laughs.xml":         CodeForbiddenDirective,
	"c0_control.xml":             CodeBadText,
	"cdata_outside_root.xml":     CodeMalformed,
	"deep_nest_10000.xml":        CodeTooDeep,
	"duplicate_element.xml":      CodeDuplicateElement,
	"elements_16000_64k.xml":     CodeTooManyElements,
	"elements_20001.xml":         CodeTooLarge,
	"empty.xml":                  CodeMalformed,
	"encoding_latin1.xml":        CodeBadEncoding,
	"external_entity_file.xml":   CodeForbiddenDirective,
	"external_entity_url.xml":    CodeForbiddenDirective,
	"invalid_utf8.xml":           CodeBadText,
	"nul.xml":                    CodeBadText,
	"oversize_64k_plus_1.xml":    CodeTooLarge,
	"parameter_entity.xml":       CodeForbiddenDirective,
	"processing_instruction.xml": CodeForbiddenPI,
	"text_node_1mib.xml":         CodeTooLarge,
	"text_node_2k.xml":           CodeTextTooLong,
	"trailing_second_root.xml":   CodeTrailingContent,
	"truncated.xml":              CodeMalformed,
	"undeclared_entity.xml":      CodeMalformed,
	"unknown_elements.xml":       CodeTooManyElements, // 2000 tiny elements in 9.5 KiB: over the allocation-derived cap
	"utf16_bom.xml":              CodeBadEncoding,
	"utf16_nobom.xml":            CodeBadEncoding,
}

func totalAlloc() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.TotalAlloc
}

// Test_replxml_hostile_corpus is RX3 (connector-contract fitness): every committed hostile file
// returns its expected DecodeError in under 100 ms, with allocation
// within 8 x the input plus the fixed decoder cost, from every decoder. The package imports no
// network or file code (TestPure), so no network or file access can occur.
func Test_replxml_hostile_corpus(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "hostile", "*.xml"))
	if len(files) != len(hostileWant) {
		t.Fatalf("corpus has %d files, expectation table %d", len(files), len(hostileWant))
	}
	for _, f := range files {
		name := filepath.Base(f)
		want, ok := hostileWant[name]
		if !ok {
			t.Errorf("%s: no expectation", name)
			continue
		}
		data := readFile(t, filepath.Join("hostile", name))
		for dn, dec := range decoders {
			t.Run(name+"/"+dn, func(t *testing.T) {
				before := totalAlloc()
				start := time.Now()
				v, e := dec(data)
				elapsed := time.Since(start)
				used := totalAlloc() - before
				if elapsed > 100*time.Millisecond {
					t.Errorf("took %v, limit 100ms", elapsed)
				}
				if bound := uint64(8*len(data) + allocSlack); len(data) <= MaxValueBytes && used > bound {
					t.Errorf("allocated %d bytes for %d-byte input (bound %d)", used, len(data), bound)
				}
				if len(data) > MaxValueBytes && used > allocSlack {
					t.Errorf("oversize input allocated %d bytes before refusal", used)
				}
				if e == nil {
					t.Fatalf("want %s, decoded %+v", want, v)
				}
				if e.Code != want && !(e.Code == CodeBadRoot) {
					t.Errorf("code %s, want %s", e.Code, want)
				}
				if !reflect.ValueOf(v).IsZero() {
					t.Errorf("fields populated on error: %+v", v)
				}
			})
		}
	}
}
