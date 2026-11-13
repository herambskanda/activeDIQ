package replxml

import (
	"bytes"
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

// hostileRoot is the root element the committed hostile files are written with. Each decoder is
// given the file with this name rewritten to its own root, so that the structural refusal (not
// bad_root) is what every one of the five decoders must produce.
const hostileRoot = "DS_REPL_NEIGHBOR"

var decoderRoot = map[string]string{
	"DecodeNeighbors":     neighborSpec.root,
	"DecodePendingOps":    pendingOpSpec.root,
	"DecodeFailures":      failureSpec.root,
	"DecodeAttrMetaData":  attrMetaSpec.root,
	"DecodeValueMetaData": valueMetaSpec.root,
}

// decoderField is a known field of each structure, standing in for dwReplicaFlags (the neighbour
// field the duplicate_element file repeats).
var decoderField = map[string]string{
	"DecodeNeighbors":     "dwReplicaFlags",
	"DecodePendingOps":    "ulOptions",
	"DecodeFailures":      "cNumFailures",
	"DecodeAttrMetaData":  "dwVersion",
	"DecodeValueMetaData": "dwVersion",
}

// forDecoder rewrites a hostile file for one decoder: its root and field names, and padding so a
// shorter root name never shrinks an oversize file under the cap.
func forDecoder(raw []byte, dn string) []byte {
	out := bytes.ReplaceAll(raw, []byte(hostileRoot), []byte(decoderRoot[dn]))
	out = bytes.ReplaceAll(out, []byte("dwReplicaFlags"), []byte(decoderField[dn]))
	if len(out) < len(raw) {
		out = append(out, bytes.Repeat([]byte{' '}, len(raw)-len(out))...)
	}
	return out
}

// hostileWant is the exact code each committed hostile file must produce from every decoder (each
// given its own root; structural refusals come before the root check is ever relevant).
var hostileWant = map[string]Code{
	"attrs_17.xml":               CodeTooManyAttrs,
	"attrs_heavy_children.xml":   CodeTooManyAttrs, // 600 elements x 16 attributes in 63 KiB: 17x the input if decoded
	"attrs_7000_one_tag.xml":     CodeTooManyAttrs, // one start tag with 7,000 attributes: refused before encoding/xml allocates them
	"xmlns_heavy_children.xml":   CodeTooManyAttrs, // namespace declarations cost more than plain attributes
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
		raw := readFile(t, filepath.Join("hostile", name))
		for dn, dec := range decoders {
			data := forDecoder(raw, dn)
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
				if e.Code != want {
					t.Errorf("code %s, want %s", e.Code, want)
				}
				if !reflect.ValueOf(v).IsZero() {
					t.Errorf("fields populated on error: %+v", v)
				}
			})
		}
	}
}
