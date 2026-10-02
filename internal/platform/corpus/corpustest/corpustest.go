// Package corpustest is the test kit every safe-primitive implementation uses to run the shared
// hostile-vector corpus (FF-SP4), to seed its fuzz targets (FF-SP5) and to check its constant argv
// (FF-SP8). A unit's test is one call:
//
//	func TestCorpus(t *testing.T) {
//		corpustest.Run(t, "go/ldapfilter", "ldapfilter", func(r corpus.Record) (corpus.Result, error) { … })
//	}
//
// The kit runs every runtime record of the unit, fails the test on any mismatch and on any record
// the handler skips, and writes the run report the FF-SP4 gate and the FF-SP6 oracles read. The
// gate runs the declared test itself (`make fitness-corpus`), so a test that is not run, or that
// reads another copy of the corpus, fails there.
package corpustest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
)

// ErrSkip is returned (or wrapped) by a handler for a record it cannot run. FF-SP4 fails on every
// skip: an implementation runs every runtime record of a unit it implements.
var ErrSkip = errors.New("record skipped")

// Skip builds a skip error with a reason.
func Skip(why string) error { return fmt.Errorf("%w: %s", ErrSkip, why) }

// Handler runs one record against the implementation under test and returns what it produced.
type Handler func(r corpus.Record) (corpus.Result, error)

// Render is a result that is rendered text.
func Render(s string) corpus.Result { return corpus.Result{Render: &s} }

// BytesHex is a result of raw bytes, recorded as lower-case hex.
func BytesHex(b []byte) corpus.Result {
	s := fmt.Sprintf("%x", b)
	return corpus.Result{BytesHex: &s}
}

// Value is a structured result; it is compared as JSON.
func Value(v any) (corpus.Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return corpus.Result{}, err
	}
	return corpus.Result{Value: b}, nil
}

// Err is the typed error code the implementation returned (nothing was sent anywhere).
func Err(code string) corpus.Result { return corpus.Result{Error: &code} }

// Check runs every runtime record of f through h. It is pure (no *testing.T), so the gate's own
// tests can drive it.
func Check(impl string, f *corpus.File, h Handler) corpus.Report {
	rep := corpus.Report{Impl: impl, Unit: f.Unit, CorpusSHA: f.SHA256}
	for _, r := range f.Records {
		if !r.Runtime() {
			continue
		}
		res, err := runOne(h, r)
		switch {
		case errors.Is(err, ErrSkip):
			rep.Skipped = append(rep.Skipped, corpus.Skipped{ID: r.ID, Why: strings.TrimPrefix(err.Error(), ErrSkip.Error()+": ")})
		case err != nil:
			rep.Ran = append(rep.Ran, corpus.Ran{ID: r.ID, Why: "handler failed: " + err.Error()})
		default:
			why := Compare(r, res)
			rep.Ran = append(rep.Ran, corpus.Ran{ID: r.ID, OK: why == "", Actual: res, Why: why})
		}
	}
	return rep
}

func runOne(h Handler, r corpus.Record) (res corpus.Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return h(r)
}

// Compare returns "" when the result matches the record's expectation, else what differs.
func Compare(r corpus.Record, res corpus.Result) string {
	key, raw := r.ExpectKey()
	switch key {
	case "render":
		var want string
		_ = json.Unmarshal(raw, &want)
		if res.Render == nil {
			return fmt.Sprintf("expected render %q, implementation produced %s", want, describe(res))
		}
		if *res.Render != want {
			return fmt.Sprintf("render = %q, want %q", *res.Render, want)
		}
	case "bytes_hex":
		var want string
		_ = json.Unmarshal(raw, &want)
		if res.BytesHex == nil {
			return fmt.Sprintf("expected bytes %q, implementation produced %s", want, describe(res))
		}
		if !strings.EqualFold(*res.BytesHex, want) {
			return fmt.Sprintf("bytes = %q, want %q", *res.BytesHex, want)
		}
	case "value":
		if res.Value == nil {
			return fmt.Sprintf("expected a value, implementation produced %s", describe(res))
		}
		var a, b any
		if json.Unmarshal(raw, &a) != nil || json.Unmarshal(res.Value, &b) != nil || !reflect.DeepEqual(a, b) {
			return fmt.Sprintf("value = %s, want %s", res.Value, bytes.TrimSpace(raw))
		}
	case "error":
		var want string
		_ = json.Unmarshal(raw, &want)
		if res.Error == nil {
			return fmt.Sprintf("expected error %q, implementation produced %s", want, describe(res))
		}
		if *res.Error != want {
			return fmt.Sprintf("error = %q, want %q", *res.Error, want)
		}
	default:
		return "record has no expectation"
	}
	return ""
}

func describe(res corpus.Result) string {
	b, _ := json.Marshal(res)
	return string(b)
}

// Run loads the unit's corpus file from the repository, runs it through h and fails t for every
// mismatch and every skip. When the gate set SAFEPRIM_REPORT_DIR it also writes the report.
func Run(t *testing.T, impl, unit string, h Handler) {
	t.Helper()
	f := Load(t, unit)
	rep := Check(impl, f, h)
	if dir := os.Getenv(corpus.ReportDirEnv); dir != "" {
		if err := corpus.WriteReport(corpus.ReportPath(dir, "corpus", impl, unit), rep); err != nil {
			t.Fatalf("writing the corpus report: %v", err)
		}
	}
	for _, r := range rep.Ran {
		if !r.OK {
			t.Errorf("%s %s: %s", unit, r.ID, r.Why)
		}
	}
	for _, s := range rep.Skipped {
		t.Errorf("%s %s: skipped (%s): an implementation runs every record of a unit it implements (FF-SP4)", unit, s.ID, s.Why)
	}
	if len(rep.Ran) == 0 && len(rep.Skipped) == 0 {
		t.Errorf("unit %s has no runtime records to run", unit)
	}
}

// Load reads and validates one unit's corpus file, failing t when it is missing or invalid.
func Load(t testing.TB, unit string) *corpus.File {
	t.Helper()
	root, err := corpus.FindRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	f, err := corpus.Load(root, unit)
	if err != nil {
		t.Fatalf("corpus %s: %v", unit, err)
	}
	return f
}
