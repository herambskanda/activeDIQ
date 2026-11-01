package rights

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileBaselineStoreSaveThenLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "baseline.json")
	s := FileBaselineStore{p}
	if err := s.Save(&Baseline{VerificationID: "v1"}); err != nil {
		t.Fatal(err)
	}
	b, err := s.Load()
	if err != nil || b.VerificationID != "v1" {
		t.Fatalf("load: %v %+v", err, b)
	}
}

// Acceptance 2 (T-0537): a baseline another principal could read or write is refused with a typed error.
func TestFileBaselineStoreLoadRefusesWiderAccess(t *testing.T) {
	p := filepath.Join(t.TempDir(), "baseline.json")
	s := FileBaselineStore{p}
	if err := s.Save(&Baseline{VerificationID: "v1"}); err != nil {
		t.Fatal(err)
	}
	widenForTest(t, p)
	if _, err := s.Load(); !errors.Is(err, ErrBaselineUnsafe) {
		t.Fatalf("want ErrBaselineUnsafe, got %v", err)
	}
}

// A widened baseline is reported as tier0_baseline_missing with reason unsafe_acl, never adopted.
func TestEpochStateTreatsUnsafeBaselineAsMissing(t *testing.T) {
	d := t.TempDir()
	bp, rp := filepath.Join(d, "baseline.json"), filepath.Join(d, "records.log")
	s := FileBaselineStore{bp}
	if err := s.Save(&Baseline{VerificationID: "v1", Entries: []ReportedEntry{{GUID: "00000000-0000-0000-0000-000000000001", Source: SourceRunInput}}}); err != nil {
		t.Fatal(err)
	}
	widenForTest(t, bp)
	ep := NewEpochState(s, FileRecordSink{rp}, nil)
	if n, err := ep.Complete(context.Background(), "v2", nil); err != nil || n != 0 {
		t.Fatalf("complete: %d %v", n, err)
	}
	raw, err := os.ReadFile(rp)
	if err != nil || !strings.Contains(string(raw), `"reason":"unsafe_acl"`) {
		t.Fatalf("record: %v %q", err, raw)
	}
	if _, err := s.Load(); err != nil { // the replacement is created restricted again
		t.Fatalf("replacement baseline: %v", err)
	}
}
