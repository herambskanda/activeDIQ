package corpus

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// ReportDirEnv names the directory an implementation's corpus test writes its run reports to. The
// FF-SP4 gate sets it for the runs it starts; outside the gate nothing is written.
const ReportDirEnv = "SAFEPRIM_REPORT_DIR"

// Result is what one implementation produced for one record: the same four shapes as "expect".
type Result struct {
	Render   *string         `json:"render,omitempty"`
	BytesHex *string         `json:"bytes_hex,omitempty"`
	Value    json.RawMessage `json:"value,omitempty"`
	Error    *string         `json:"error,omitempty"`
}

// Ran is one record an implementation ran.
type Ran struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Actual Result `json:"actual"`
	Why    string `json:"why,omitempty"` // when not ok: what differed
}

// Skipped is one record an implementation did not run. FF-SP4 fails on any.
type Skipped struct {
	ID  string `json:"id"`
	Why string `json:"why"`
}

// Report is the outcome of one implementation running one unit: the evidence FF-SP4 reads and the
// outputs the FF-SP6 oracles check independently.
type Report struct {
	Impl      string    `json:"impl"`
	Unit      string    `json:"unit"`
	CorpusSHA string    `json:"corpus_sha256"` // digest of the unit file the run read
	Ran       []Ran     `json:"ran"`
	Skipped   []Skipped `json:"skipped,omitempty"`
}

// ArgvReport is the outcome of one FF-SP8 constant-argv run.
type ArgvReport struct {
	Impl       string   `json:"impl"`
	Requests   int      `json:"requests"`
	Mismatches []string `json:"mismatches,omitempty"`
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// ReportPath is where a report of the given kind ("corpus", "argv") for impl/unit goes in dir.
func ReportPath(dir, kind, impl, unit string) string {
	return filepath.Join(dir, kind+"-"+unsafeName.ReplaceAllString(impl, "_")+"-"+unsafeName.ReplaceAllString(unit, "_")+".json")
}

// WriteReport stores v as JSON at path, creating the directory.
func WriteReport(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// ReadReports reads every corpus report in dir.
func ReadReports(dir string) ([]Report, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "corpus-*.json"))
	if err != nil {
		return nil, err
	}
	var out []Report
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var r Report
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// ReadArgvReports reads every constant-argv report in dir.
func ReadArgvReports(dir string) ([]ArgvReport, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "argv-*.json"))
	if err != nil {
		return nil, err
	}
	var out []ArgvReport
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var r ArgvReport
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, r)
	}
	return out, nil
}
