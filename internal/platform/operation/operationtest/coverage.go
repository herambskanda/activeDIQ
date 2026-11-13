package operationtest

import (
	"bufio"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/operation"
)

// Record is one line of the coverage file: one Contract run of one Action.
type Record struct {
	Action  operation.ActionID `json:"action"`
	Version int                `json:"version"`
	Target  string             `json:"target"`
	Test    string             `json:"test"`   // the test that ran Contract
	Passed  bool               `json:"passed"` // no clause was violated
	Steps   int                `json:"steps"`  // steps the fixture's Plan produced
	// Exercised lists the clauses the run could really check. A clause an Action gave the harness
	// nothing to check (an Apply that changes nothing cannot be shown to drop a write) is absent.
	Exercised  []string  `json:"exercised"`
	Violations []string  `json:"violations,omitempty"` // clause names
	At         time.Time `json:"at"`
}

// CoverageEnv names the environment variable that overrides the coverage file's path.
const CoverageEnv = "ACTIVEDIQ_CONTRACT_COVERAGE"

// CoveragePath returns where Contract appends its records: $ACTIVEDIQ_CONTRACT_COVERAGE when set,
// otherwise build/operationtest/contract-coverage.jsonl under the module root (the directory
// holding go.mod, found by walking up from the test's working directory). build/ is git-ignored.
func CoveragePath() (string, error) {
	if p := os.Getenv(CoverageEnv); p != "" {
		return p, nil
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "build", "operationtest", "contract-coverage.jsonl"), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("operationtest: no go.mod above the working directory; set " + CoverageEnv)
		}
		dir = parent
	}
}

// appendRecord adds r to the file at path as one JSON line, in a single append so that test
// binaries of different packages running at once never interleave a line.
func appendRecord(path string, r Record) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// ReadCoverage reads every record of the coverage file at path. A missing file is an error: a
// check that finds no file must fail, not pass vacuously.
func ReadCoverage(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("operationtest: %s line %d: %w", path, n, err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// Ran returns the ActionIDs that have at least one record, sorted and unique.
func Ran(rs []Record) []operation.ActionID {
	seen := map[operation.ActionID]bool{}
	var out []operation.ActionID
	for _, r := range rs {
		if !seen[r.Action] {
			seen[r.Action] = true
			out = append(out, r.Action)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
