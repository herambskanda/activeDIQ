package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ManifestFile and LockFile live beside the corpus (testdata/safe-primitives/).
const (
	ManifestFile = "implementations.json"
	LockFile     = "records.lock.json"
)

// Manifest declares every implementation of every unit, every fuzz target and every constant-argv
// test. It is the list FF-SP4/5/8 run: an implementation that is not declared is not trusted, and
// Go code in a primitive's home that no entry declares fails the gate.
type Manifest struct {
	Implementations []Implementation `json:"implementations"`
	Fuzz            []FuzzTarget     `json:"fuzz"`
	FuzzExempt      []FuzzExempt     `json:"fuzzExempt,omitempty"`
}

// Implementation is one implementation of one or more units in one tier.
type Implementation struct {
	Name     string   `json:"name"`     // e.g. "go/ldapfilter", "rust/native-shared"
	Language string   `json:"language"` // "go" derives the commands; anything else gives "command"
	Tier     string   `json:"tier"`     // S, A, N, X or W (ADR-0001)
	Units    []string `json:"units"`
	Package  string   `json:"package"`          // go: the package directory holding the corpus test
	Covers   []string `json:"covers,omitempty"` // further package directories this implementation covers
	Test     string   `json:"test,omitempty"`   // go: the corpus test function, default TestCorpus
	ArgvTest string   `json:"argvTest,omitempty"`
	// Command and ArgvCommand run the corpus and the constant-argv tests for a non-Go
	// implementation (for example `cargo test -p shared corpus`). They write their reports to the
	// directory in $SAFEPRIM_REPORT_DIR, in the JSON shape of internal/platform/corpus/report.go.
	Command     []string `json:"command,omitempty"`
	ArgvCommand []string `json:"argvCommand,omitempty"`
}

// FuzzTarget is one corpus-seeded fuzz target.
type FuzzTarget struct {
	Implementation string   `json:"implementation"`
	Unit           string   `json:"unit"`
	Target         string   `json:"target"`
	Package        string   `json:"package,omitempty"` // go: defaults to the implementation's package
	Properties     []string `json:"properties"`
	// Command fuzzes a non-Go target; the token {fuzztime} is replaced by a Go duration string.
	Command []string `json:"command,omitempty"`
}

// FuzzExempt records why a declared unit has no fuzz target. The reason is printed on every run.
type FuzzExempt struct {
	Implementation string `json:"implementation"`
	Unit           string `json:"unit"`
	Reason         string `json:"reason"`
}

// Lock is the ratchet FF-SP4 uses to detect a record that disappears: every record ID ever in a
// unit, with its hostile flag, plus the explicit retirements.
type Lock struct {
	Units   map[string]map[string]bool `json:"units"` // unit -> record id -> hostile
	Retired []Retired                  `json:"retired,omitempty"`
}

// Retired is a record that was removed on purpose. FF-SP4 accepts the removal only when the
// superseding record exists (and is hostile when the retired one was).
type Retired struct {
	Unit         string `json:"unit"`
	ID           string `json:"id"`
	SupersededBy string `json:"supersededBy"`
	Reason       string `json:"reason"`
}

func loadManifest(corpusDir string) (*Manifest, error) {
	p := filepath.Join(corpusDir, ManifestFile)
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return &Manifest{}, nil
	}
	if err != nil {
		return nil, err
	}
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return &m, nil
}

func loadLock(corpusDir string) (*Lock, error) {
	p := filepath.Join(corpusDir, LockFile)
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return &Lock{Units: map[string]map[string]bool{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var l Lock
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if l.Units == nil {
		l.Units = map[string]map[string]bool{}
	}
	return &l, nil
}

func (m *Manifest) implementation(name string) *Implementation {
	for i := range m.Implementations {
		if m.Implementations[i].Name == name {
			return &m.Implementations[i]
		}
	}
	return nil
}

func (m *Manifest) declaresUnit(unit string) bool {
	for _, im := range m.Implementations {
		for _, u := range im.Units {
			if u == unit {
				return true
			}
		}
	}
	return false
}

func (im *Implementation) testName() string {
	if im.Test != "" {
		return im.Test
	}
	return "TestCorpus"
}

func (im *Implementation) hasUnit(unit string) bool {
	for _, u := range im.Units {
		if u == unit {
			return true
		}
	}
	return false
}
