// Package corpus reads the shared safe-primitives hostile-vector corpus
// (testdata/safe-primitives/<unit>.jsonl, safe-primitives §8) and defines the run report that every
// implementation of a unit writes. It is standard-library only, so the Go test kit
// (corpustest), the FF-SP4 gate (tools/fitness/corpus) and the oracles share one reading of the
// files. Tier N (Rust) reads the same files and writes the same report; see
// knowledge/development/runbooks/safe-primitives-fitness.md.
package corpus

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// Dir is the corpus root relative to the repository root (blueprint §1.1).
const Dir = "testdata/safe-primitives"

// Kinds of record. A runtime record is one an implementation runs; the others are checked elsewhere.
const (
	KindRuntime = ""       // a call and an expected outcome: every implementation of the unit runs it
	KindStatic  = "static" // checked by FF-SP1 to FF-SP3 or FF-SP9/10 instead of a runtime call
	KindLab     = "lab"    // run in a spreadsheet application (FF-SP11)
	KindE2E     = "e2e"    // run by the server integration and Playwright suites
)

// Units is the FF-SP4 unit list of safe-primitives §8, in document order.
var Units = []string{
	"ldapfilter", "dn",
	"attr.guid", "attr.sid", "attr.filetime", "attr.gentime", "attr.flags", "attr.unicodepwd",
	"psx", "pslit", "proc", "sql",
	"cellsafe", "csv", "xlsx", "html", "mail", "pdf",
	"sd.read", "sd.write",
}

// MinHostile is the FF-SP4 floor: records with "hostile": true per unit.
const MinHostile = 10

var verifiedValues = map[string]bool{
	"doc": true, "samba": true, "windows": true, "samba+windows": true,
	"libreoffice": true, "excel": true, "libreoffice+excel": true,
}

// Record is one corpus line: one input.
type Record struct {
	ID        string                     `json:"id"`
	Primitive string                     `json:"primitive"`
	Call      string                     `json:"call,omitempty"`
	Args      map[string]json.RawMessage `json:"args,omitempty"`
	Expect    map[string]json.RawMessage `json:"expect,omitempty"`
	Hostile   *bool                      `json:"hostile"`
	Source    string                     `json:"source,omitempty"`
	Verified  string                     `json:"verified"`
	Kind      string                     `json:"kind,omitempty"`
}

// IsHostile reports the explicit hostile flag; an unset flag is a schema error, so false here.
func (r Record) IsHostile() bool { return r.Hostile != nil && *r.Hostile }

// Runtime reports whether implementations run this record.
func (r Record) Runtime() bool { return r.Kind == KindRuntime }

// ExpectKey returns the one expectation key of the record (render, bytes_hex, value or error) and its raw value.
func (r Record) ExpectKey() (string, json.RawMessage) {
	for _, k := range []string{"render", "bytes_hex", "value", "error"} {
		if v, ok := r.Expect[k]; ok {
			return k, v
		}
	}
	return "", nil
}

// Input is a corpus input value: {"utf8": text} or {"hex": bytes}. JSON cannot carry invalid UTF-8,
// lone surrogates or NUL, which is what the hex form is for.
type Input struct {
	Raw   []byte
	IsHex bool
}

// Text returns the input as a string (the bytes, whatever they hold).
func (i Input) Text() string { return string(i.Raw) }

// ValidUTF8 reports whether the bytes are well-formed UTF-8.
func (i Input) ValidUTF8() bool { return utf8.Valid(i.Raw) }

// Arg decodes the named argument as an Input. A bare JSON string counts as {"utf8": …}.
func (r Record) Arg(name string) (Input, error) {
	raw, ok := r.Args[name]
	if !ok {
		return Input{}, fmt.Errorf("record %s: no argument %q", r.ID, name)
	}
	return decodeInput(raw)
}

func decodeInput(raw json.RawMessage) (Input, error) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return Input{Raw: []byte(s)}, nil
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil || len(m) != 1 {
		return Input{}, errors.New(`input must be a string, {"utf8":…} or {"hex":…}`)
	}
	if v, ok := m["utf8"]; ok {
		return Input{Raw: []byte(v)}, nil
	}
	if v, ok := m["hex"]; ok {
		b, err := hex.DecodeString(v)
		if err != nil {
			return Input{}, fmt.Errorf("bad hex input: %w", err)
		}
		return Input{Raw: b, IsHex: true}, nil
	}
	return Input{}, errors.New(`input object must hold "utf8" or "hex"`)
}

// Inputs returns every {"utf8"}/{"hex"}/string argument of the record, in name order: the seeds a
// fuzz target starts from.
func (r Record) Inputs() [][]byte {
	names := make([]string, 0, len(r.Args))
	for n := range r.Args {
		names = append(names, n)
	}
	sort.Strings(names)
	var out [][]byte
	for _, n := range names {
		if in, err := decodeInput(r.Args[n]); err == nil {
			out = append(out, in.Raw)
		}
	}
	return out
}

// File is one unit's records and the digest of the file they came from.
type File struct {
	Unit    string
	Path    string
	SHA256  string
	Records []Record
}

// Hostile counts the records marked hostile.
func (f *File) Hostile() int {
	n := 0
	for _, r := range f.Records {
		if r.IsHostile() {
			n++
		}
	}
	return n
}

// RuntimeIDs returns the IDs implementations must run, in file order.
func (f *File) RuntimeIDs() []string {
	var ids []string
	for _, r := range f.Records {
		if r.Runtime() {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

// UnitFromFile maps "attr.guid.jsonl" to "attr.guid".
func UnitFromFile(name string) (string, bool) {
	u, ok := strings.CutSuffix(filepath.Base(name), ".jsonl")
	return u, ok
}

// IsUnit reports whether name is on the FF-SP4 unit list.
func IsUnit(name string) bool {
	for _, u := range Units {
		if u == name {
			return true
		}
	}
	return false
}

// Load reads and validates <root>/<unit>.jsonl. Validation errors are returned together.
func Load(root, unit string) (*File, error) {
	p := filepath.Join(root, unit+".jsonl")
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	f := &File{Unit: unit, Path: p, SHA256: DigestHex(data)}
	var problems []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var r Record
		dec := json.NewDecoder(strings.NewReader(text))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			problems = append(problems, fmt.Sprintf("%s:%d: %v", p, line, err))
			continue
		}
		for _, pr := range validateRecord(unit, r) {
			problems = append(problems, fmt.Sprintf("%s:%d: %s", p, line, pr))
		}
		f.Records = append(f.Records, r)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	seen := map[string]bool{}
	for _, r := range f.Records {
		if seen[r.ID] {
			problems = append(problems, fmt.Sprintf("%s: duplicate record id %s", p, r.ID))
		}
		seen[r.ID] = true
	}
	if len(problems) > 0 {
		return f, errors.New(strings.Join(problems, "\n"))
	}
	return f, nil
}

func validateRecord(unit string, r Record) []string {
	var ps []string
	id := r.ID
	if id == "" {
		return []string{"record has no id"}
	}
	if r.Primitive == "" {
		ps = append(ps, id+`: "primitive" is required`)
	}
	if r.Hostile == nil {
		ps = append(ps, id+`: "hostile" must be written explicitly as true or false; it is never inferred`)
	}
	if !verifiedValues[r.Verified] {
		ps = append(ps, fmt.Sprintf(`%s: "verified" is %q; want doc, samba, windows, samba+windows, libreoffice, excel or libreoffice+excel`, id, r.Verified))
	}
	switch r.Kind {
	case KindRuntime:
		if r.Call == "" {
			ps = append(ps, id+`: a runtime record needs a "call"`)
		}
		if len(r.Expect) != 1 {
			ps = append(ps, id+`: "expect" must hold exactly one of render, bytes_hex, value, error`)
		} else if k, _ := r.ExpectKey(); k == "" {
			ps = append(ps, id+`: "expect" key is none of render, bytes_hex, value, error`)
		}
	case KindStatic, KindLab, KindE2E:
	default:
		ps = append(ps, fmt.Sprintf(`%s: "kind" is %q; want static, lab or e2e (or none for a runtime record)`, id, r.Kind))
	}
	for n, raw := range r.Args {
		var probe any
		if err := json.Unmarshal(raw, &probe); err != nil {
			ps = append(ps, fmt.Sprintf("%s: argument %q: %v", id, n, err))
		}
	}
	return ps
}

// LoadAll loads every <unit>.jsonl under root. A file whose name is not on the unit list is an error
// (a typo would otherwise hide a unit from the gate). A missing root is an empty corpus.
func LoadAll(root string) (map[string]*File, []string, error) {
	ents, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]*File{}, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	out := map[string]*File{}
	var problems []string
	for _, e := range ents {
		unit, ok := UnitFromFile(e.Name())
		if e.IsDir() || !ok {
			continue
		}
		if !IsUnit(unit) {
			problems = append(problems, fmt.Sprintf("%s: %q is not an FF-SP4 unit (safe-primitives §8: %s)", filepath.Join(root, e.Name()), unit, strings.Join(Units, ", ")))
			continue
		}
		f, err := Load(root, unit)
		if err != nil {
			problems = append(problems, strings.Split(err.Error(), "\n")...)
		}
		if f != nil {
			out[unit] = f
		}
	}
	return out, problems, nil
}

// DigestHex is the SHA-256 of data in lower-case hex.
func DigestHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// FindRoot walks up from dir to the directory holding go.mod and returns its corpus directory.
// SAFEPRIM_CORPUS overrides it (fixtures).
func FindRoot(dir string) (string, error) {
	if v := os.Getenv("SAFEPRIM_CORPUS"); v != "" {
		return v, nil
	}
	d, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return filepath.Join(d, filepath.FromSlash(Dir)), nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", errors.New("no go.mod above " + dir)
		}
		d = parent
	}
}

// Write rewrites a unit file with the records given, one JSON object per line (used by the lab
// oracles to update "verified"; nothing else edits the corpus mechanically).
func Write(path string, recs []Record) error {
	var buf bytes.Buffer
	for _, r := range recs {
		b, err := marshalLine(r)
		if err != nil {
			return err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func marshalLine(r Record) ([]byte, error) {
	return json.Marshal(r)
}

// MergeVerified combines the platform a record was already verified on with a new one:
// doc < samba, windows < samba+windows; the P7 spreadsheet values combine the same way.
func MergeVerified(old, add string) string {
	set := map[string]bool{}
	for _, s := range []string{old, add} {
		for _, p := range strings.Split(s, "+") {
			if p != "" && p != "doc" {
				set[p] = true
			}
		}
	}
	var parts []string
	for _, p := range []string{"samba", "windows", "libreoffice", "excel"} {
		if set[p] {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return "doc"
	}
	return strings.Join(parts, "+")
}
