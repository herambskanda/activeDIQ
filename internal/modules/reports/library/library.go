package library

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
)

//go:embed *.json LOCK crosswalk.tsv
var shipped embed.FS

// Shipped is the file system of the definitions compiled into the binary.
func Shipped() fs.FS { return shipped }

// Options says what the library validates its definitions against.
type Options struct {
	// Datasets are the EP-8 datasets by source form; every definition is resolved against its dataset
	// with each preset, so a broken definition stops start-up (contract 3.6).
	Datasets []report.Dataset
	// Registry holds the same datasets in their compiled form. Required: the run path needs both.
	Registry *reportsql.Registry
}

type entry struct {
	def  report.Definition
	sha  [32]byte
	file string
	ds   report.Dataset
	sql  reportsql.Dataset
}

// Library is the loaded, verified set of shipped definitions and the ManageEngine crosswalk. It is
// immutable after Load: there is no method that adds, changes or removes a definition (FR-03).
type Library struct {
	byID  map[report.DefinitionID][]entry // versions ascending
	order []report.DefinitionID
	cross []crossRow
}

var lockLine = regexp.MustCompile(`^([0-9a-f]{64})  (\S.*)$`)

// parseLock reads sha256sum-style lines: 64 hex digits, two spaces, a path relative to the library
// directory. Blank lines and lines starting with # are comments. The format and the path rules are the
// ones RP7 (tools/fitness/reports/lock.go) checks in CI.
func parseLock(raw []byte) (map[string]string, error) {
	entries := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := lockLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("library: LOCK line %d is not `<sha256 hex>  <path>`", n)
		}
		p := m[2]
		if p != path.Clean(p) || path.IsAbs(p) || strings.HasPrefix(p, "../") || p == "LOCK" || !strings.HasSuffix(p, ".json") {
			return nil, fmt.Errorf("library: LOCK line %d: %q is not a clean relative .json path", n, p)
		}
		if _, dup := entries[p]; dup {
			return nil, fmt.Errorf("library: LOCK line %d: %q is listed twice", n, p)
		}
		entries[p] = m[1]
	}
	return entries, sc.Err()
}

// Load reads every *.json under fsys, checks each against LOCK, decodes it strictly and resolves it
// against its dataset. It refuses, naming the file: a file that is not listed in LOCK; a listed file that
// is missing or whose SHA-256 differs; a file whose name is not <id>.v<version>.json; a duplicate
// (ID, version); a dataset that is not registered; a definition that does not Resolve with every
// preset; and a crosswalk that disagrees with the presets' ManageEngine names.
func Load(fsys fs.FS, o Options) (*Library, error) {
	if o.Registry == nil {
		return nil, errors.New("library: Options.Registry is required")
	}
	rawLock, err := fs.ReadFile(fsys, "LOCK")
	if err != nil {
		return nil, fmt.Errorf("library: no LOCK file: %w", err)
	}
	locked, err := parseLock(rawLock)
	if err != nil {
		return nil, err
	}
	files, err := fs.Glob(fsys, "*.json")
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	for p := range locked {
		if !slices.Contains(files, p) {
			return nil, fmt.Errorf("library: %s is listed in LOCK but missing: a shipped version is never deleted", p)
		}
	}
	datasets := map[report.DatasetID]report.Dataset{}
	for _, d := range o.Datasets {
		datasets[d.ID] = d
	}
	l := &Library{byID: map[report.DefinitionID][]entry{}}
	for _, f := range files {
		raw, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		want, ok := locked[f]
		switch {
		case !ok:
			return nil, fmt.Errorf("library: %s is not listed in LOCK", f)
		case want != hex.EncodeToString(sum[:]):
			return nil, fmt.Errorf("library: %s changed since it was locked: ship a new version as a new file (FR-03)", f)
		}
		def, err := Decode(raw)
		if err != nil {
			return nil, fmt.Errorf("library: %s: %w", f, err)
		}
		if def.FileName() != f {
			return nil, fmt.Errorf("library: %s holds %s, which must be named %s", f, def.Key(), def.FileName())
		}
		ds, ok := datasets[def.Dataset]
		if !ok {
			return nil, fmt.Errorf("library: %s: dataset %s is not registered", f, def.Dataset)
		}
		sqlDS, ok := o.Registry.Dataset(def.Dataset)
		if !ok {
			return nil, fmt.Errorf("library: %s: dataset %s is not in the SQL registry", f, def.Dataset)
		}
		if err := def.ValidateAgainst(ds); err != nil {
			return nil, fmt.Errorf("library: %s: %w", f, err)
		}
		if err := checkReasonCoverage(def, ds); err != nil {
			return nil, fmt.Errorf("library: %s: %w", f, err)
		}
		l.byID[def.ID] = append(l.byID[def.ID], entry{def: def, sha: sum, file: f, ds: ds, sql: sqlDS})
	}
	for id, es := range l.byID {
		sort.Slice(es, func(i, j int) bool { return es[i].def.Version < es[j].def.Version })
		for i, e := range es {
			if e.def.Version != i+1 {
				return nil, fmt.Errorf("library: %s has versions with a gap before %d", id, e.def.Version)
			}
		}
		l.order = append(l.order, id)
	}
	sort.Slice(l.order, func(i, j int) bool { return l.order[i] < l.order[j] })
	if l.cross, err = loadCrosswalk(fsys); err != nil {
		return nil, err
	}
	if err := l.checkCrosswalk(); err != nil {
		return nil, err
	}
	return l, nil
}

// checkReasonCoverage is the FR-14 guard for the reports that hide probable service accounts: a hidden
// group must be backed by a column that shows the reason, so a hidden row can be explained when shown.
func checkReasonCoverage(def report.Definition, ds report.Dataset) error {
	for _, p := range def.Presets {
		for _, h := range p.Hidden {
			if h.Locked {
				continue
			}
			if h.ID == "service_accounts" {
				cols := p.Columns
				if cols == nil {
					cols = def.Columns
				}
				if !slices.Contains(cols, "probable_service_account_reason") {
					return fmt.Errorf("preset %s hides probable service accounts but shows no reason column (spec 6.7)", p.ID)
				}
			}
		}
	}
	return nil
}

// Definition implements run.Catalog. Version 0 is the newest.
func (l *Library) Definition(id string, version int) (run.Definition, bool) {
	es := l.byID[report.DefinitionID(id)]
	if len(es) == 0 {
		return run.Definition{}, false
	}
	e := es[len(es)-1]
	if version != 0 {
		if version < 1 || version > len(es) {
			return run.Definition{}, false
		}
		e = es[version-1]
	}
	return run.Definition{Def: e.def, SHA256: e.sha, Dataset: e.ds, SQL: e.sql}, true
}

var _ run.Catalog = (*Library)(nil)

// Item is one library listing row: the newest version of a report.
type Item struct {
	Def    report.Definition
	SHA256 [32]byte
	File   string
}

// List returns the newest version of every shipped report, ordered by ID.
func (l *Library) List() []Item {
	out := make([]Item, 0, len(l.order))
	for _, id := range l.order {
		es := l.byID[id]
		e := es[len(es)-1]
		out = append(out, Item{Def: e.def, SHA256: e.sha, File: e.file})
	}
	return out
}

// Versions returns every shipped version of a report, oldest first.
func (l *Library) Versions(id report.DefinitionID) []report.Definition {
	var out []report.Definition
	for _, e := range l.byID[id] {
		out = append(out, e.def)
	}
	return out
}
