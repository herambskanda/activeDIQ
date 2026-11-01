// Command modules generates the table ownership map from the migrations (ADR-0003 rule 6 and its
// 2026-10-02 write-class amendment; blueprint §2). The owner key of a table is the second segment of
// the name of the migration that creates it (`NNNN_<owner>_<what>.sql`, pinned by migrations_test
// TestOwnerKeyMatchesTableOwner), and its write class is the `-- write-class: <table> config|system`
// line beside the CREATE TABLE. A partition (`CREATE TABLE … PARTITION OF <parent>`) takes its
// parent's class and may not declare one. The output is internal/platform/store/owners/owners.gen.tsv, data rather than Go source so that
// the guarded-table scans of ADR-0007 P8 and FF-KEY-2 need no exemption.
//
// The parser is deliberately strict: a CREATE TABLE form it cannot read, a table with no class, a class
// for a table the same file does not create, a table created twice and a DROP or RENAME of a table all
// fail generation rather than produce a map that differs from the schema.
package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

// Class is a table's write class (ADR-0005 rule 10).
type Class string

// The two write classes.
const (
	Config Class = "config"
	System Class = "system"
)

// Entry is one row of the ownership map.
type Entry struct {
	Table string
	Owner string
	Class Class
	File  string // the migration that creates the table; not emitted
}

var (
	fileName   = regexp.MustCompile(`^(\d{4})_([a-z0-9]+)_[a-z0-9_]+\.sql$`)
	classLine  = regexp.MustCompile(`^--\s*write-class:\s*(\S+)\s+(\S+)\s*$`)
	classMaybe = regexp.MustCompile(`(?i)^--\s*write-class\b`)
	// createAny finds any CREATE … TABLE so that a form createOK does not read is an error, not a gap.
	createAny = regexp.MustCompile(`(?i)\bCREATE\s+(?:(?:GLOBAL\s+|LOCAL\s+)?(?:TEMP|TEMPORARY)\s+|UNLOGGED\s+)?(?:FOREIGN\s+)?TABLE\b`)
	createOK  = regexp.MustCompile(`(?i)^\s*CREATE\s+TABLE\s+(?:public\.)?([a-z][a-z0-9_]*)\s*(\(|PARTITION\s+OF\s+(?:public\.)?([a-z][a-z0-9_]*)\b)`)
	dropTable = regexp.MustCompile(`(?i)\bDROP\s+TABLE\b`)
	alterName = regexp.MustCompile(`(?i)\bALTER\s+TABLE\b[^;]*\b(?:RENAME\s+TO|SET\s+SCHEMA)\b`)
)

// Parse reads every NNNN_*.sql in dir and returns the ownership entries sorted by table. Files are read in
// name order so the error for a duplicate names the earlier file.
func Parse(dir fs.FS) ([]Entry, error) {
	names, err := fs.Glob(dir, "*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	byTable := map[string]*Entry{}
	parent := map[string]string{} // partition -> parent
	var errs []string
	fail := func(f string, line int, format string, a ...any) {
		errs = append(errs, fmt.Sprintf("%s:%d: %s", f, line, fmt.Sprintf(format, a...)))
	}
	for _, name := range names {
		m := fileName.FindStringSubmatch(name)
		if m == nil {
			errs = append(errs, name+": not named NNNN_<owner>_<what>.sql")
			continue
		}
		owner := m[2]
		raw, err := fs.ReadFile(dir, name)
		if err != nil {
			return nil, err
		}
		classes := map[string]Class{}
		classAt := map[string]int{}
		created := map[string]int{}
		tag := "" // the open dollar-quote tag ($fn$, $$ …): text inside a function or DO body is not a statement
		for i, line := range strings.Split(string(raw), "\n") {
			n := i + 1
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "--") {
				if classMaybe.MatchString(trim) {
					cm := classLine.FindStringSubmatch(trim)
					if cm == nil {
						fail(name, n, "malformed write-class line %q; want `-- write-class: <table> config|system`", trim)
						continue
					}
					table, class := cm[1], Class(cm[2])
					if class != Config && class != System {
						fail(name, n, "table %s: write class %q is neither config nor system", table, class)
						continue
					}
					if _, dup := classes[table]; dup {
						fail(name, n, "table %s: write class declared twice (first at line %d)", table, classAt[table])
						continue
					}
					classes[table], classAt[table] = class, n
				}
				continue
			}
			code, inside := splitQuoted(line, &tag)
			if createAny.MatchString(inside) {
				fail(name, n, "CREATE TABLE inside a function or DO body is invisible to the ownership generator: %q", trim)
			}
			if k := strings.Index(code, "--"); k >= 0 {
				code = code[:k]
			}
			if createAny.MatchString(code) {
				cm := createOK.FindStringSubmatch(code)
				if cm == nil {
					fail(name, n, "a CREATE TABLE form the generator cannot read: %q (write `CREATE TABLE public.<name> (` or `… PARTITION OF public.<parent>`)", trim)
					continue
				}
				table := cm[1]
				if prev, dup := byTable[table]; dup {
					fail(name, n, "table %s is already created by %s", table, prev.File)
					continue
				}
				if _, dup := created[table]; dup {
					fail(name, n, "table %s is created twice in this file", table)
					continue
				}
				created[table] = n
				byTable[table] = &Entry{Table: table, Owner: owner, File: name}
				if cm[3] != "" {
					parent[table] = cm[3]
				}
				continue
			}
			if dropTable.MatchString(code) || alterName.MatchString(code) {
				fail(name, n, "DROP TABLE and table renames are not supported by the ownership generator: %q (extend tools/gen/modules first)", trim)
			}
		}
		for table, n := range classAt {
			if _, ok := created[table]; !ok {
				fail(name, n, "write class for %s, which this file does not create (declare it in the migration that does)", table)
			}
		}
		for table := range created {
			e := byTable[table]
			if p, isPart := parent[table]; isPart {
				if _, has := classes[table]; has {
					fail(name, created[table], "partition %s declares a write class; it takes its parent %s's", table, p)
				}
				continue // resolved below
			}
			c, ok := classes[table]
			if !ok {
				fail(name, created[table], "table %s has no `-- write-class: %s config|system` line", table, table)
				continue
			}
			e.Class = c
		}
	}
	for table, p := range parent {
		pe, ok := byTable[p]
		switch {
		case !ok:
			errs = append(errs, fmt.Sprintf("%s: partition %s names parent %s, which no migration creates", byTable[table].File, table, p))
		case pe.Owner != byTable[table].Owner:
			errs = append(errs, fmt.Sprintf("%s: partition %s (owner %s) has parent %s owned by %s", byTable[table].File, table, byTable[table].Owner, p, pe.Owner))
		case parent[p] != "":
			errs = append(errs, fmt.Sprintf("%s: partition %s has a partitioned parent %s that is itself a partition", byTable[table].File, table, p))
		default:
			byTable[table].Class = pe.Class
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, fmt.Errorf("the migrations do not yield an ownership map:\n  %s", strings.Join(errs, "\n  "))
	}
	out := make([]Entry, 0, len(byTable))
	for _, e := range byTable {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Table < out[j].Table })
	return out, nil
}

var dollar = regexp.MustCompile(`\$[A-Za-z_]*\$`)

// splitQuoted splits a line into the text outside dollar quotes and the text inside them, tracking the
// open tag across lines.
func splitQuoted(line string, tag *string) (outside, inside string) {
	var o, i strings.Builder
	rest := line
	for rest != "" {
		loc := dollar.FindStringIndex(rest)
		if *tag == "" {
			if loc == nil {
				o.WriteString(rest)
				break
			}
			o.WriteString(rest[:loc[0]])
			*tag = rest[loc[0]:loc[1]]
			rest = rest[loc[1]:]
			continue
		}
		end := strings.Index(rest, *tag)
		if end < 0 {
			i.WriteString(rest)
			break
		}
		i.WriteString(rest[:end])
		rest = rest[end+len(*tag):]
		*tag = ""
	}
	return o.String(), i.String()
}

// Render returns the owners.gen.tsv bytes for entries (as Parse returns them): a header comment, then one
// `table<TAB>owner<TAB>class` line per table. It is data, not Go source, on purpose: the map names every
// table, including the ones other code must never name (ADR-0007 P8 and FF-KEY-2 scan Go source for the
// key-custody tables), so the Go scans stay exact and unexempted.
func Render(entries []Entry) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("# Generated by tools/gen/modules from the migrations; DO NOT EDIT.\n")
	b.WriteString("# table<TAB>owner<TAB>write class. Read by internal/platform/store/owners (go:embed).\n")
	for _, e := range entries {
		if e.Class != Config && e.Class != System {
			return nil, fmt.Errorf("table %s has no write class", e.Table)
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\n", e.Table, e.Owner, e.Class)
	}
	return b.Bytes(), nil
}
