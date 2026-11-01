package report

import "regexp"

// Ident is a SQL identifier (a table or column name) that report validates and never quotes:
// pre-quoting happens once, in reportsql.NewRegistry (P5 rule 3).
type Ident string

// DatasetID is "<owner>.<name>", for example "inventory.users".
type DatasetID string

// ColumnID is a stable column identifier. It appears in the API, in definitions and in digests, and
// is only ever a map key into a registry, never text in SQL.
type ColumnID string

// AnchorID names an anchor or a relation of a dataset; it is also the SQL alias of the relation.
type AnchorID string

// DefinitionID is a library definition ID in lower case ("usr-01").
type DefinitionID string

var (
	identPattern      = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	datasetIDPattern  = regexp.MustCompile(`^[a-z][a-z0-9]{1,30}\.[a-z][a-z0-9_]{1,40}$`)
	columnIDPattern   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	anchorIDPattern   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)
	definitionPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)
	paramNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	presetIDPattern   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// Valid reports whether i is a well-formed identifier.
func (i Ident) Valid() bool { return identPattern.MatchString(string(i)) }

// Valid reports whether d is a well-formed dataset ID.
func (d DatasetID) Valid() bool { return datasetIDPattern.MatchString(string(d)) }

// Owner is the part of the ID before the dot, the key of the package that owns the dataset.
func (d DatasetID) Owner() string {
	for i := 0; i < len(d); i++ {
		if d[i] == '.' {
			return string(d[:i])
		}
	}
	return ""
}

// Valid reports whether c is a well-formed column ID.
func (c ColumnID) Valid() bool { return columnIDPattern.MatchString(string(c)) }

// Valid reports whether a is a well-formed anchor ID.
func (a AnchorID) Valid() bool { return anchorIDPattern.MatchString(string(a)) }

// Valid reports whether d is a well-formed definition ID.
func (d DefinitionID) Valid() bool { return definitionPattern.MatchString(string(d)) }

// safeKey returns s when it is safe to put in an error path (a bare name), "?" otherwise, so an
// error never echoes request text.
func safeKey(s string) string {
	if len(s) <= 64 && paramNamePattern.MatchString(s) || len(s) <= 64 && presetIDPattern.MatchString(s) {
		return s
	}
	return "?"
}
