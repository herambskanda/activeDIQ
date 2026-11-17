package migration

import (
	"errors"
	"fmt"
)

// SourceKind is what an uploaded source is (spec e2-11 §7: the size limit depends on it).
type SourceKind string

// The source kinds of v1 file intake.
const (
	SourceCSV    SourceKind = "csv"
	SourceXLSX   SourceKind = "xlsx"
	SourceHTML   SourceKind = "html"
	SourceDBDump SourceKind = "db_dump"
)

// Size limits of spec §7. They are configuration ceilings: an operator may lower them, raising needs a
// change of these constants.
const (
	MaxReportBytes int64 = 256 << 20 // report, CSV, XLSX and HTML uploads
	MaxDumpBytes   int64 = 4 << 30   // database dump

	// MaxActivePerTenant and MaxActivePerUser are the quotas of spec §6.1.
	MaxActivePerTenant = 3
	MaxActivePerUser   = 1
)

// Errors of intake. None carries file content or a path.
var (
	ErrInvalid       = errors.New("migration: invalid input")
	ErrSizeLimit     = errors.New("migration: source is over its size limit")
	ErrQuotaUser     = errors.New("migration: the user already has an active migration job")
	ErrQuotaTenant   = errors.New("migration: the tenant already has the maximum number of active migration jobs")
	ErrNoSuchProject = errors.New("migration: no open project with that id in this tenant")
)

// Valid reports whether k is a known source kind.
func (k SourceKind) Valid() bool {
	switch k {
	case SourceCSV, SourceXLSX, SourceHTML, SourceDBDump:
		return true
	}
	return false
}

// Limit returns the size ceiling of the kind and the code recorded when it is hit.
func (k SourceKind) Limit() (bytes int64, code string) {
	if k == SourceDBDump {
		return MaxDumpBytes, "upload_size_4gib"
	}
	return MaxReportBytes, "upload_size_256mib"
}

// SizeGate is the gate of spec §7. It decides from the declared size alone (a Content-Length or a stat),
// before any byte of the source is read, hashed or parsed. It returns the limit code when the source is
// over the ceiling, and an error for an unknown kind or a negative size.
func SizeGate(k SourceKind, size int64) (limitHit string, err error) {
	if !k.Valid() {
		return "", fmt.Errorf("%w: unknown source kind", ErrInvalid)
	}
	if size < 0 {
		return "", fmt.Errorf("%w: negative size", ErrInvalid)
	}
	if max, code := k.Limit(); size > max {
		return code, nil
	}
	return "", nil
}
