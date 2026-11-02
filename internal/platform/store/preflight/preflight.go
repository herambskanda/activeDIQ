// Package preflight is the read-only check the server runs against the migration role's connection
// before it applies a single migration (ADR-0011 rule 4, T-1128). It refuses a database the product
// cannot be installed into, and says in plain words what the administrator must change, so an install
// never fails halfway through a migration with an obscure error.
//
// It checks:
//   - pg_trgm is available (the PostgreSQL contrib package is installed and, on a managed service,
//     allow-listed), or already installed in this database, and the migration role may create it;
//   - the database encoding is UTF8 (anything else is refused);
//   - the database ctype is not C/POSIX (only a warning: fuzzy matching degrades for non-Latin keys).
//
// Check issues only SELECTs: when it refuses, the database is unchanged.
package preflight

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Extension is the one extension the product's migrations create (ADR-0011 rule 4).
const Extension = "pg_trgm"

// Code identifies why Check refused.
type Code string

const (
	// CodeExtensionMissing: pg_trgm is not in pg_available_extensions and not installed.
	CodeExtensionMissing Code = "extension-missing"
	// CodeExtensionNotCreatable: pg_trgm is available but needs a superuser to create, and the
	// migration role is not one.
	CodeExtensionNotCreatable Code = "extension-not-creatable"
	// CodeEncoding: the database encoding is not UTF8.
	CodeEncoding Code = "encoding-not-utf8"
)

// Refusal is one reason the server will not migrate. Detail says what was found; Fix says what to do.
// Neither carries connection strings or credentials.
type Refusal struct {
	Code   Code
	Detail string
	Fix    string
}

func (r *Refusal) Error() string {
	return "refusing to migrate: " + r.Detail + " " + r.Fix
}

// Report is what a passing (or refusing) Check learned.
type Report struct {
	// ServerVersionNum is server_version_num, for example 160014.
	ServerVersionNum int
	// Encoding is the database encoding name, for example "UTF8".
	Encoding string
	// Warnings are conditions that do not stop the install, in plain words.
	Warnings []string
}

// Querier is the part of *pgx.Conn Check needs. It must be a connection as the migration owner role.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

const (
	versionSQL = `SELECT current_setting('server_version_num')::int`

	// One row: whether the extension can be had. creatable is true when its default version is trusted
	// or does not need a superuser; it is false when the extension is not available at all.
	extensionSQL = `SELECT
  EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = $1) AS available,
  EXISTS (SELECT 1 FROM pg_extension WHERE extname = $1) AS installed,
  COALESCE((SELECT v.trusted OR NOT v.superuser
              FROM pg_available_extension_versions v
              JOIN pg_available_extensions a ON a.name = v.name AND a.default_version = v.version
             WHERE v.name = $1), false) AS creatable,
  COALESCE((SELECT rolsuper FROM pg_roles WHERE rolname = current_user), false) AS is_super`

	// datlocprovider exists from PostgreSQL 15; datlocale (the built-in provider's locale) from 17.
	databaseSQL = `SELECT pg_encoding_to_char(encoding), datlocprovider::text, datctype, ''::text
  FROM pg_database WHERE datname = current_database()`
	databaseSQL17 = `SELECT pg_encoding_to_char(encoding), datlocprovider::text, datctype, COALESCE(datlocale, '')
  FROM pg_database WHERE datname = current_database()`
)

// Provider codes of pg_database.datlocprovider.
const (
	providerLibc    = "c"
	providerBuiltin = "b"
)

// Check reads the catalogs through q and returns a Report. When the install cannot proceed it returns
// the Report together with an error that unwraps (errors.As) to one or more *Refusal. An error that is
// not a *Refusal means the check itself could not run.
func Check(ctx context.Context, q Querier) (Report, error) {
	var rep Report
	if err := q.QueryRow(ctx, versionSQL).Scan(&rep.ServerVersionNum); err != nil {
		return rep, fmt.Errorf("preflight: read the server version: %w", err)
	}

	var refusals []error

	var available, installed, creatable, isSuper bool
	if err := q.QueryRow(ctx, extensionSQL, Extension).Scan(&available, &installed, &creatable, &isSuper); err != nil {
		return rep, fmt.Errorf("preflight: read the extension catalog: %w", err)
	}
	switch {
	case installed:
		// Already in this database: the migration's CREATE EXTENSION IF NOT EXISTS is a no-op.
	case !available:
		refusals = append(refusals, &Refusal{
			Code: CodeExtensionMissing,
			Detail: "the PostgreSQL extension pg_trgm is not available on this server " +
				"(it is not listed in pg_available_extensions).",
			Fix: "Install the PostgreSQL \"contrib\" package that matches this server's major version " +
				"(on Red Hat family systems that is postgresql<N>-contrib; on Debian and Ubuntu pg_trgm ships in the " +
				"postgresql-<N> server package [UNVERIFIED per distribution]) and restart PostgreSQL if the packager asks for it. " +
				"On a managed PostgreSQL service, allow-list pg_trgm in the service's extension settings. " +
				"Nothing has been changed; start activeDIQ again afterwards.",
		})
	case !creatable && !isSuper:
		refusals = append(refusals, &Refusal{
			Code: CodeExtensionNotCreatable,
			Detail: "pg_trgm is available but this server only lets a superuser create it, " +
				"and the migration role is not a superuser.",
			Fix: "Ask a database administrator to run CREATE EXTENSION pg_trgm in the activeDIQ database as a superuser, " +
				"then start activeDIQ again. Nothing has been changed.",
		})
	}

	dbSQL := databaseSQL
	if rep.ServerVersionNum >= 170000 {
		dbSQL = databaseSQL17
	}
	var provider, ctype, locale string
	if err := q.QueryRow(ctx, dbSQL).Scan(&rep.Encoding, &provider, &ctype, &locale); err != nil {
		return rep, errors.Join(append(refusals, fmt.Errorf("preflight: read the database encoding: %w", err))...)
	}
	if rep.Encoding != "UTF8" {
		refusals = append(refusals, &Refusal{
			Code:   CodeEncoding,
			Detail: fmt.Sprintf("the database encoding is %s, but activeDIQ needs UTF8.", rep.Encoding),
			Fix: "Create the activeDIQ database with ENCODING 'UTF8' (a database's encoding cannot be changed in place) " +
				"and point activeDIQ at it. Nothing has been changed.",
		})
	} else if weak := weakCtype(provider, ctype, locale); weak != "" {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf(
			"the database character classification is %s: fuzzy search still works for Latin text, "+
				"but not for Cyrillic, Greek or CJK names. Create the database with a UTF-8 locale (for example en_US.UTF-8 or C.UTF-8) to fix that.", weak))
	}

	return rep, errors.Join(refusals...)
}

// weakCtype names the C/POSIX classification the database uses, or "" when it is a Unicode-aware one.
// The ICU provider is not judged: its classification is not read from datctype.
func weakCtype(provider, ctype, locale string) string {
	switch provider {
	case providerLibc:
		if isC(ctype) {
			return strings.ToUpper(ctype)
		}
	case providerBuiltin:
		if isC(locale) {
			return strings.ToUpper(locale)
		}
	}
	return ""
}

func isC(s string) bool { return s == "C" || s == "POSIX" }
