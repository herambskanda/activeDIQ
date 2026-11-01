package store

import (
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// IsNoRows reports whether err is the "no rows" result of a QueryRow(...).Scan. Packages above store may
// not import pgx (fitness-tenancy T5 pgx-boundary), so they ask here.
func IsNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// SQLState returns the five-character SQLSTATE of a database error in err's chain, or "" when there is
// none. It never returns the message, which can carry object names and values.
func SQLState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// SQLConstraint returns the SQLSTATE and the table and constraint names of a database error in err's
// chain, or three empty strings when there is none. Schema names only: never the message or the detail,
// which carry values. It lets a test tell which CHECK refused a write without importing pgx.
func SQLConstraint(err error) (state, table, constraint string) {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code, pe.TableName, pe.ConstraintName
	}
	return "", "", ""
}
