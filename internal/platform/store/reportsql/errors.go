package reportsql

import (
	"errors"

	"github.com/skenzeriq/activediq/internal/platform/store"
)

// Errors are typed and carry no SQL text and no request value (contract §5).
var (
	ErrUnknownColumn    = errors.New("reportsql: unknown column")
	ErrBadOperator      = errors.New("reportsql: operator not accepted by the column")
	ErrBadSortDirection = errors.New("reportsql: bad sort direction")
	ErrTooManyValues    = errors.New("reportsql: too many values")
	ErrScopeTooLarge    = errors.New("reportsql: read scope has too many terms")
	ErrBadValue         = errors.New("reportsql: value does not fit the column")
	ErrInvalidQuery     = errors.New("reportsql: query was not resolved against this dataset")
	ErrNoNow            = errors.New("reportsql: Inputs.Now is required")
	ErrNoSubjects       = errors.New("reportsql: the dataset has no subject anchor")
	ErrPerDCInSQL       = errors.New("reportsql: a per-DC column cannot be filtered or sorted in SQL")
	ErrQueryTimeout     = errors.New("reportsql: query timed out")
	ErrTooManyRows      = errors.New("reportsql: the query returned more rows than the caller accepts")
	ErrBadEnumValue     = errors.New("reportsql: the dataset produced an undeclared enum value")

	// ErrNulInText and ErrInvalidUTF8 are the store's (safe-primitives rule 7): SQL-10 and SQL-11.
	ErrNulInText   = store.ErrNulInText
	ErrInvalidUTF8 = store.ErrInvalidUTF8
)

// MaxScopeTerms caps the terms of one scope (grants and token layer together, contract §4.3).
const MaxScopeTerms = 512
