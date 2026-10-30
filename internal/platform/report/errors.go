package report

import (
	"errors"
	"fmt"
)

// Code is the machine-readable reason a definition, a dataset or a run request was refused.
type Code string

// Validation codes. The API layer maps them to problem types; none carries a value from the request.
const (
	CodeUnknownDataset     Code = "unknown_dataset"
	CodeUnknownColumn      Code = "unknown_column"
	CodeUnknownOperator    Code = "unknown_operator"
	CodeUnknownPreset      Code = "unknown_preset"
	CodeUnknownParameter   Code = "unknown_parameter"
	CodeOperatorNotAllowed Code = "operator_not_allowed"
	CodeBadValue           Code = "bad_value"
	CodeBadSort            Code = "bad_sort"
	CodeMissingParameter   Code = "missing_parameter"
	CodeBelowFloor         Code = "below_floor"
	CodeAboveCeiling       Code = "above_ceiling"
	CodePerDCMisplaced     Code = "per_dc_misplaced"
	CodeTooManyColumns     Code = "too_many_columns"
	CodeDuplicateColumn    Code = "duplicate_column"
	CodeTooComplex         Code = "filter_too_complex"
	CodeTooManyValues      Code = "too_many_values"
	CodeBadNarrowing       Code = "bad_narrowing"
	CodeSubjects           Code = "bad_subjects"
	CodeInvalidDefinition  Code = "invalid_definition"
	CodeInvalidDataset     Code = "invalid_dataset"
	CodeInvalidQuery       Code = "invalid_query"
)

// ValidationError is the one error type of this package (contract §3.4). Path says where, for
// example "columns[2]" or "where.cmp.op". It never echoes a request value.
//
// Detail is set only for Definition and Dataset validation, whose input is code written by us, not
// a request; it names the offending identifier to help the author. Resolve leaves it empty.
type ValidationError struct {
	Code   Code
	Path   string
	Detail string
}

func (e ValidationError) Error() string {
	s := "report: " + string(e.Code)
	if e.Path != "" {
		s += " at " + e.Path
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

func verr(c Code, path string) error { return ValidationError{Code: c, Path: path} }

func verrf(c Code, path, format string, a ...any) error {
	return ValidationError{Code: c, Path: path, Detail: fmt.Sprintf(format, a...)}
}

// CodeOf returns the validation code in err's chain.
func CodeOf(err error) (Code, bool) {
	var v ValidationError
	if errors.As(err, &v) {
		return v.Code, true
	}
	return "", false
}

// ErrSealed is returned when a dataset is added to a host after Seal.
var ErrSealed = errors.New("report: host is sealed")

// ErrDuplicateDataset is returned when two owners register the same dataset ID.
var ErrDuplicateDataset = errors.New("report: duplicate dataset")
