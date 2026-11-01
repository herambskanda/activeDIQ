package report

import (
	"context"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// PerDCAttr is an attribute that is not replicated and is read from every DC (a closed set: the
// connector's PerDcAttribute enum, so this is no back door for arbitrary reads).
type PerDCAttr uint8

const (
	perDCAttrInvalid PerDCAttr = iota
	PerDCLastLogon
	PerDCLogonCount
	PerDCBadPwdCount
	PerDCBadPasswordTime
	PerDCLockoutTime
	perDCAttrEnd
)

// Valid reports whether a is a defined attribute.
func (a PerDCAttr) Valid() bool { return a > perDCAttrInvalid && a < perDCAttrEnd }

// PerDCAgg is how the per-DC values of one object combine into one cell. A sum is never offered.
type PerDCAgg uint8

const (
	perDCAggInvalid PerDCAgg = iota
	AggMax
	AggMin
	aggEnd
)

// Valid reports whether g is a defined aggregate.
func (g PerDCAgg) Valid() bool { return g > perDCAggInvalid && g < aggEnd }

// PerDCScope says which DCs are asked.
type PerDCScope uint8

const (
	perDCScopeInvalid PerDCScope = iota
	ScopeWritable                // writable DCs only
	ScopeAll                     // every DC including RODCs
)

// Coverage says whether every DC in scope answered. Only COMPLETE makes a maximum an exact value.
type Coverage uint8

const (
	coverageInvalid Coverage = iota
	CoverageComplete
	CoveragePartial
)

// PerDCSummary mirrors the connector's PerDcSummary.
type PerDCSummary struct {
	DCsInScope  uint32
	DCsAnswered uint32
	Coverage    Coverage
}

// PerDCValue is one DC's answer for one attribute: exactly one of Time and Int is meaningful,
// by attribute.
type PerDCValue struct {
	Attr PerDCAttr
	Time time.Time
	Int  int64
}

// PerDCResult is one DC's answer for one object; Err is a fixed code, never driver text.
type PerDCResult struct {
	DC     string
	Values []PerDCValue
	Err    string
}

// PerDCObject is the answers for one object.
type PerDCObject struct {
	Object  authz.ObjectID
	Results []PerDCResult
}

// PerDCReader is the port the run path reads per-DC attributes through. Row P5 implements it over
// directory/client; a stored-dataset implementation could replace it without touching the module.
type PerDCReader interface {
	// Read returns, per object, one value per DC in scope and the coverage; it never sums.
	Read(ctx context.Context, conn, nc authz.ObjectID, objs []authz.ObjectID, attrs []PerDCAttr, scope PerDCScope) ([]PerDCObject, PerDCSummary, error)
}
