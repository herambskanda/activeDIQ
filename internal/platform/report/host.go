package report

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
)

// TableOwners says which package owns a table: the generated ownership map
// (store/owners, ADR-0003 rule 6). ok is false for a table no owner declared.
type TableOwners func(table string) (owner string, ok bool)

// ErrTableOwnership is the error CheckTables returns, for errors.Is.
var ErrTableOwnership = errors.New("report: dataset names a table its owner does not own")

// TableOwnershipError names the dataset and the table. Boot and the host fail with it, so start-up
// stops and the message says which table.
type TableOwnershipError struct {
	Dataset DatasetID
	Table   string
	Owner   string // who registers the dataset
	Actual  string // who owns the table; empty when no owner declared it
}

func (e *TableOwnershipError) Error() string {
	if e.Actual == "" {
		return fmt.Sprintf("report: dataset %q registered by %q names table %q, which no owner declared in the ownership map", e.Dataset, e.Owner, e.Table)
	}
	return fmt.Sprintf("report: dataset %q registered by %q names table %q, which is owned by %q", e.Dataset, e.Owner, e.Table, e.Actual)
}

func (e *TableOwnershipError) Unwrap() error { return ErrTableOwnership }

// CheckTables fails when the dataset names a table that owner does not own, or that nobody owns,
// and names the first such table (sorted). It also fails a dataset whose ID is not in owner's
// namespace. A nil ownerOf owns nothing, so every table fails closed.
func CheckTables(owner string, d Dataset, ownerOf TableOwners) error {
	if d.ID.Owner() != owner {
		return fmt.Errorf("%w: dataset %q is registered by %q but its ID must start with %q", ErrNamespace, d.ID, owner, owner+".")
	}
	tables := slices.Clone(d.Tables)
	sort.Strings(tables)
	for _, t := range tables {
		var actual string
		var ok bool
		if ownerOf != nil {
			actual, ok = ownerOf(t)
		}
		if !ok || actual != owner {
			return &TableOwnershipError{Dataset: d.ID, Table: t, Owner: owner, Actual: actual}
		}
	}
	return nil
}

// ErrNamespace is returned for a dataset ID outside its registrant's namespace.
var ErrNamespace = errors.New("report: dataset outside its owner's namespace")

// OwnedDatasets is a set of datasets and the owner key that registered them.
type OwnedDatasets struct {
	Owner    string
	Datasets []Dataset
}

// Host holds the registered datasets (EP-8). compose/server creates it, hands it to modules as
// Deps.Report, adds the datasets that directory packages export (inventory.Datasets()) and the
// ones Boot collected from modules, then seals it. After Seal it is read-only and safe for
// concurrent use.
type Host struct {
	ownerOf TableOwners
	mu      sync.RWMutex
	sealed  bool
	sets    map[DatasetID]Dataset
	owners  map[DatasetID]string
}

// NewHost returns an empty, open host that checks table ownership with ownerOf.
func NewHost(ownerOf TableOwners) *Host {
	return &Host{ownerOf: ownerOf, sets: map[DatasetID]Dataset{}, owners: map[DatasetID]string{}}
}

// Add validates and registers datasets under the owner key: structure (Dataset.Validate), namespace
// and table ownership (CheckTables), and uniqueness. It adds none of them if any fails.
func (h *Host) Add(owner string, ds ...Dataset) error {
	if h == nil {
		return ErrSealed
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sealed {
		return ErrSealed
	}
	seen := map[DatasetID]bool{}
	for _, d := range ds {
		if err := d.Validate(); err != nil {
			return err
		}
		if err := CheckTables(owner, d, h.ownerOf); err != nil {
			return err
		}
		if _, dup := h.sets[d.ID]; dup || seen[d.ID] {
			return fmt.Errorf("%w: %q", ErrDuplicateDataset, d.ID)
		}
		seen[d.ID] = true
	}
	for _, d := range ds {
		h.sets[d.ID] = d
		h.owners[d.ID] = owner
	}
	return nil
}

// Seal closes the host to further datasets.
func (h *Host) Seal() {
	h.mu.Lock()
	h.sealed = true
	h.mu.Unlock()
}

// Dataset returns the registered dataset with the given ID.
func (h *Host) Dataset(id DatasetID) (Dataset, bool) {
	if h == nil {
		return zeroDataset, false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	d, ok := h.sets[id]
	return d, ok
}

// Datasets lists the registered dataset IDs, sorted.
func (h *Host) Datasets() []DatasetID {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]DatasetID, 0, len(h.sets))
	for id := range h.sets {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// Resolve resolves a run request against def's registered dataset. An unregistered dataset is
// CodeUnknownDataset and no Query exists.
func (h *Host) Resolve(def Definition, preset string, p RunParams) (Query, error) {
	ds, ok := h.Dataset(def.Dataset)
	if !ok {
		return Query{}, verr(CodeUnknownDataset, "dataset")
	}
	return Resolve(def, preset, p, ds)
}

// zeroDataset is the "not found" result. It is a variable so no Dataset literal without an ID
// appears in non-test code, which fitness-reports RP11 would list as a dataset it cannot name.
var zeroDataset Dataset
