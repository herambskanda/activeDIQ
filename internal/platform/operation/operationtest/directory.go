package operationtest

import (
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/skenzeriq/activediq/internal/platform/operation/step"
)

// MutationOp is how a Mutation changes an attribute.
type MutationOp string

// Mutation operations. Replace sets the whole value list; Add appends the values not already
// present; Remove deletes the values that are present.
const (
	Replace MutationOp = "replace"
	Add     MutationOp = "add"
	Remove  MutationOp = "remove"
)

// Mutation is one attribute write against the fake directory.
type Mutation struct {
	GUID      string // the object's objectGUID, never its DN
	Attribute string
	Op        MutationOp
	Values    []string
}

// FakeDirectory is the fake directory provider: an in-memory object store an Action under test
// writes to and reads back from. It stands in for directory/client, so a test wires the Action to
// it and hands the same *FakeDirectory to the Fixture.
//
// It counts two things. Writes counts every call to Write, including one the fake refuses, so a
// Plan that tries to write is seen even if the attempt fails. Changes counts the calls that really
// changed the stored state, so an idempotent repeat is told apart from a second change.
type FakeDirectory struct {
	mu      sync.Mutex
	objs    map[string]map[string][]string
	writes  int
	changes int
}

// NewFakeDirectory returns an empty fake directory.
func NewFakeDirectory() *FakeDirectory {
	return &FakeDirectory{objs: map[string]map[string][]string{}}
}

// Seed sets an attribute without counting a write: it is fixture setup, not an Action's work.
func (d *FakeDirectory) Seed(guid, attribute string, values ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.setLocked(guid, attribute, values)
}

// Read returns a copy of an attribute's values, nil when the object or attribute is absent.
func (d *FakeDirectory) Read(guid, attribute string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.objs[guid][attribute])
}

// Write applies m. Like the real write API it needs a live Step: the call is counted first, then a
// zero or revoked Step is refused and nothing changes.
func (d *FakeDirectory) Write(s step.Step, m Mutation) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.writes++
	if err := s.Valid(); err != nil {
		return err
	}
	if m.GUID == "" || m.Attribute == "" {
		return fmt.Errorf("operationtest: mutation needs an object GUID and an attribute")
	}
	cur := d.objs[m.GUID][m.Attribute]
	var next []string
	switch m.Op {
	case Replace:
		next = slices.Clone(m.Values)
	case Add:
		next = slices.Clone(cur)
		for _, v := range m.Values {
			if !slices.Contains(next, v) {
				next = append(next, v)
			}
		}
	case Remove:
		for _, v := range cur {
			if !slices.Contains(m.Values, v) {
				next = append(next, v)
			}
		}
	default:
		return fmt.Errorf("operationtest: unknown mutation op %q", m.Op)
	}
	if !slices.Equal(cur, next) {
		d.changes++
	}
	d.setLocked(m.GUID, m.Attribute, next)
	return nil
}

// Writes is the number of Write calls so far, refused ones included.
func (d *FakeDirectory) Writes() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.writes
}

// Changes is the number of Write calls that changed the stored state.
func (d *FakeDirectory) Changes() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.changes
}

func (d *FakeDirectory) setLocked(guid, attribute string, values []string) {
	if d.objs[guid] == nil {
		d.objs[guid] = map[string][]string{}
	}
	if len(values) == 0 {
		delete(d.objs[guid], attribute)
		return
	}
	d.objs[guid][attribute] = slices.Clone(values)
}

// snapshot copies the stored state; restore puts a snapshot back. The counters are not restored: a
// drop is the directory losing a write the Action believed it made.
type snapshot map[string]map[string][]string

func (d *FakeDirectory) snapshot() snapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(snapshot, len(d.objs))
	for g, attrs := range d.objs {
		c := make(map[string][]string, len(attrs))
		for a, v := range attrs {
			c[a] = slices.Clone(v)
		}
		out[g] = c
	}
	return out
}

func (d *FakeDirectory) restore(s snapshot) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.objs = make(map[string]map[string][]string, len(s))
	for g, attrs := range s {
		c := make(map[string][]string, len(attrs))
		maps.Copy(c, attrs)
		d.objs[g] = c
	}
}
