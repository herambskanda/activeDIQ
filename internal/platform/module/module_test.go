package module_test

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
	"github.com/skenzeriq/activediq/internal/platform/operation"
)

// fake is a module whose behaviour the test sets.
type fake struct {
	id       module.ID
	requires []capability.ID
	register func(r *module.Registrar) error
	calls    int
}

func (f *fake) ID() module.ID             { return f.id }
func (f *fake) Requires() []capability.ID { return f.requires }
func (f *fake) Register(r *module.Registrar) error {
	f.calls++
	return f.register(r)
}

func actions(ids ...operation.ActionID) func(*module.Registrar) error {
	return func(r *module.Registrar) error {
		for _, id := range ids {
			if err := r.Action(moduletest.Action(id)); err != nil {
				return err
			}
		}
		return nil
	}
}

func TestRegisterCollectsActions(t *testing.T) {
	m := &fake{id: "fake", register: actions("fake.thing.do", "fake.thing.undo")}
	c, err := moduletest.Register(m)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	got := c.Actions()
	if len(got) != 2 || got[0].Describe().ID != "fake.thing.do" || got[1].Describe().ID != "fake.thing.undo" {
		t.Fatalf("actions = %v", got)
	}
	if l := c.Loaded(); len(l) != 1 || l[0] != "fake" {
		t.Fatalf("loaded = %v", l)
	}
}

func TestBootRejects(t *testing.T) {
	var stash *module.Registrar
	tests := []struct {
		name string
		mods []module.Entry
		want error
	}{
		{"action outside namespace", []module.Entry{{ID: "fake", Module: &fake{id: "fake", register: actions("other.thing.do")}}}, module.ErrNamespace},
		{"action ID is only the prefix", []module.Entry{{ID: "fake", Module: &fake{id: "fake", register: actions("fake.")}}}, module.ErrNamespace},
		{"prefix without dot", []module.Entry{{ID: "fake", Module: &fake{id: "fake", register: actions("faker.thing")}}}, module.ErrNamespace},
		{"duplicate action", []module.Entry{{ID: "fake", Module: &fake{id: "fake", register: actions("fake.a", "fake.a")}}}, module.ErrDuplicate},
		{"module listed twice", []module.Entry{
			{ID: "fake", Module: &fake{id: "fake", register: actions()}},
			{ID: "fake", Module: &fake{id: "fake", register: actions()}},
		}, module.ErrDuplicate},
		{"ID does not match entry", []module.Entry{{ID: "fake", Module: &fake{id: "liar", register: actions()}}}, module.ErrInvalid},
		{"invalid ID", []module.Entry{{ID: "Fake", Module: &fake{id: "Fake", register: actions()}}}, module.ErrInvalid},
		{"nil module", []module.Entry{{ID: "fake"}}, module.ErrInvalid},
		{"nil action", []module.Entry{{ID: "fake", Module: &fake{id: "fake", register: func(r *module.Registrar) error { return r.Action(nil) }}}}, module.ErrInvalid},
		{"use after Register returned", []module.Entry{{ID: "fake", Module: &fake{id: "fake", register: func(r *module.Registrar) error {
			stash = r
			return nil
		}}}}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := module.Boot(context.Background(), tc.mods, capability.NewSet())
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Boot: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Boot err = %v, want %v", err, tc.want)
			}
			if c != nil {
				t.Fatal("Boot returned contributions alongside an error")
			}
		})
	}
	// A Registrar stashed by a module gains nothing once Boot has returned.
	if err := stash.Action(moduletest.Action("fake.late")); !errors.Is(err, module.ErrClosed) {
		t.Fatalf("Action after Boot err = %v, want ErrClosed", err)
	}
}

func TestRegisterErrorPropagates(t *testing.T) {
	boom := errors.New("boom")
	m := &fake{id: "fake", register: func(*module.Registrar) error { return boom }}
	if _, err := moduletest.Register(m); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
}

func TestZeroRegistrarRefuses(t *testing.T) {
	var r module.Registrar
	if err := r.Action(moduletest.Action("fake.thing")); !errors.Is(err, module.ErrClosed) {
		t.Fatalf("zero Registrar err = %v, want ErrClosed", err)
	}
}

func TestBootSkipsUnsatisfiedCapability(t *testing.T) {
	needs := &fake{id: "entra", requires: []capability.ID{capability.DirectoryEntra}, register: actions("entra.x")}
	plain := &fake{id: "plain", register: actions("plain.x")}
	mods := []module.Entry{{ID: "entra", Module: needs}, {ID: "plain", Module: plain}}

	c, err := module.Boot(context.Background(), mods, capability.NewSet(capability.DirectoryAD))
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	if needs.calls != 0 {
		t.Fatal("module with an unmet capability must not be registered")
	}
	if s := c.Skipped(); len(s) != 1 || s[0] != "entra" {
		t.Fatalf("skipped = %v", s)
	}
	if a := c.Actions(); len(a) != 1 || a[0].Describe().ID != "plain.x" {
		t.Fatalf("actions = %v", a)
	}

	c, err = module.Boot(context.Background(), mods, capability.NewSet(capability.DirectoryEntra))
	if err != nil || len(c.Loaded()) != 2 || needs.calls != 1 {
		t.Fatalf("with capability: err=%v loaded=%v calls=%d", err, c.Loaded(), needs.calls)
	}
}

func TestBootEmptyAndCancelled(t *testing.T) {
	c, err := module.Boot(context.Background(), nil, capability.NewSet())
	if err != nil || len(c.Loaded()) != 0 || len(c.Actions()) != 0 {
		t.Fatalf("empty Boot: %v %v", c, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := &fake{id: "fake", register: actions()}
	if _, err := module.Boot(ctx, []module.Entry{{ID: "fake", Module: m}}, capability.NewSet()); !errors.Is(err, context.Canceled) || m.calls != 0 {
		t.Fatalf("cancelled Boot err=%v calls=%d", err, m.calls)
	}
}

func TestMustRegisterNilModule(t *testing.T) {
	if _, err := moduletest.Register(nil); !errors.Is(err, module.ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
}
