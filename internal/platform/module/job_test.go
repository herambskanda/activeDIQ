package module_test

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
)

// kind is a module.Job without the kernel types: module's tests import neither jobs, store nor tenant.
type kind string

func (k kind) JobName() string { return string(k) }

func TestJobIsCollectedAndNamespaced(t *testing.T) {
	m := &fake{id: "fake", register: func(r *module.Registrar) error {
		if err := r.Job(kind("fake.sweep")); err != nil {
			return err
		}
		return r.Job(kind("fake.other"))
	}}
	c, err := moduletest.Register(m)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Jobs(); len(got) != 2 || got[0].JobName() != "fake.sweep" {
		t.Fatalf("jobs = %v", got)
	}
	for name, reg := range map[string]func(r *module.Registrar) error{
		"outside namespace": func(r *module.Registrar) error { return r.Job(kind("other.sweep")) },
		"duplicate": func(r *module.Registrar) error {
			if err := r.Job(kind("fake.sweep")); err != nil {
				return err
			}
			return r.Job(kind("fake.sweep"))
		},
	} {
		if _, err := moduletest.Register(&fake{id: "fake", register: reg}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReadyHooksRunInOrderAndStopOnError(t *testing.T) {
	var order []string
	boom := errors.New("boom")
	mk := func(id module.ID, err error) *fake {
		return &fake{id: id, register: func(r *module.Registrar) error {
			return r.Ready(func(context.Context) error { order = append(order, string(id)); return err })
		}}
	}
	a, b, d := mk("aa", nil), mk("bb", boom), mk("cc", nil)
	c, err := module.Boot(context.Background(), []module.Entry{{ID: "aa", Module: a}, {ID: "bb", Module: b}, {ID: "cc", Module: d}}, capability.NewSet())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Ready(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("Ready = %v", err)
	}
	if len(order) != 2 || order[0] != "aa" || order[1] != "bb" {
		t.Fatalf("order = %v", order)
	}
	if _, err := moduletest.Register(&fake{id: "fake", register: func(r *module.Registrar) error { return r.Ready(nil) }}); !errors.Is(err, module.ErrInvalid) {
		t.Fatalf("nil hook: %v", err)
	}
}
