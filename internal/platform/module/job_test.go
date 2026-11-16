package module_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

func kind(name string) jobs.Kind {
	return jobs.Kind{Name: name, Timeout: time.Minute, Mode: jobs.ModeDefault, Run: func(context.Context, store.Tx, jobs.Claimed) error { return nil }}
}

func TestJobIsCollectedAndNamespaced(t *testing.T) {
	m := &fake{id: "fake", register: func(r *module.Registrar) error {
		if err := r.Job(module.Job{Kind: kind("fake.sweep")}); err != nil {
			return err
		}
		return r.Job(module.Job{Kind: kind("fake.other")})
	}}
	c, err := moduletest.Register(m)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Jobs(); len(got) != 2 || got[0].Kind.Name != "fake.sweep" {
		t.Fatalf("jobs = %v", got)
	}
	for name, reg := range map[string]func(r *module.Registrar) error{
		"outside namespace": func(r *module.Registrar) error { return r.Job(module.Job{Kind: kind("other.sweep")}) },
		"duplicate": func(r *module.Registrar) error {
			if err := r.Job(module.Job{Kind: kind("fake.sweep")}); err != nil {
				return err
			}
			return r.Job(module.Job{Kind: kind("fake.sweep")})
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
