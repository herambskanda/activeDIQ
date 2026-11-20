package jobcontrib_test

import (
	"context"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/module/jobcontrib"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

type fake struct {
	reg func(r *module.Registrar) error
}

func (fake) ID() module.ID                        { return "fake" }
func (fake) Requires() []capability.ID            { return nil }
func (f fake) Register(r *module.Registrar) error { return f.reg(r) }

func kind(name string) jobs.Kind {
	return jobs.Kind{Name: name, Timeout: time.Minute, Mode: jobs.ModeDefault, Run: func(context.Context, store.Tx, jobs.Claimed) error { return nil }}
}

type foreign string

func (f foreign) JobName() string { return string(f) }

func TestAllReturnsTypedJobsInBootOrder(t *testing.T) {
	c, err := moduletest.Register(fake{func(r *module.Registrar) error {
		if err := r.Job(jobcontrib.Job{Kind: kind("fake.sweep")}); err != nil {
			return err
		}
		return r.Job(jobcontrib.Job{Kind: kind("fake.other")})
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := jobcontrib.All(c)
	if err != nil || len(got) != 2 || got[0].Kind.Name != "fake.sweep" || got[1].Kind.Name != "fake.other" {
		t.Fatalf("All = %v, %v", got, err)
	}
}

func TestAllRefusesAForeignJobType(t *testing.T) {
	c, err := moduletest.Register(fake{func(r *module.Registrar) error { return r.Job(foreign("fake.x")) }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobcontrib.All(c); err == nil {
		t.Fatal("foreign job type accepted")
	}
}
