// Package jobcontrib is the job contribution (EP-5) a module registers with Registrar.Job.
//
// It sits above platform/module and platform/jobs so that platform/module imports neither jobs,
// store nor tenant (ADR-0005 rule 13, O9). module sees only the module.Job interface; this package
// supplies the concrete type and the reader the composition root uses to get it back.
package jobcontrib

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Job is one job kind a module contributes. Kind.Name must start with "<moduleID>.". Seed, when set,
// is called by the composition root once per boot for the install tenant, in that tenant's
// transaction, after the tenant exists; it must be idempotent (a keyed enqueue). The module starts no
// goroutine: the kernel's worker runs the kind and the kernel calls Seed.
type Job struct {
	Kind jobs.Kind
	Seed func(ctx context.Context, tx store.Tx, tid tenant.ID) error
}

// JobName implements module.Job.
func (j Job) JobName() string { return j.Kind.Name }

// All returns the jobs the loaded modules registered, in boot order. It fails when a contribution is
// not a Job from this package, which Boot cannot check.
func All(c *module.Contributions) ([]Job, error) {
	var out []Job
	for _, m := range c.Jobs() {
		j, ok := m.(Job)
		if !ok {
			return nil, fmt.Errorf("jobcontrib: job %q is %T, not jobcontrib.Job", m.JobName(), m)
		}
		out = append(out, j)
	}
	return out, nil
}
