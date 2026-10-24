package operation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/jobs"
)

// registerJobs registers the job kinds of the persisted path (ADR-0005 rule 6). All are ManagedTx kinds:
// a body never holds a transaction across a directory call. The job is only a driver; the state lives
// in the operation_steps rows, so a lost job is re-driven by the sweeper and a duplicate is harmless.
func (r *Runner) registerJobs(reg *jobs.Registry) error {
	kinds := []jobs.Kind{
		{Name: JobApply, Timeout: 30 * time.Minute, Mode: jobs.ModeManagedTx,
			ValidateArgs: func(a json.RawMessage) error { return decodeArgs(a, &chunkArgs{}) },
			RunManaged: func(ctx context.Context, run jobs.TenantTx, c jobs.Claimed) error {
				var a chunkArgs
				if err := decodeArgs(c.Args, &a); err != nil {
					return &jobs.Failure{Code: "bad_args", Permanent: true, Err: err}
				}
				return r.RunChunk(ctx, c.Tenant, run.Run, a)
			}},
		{Name: JobVerify, Timeout: 10 * time.Minute, Mode: jobs.ModeManagedTx,
			ValidateArgs: func(a json.RawMessage) error { return decodeArgs(a, &verifyArgs{}) },
			RunManaged: func(ctx context.Context, run jobs.TenantTx, c jobs.Claimed) error {
				var a verifyArgs
				if err := decodeArgs(c.Args, &a); err != nil {
					return &jobs.Failure{Code: "bad_args", Permanent: true, Err: err}
				}
				return r.Verify(ctx, c.Tenant, run.Run, a.Operation)
			}},
		{Name: JobReconcile, Timeout: 10 * time.Minute, Mode: jobs.ModeManagedTx,
			RunManaged: func(ctx context.Context, run jobs.TenantTx, c jobs.Claimed) error {
				_, err := r.Reconcile(ctx, c.Tenant, run.Run, 50)
				return err
			}},
		{Name: JobSweep, Timeout: 10 * time.Minute, Mode: jobs.ModeManagedTx,
			RunManaged: func(ctx context.Context, run jobs.TenantTx, c jobs.Claimed) error {
				return r.Sweep(ctx, c.Tenant, run.Run)
			}},
	}
	for _, k := range kinds {
		if err := reg.Register(k); err != nil {
			return fmt.Errorf("operation: registering job kind: %w", err)
		}
	}
	return nil
}

// decodeArgs decodes typed references and refuses unknown fields: job args never carry values.
func decodeArgs(raw json.RawMessage, into any) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return errors.New("args are not an object")
	}
	delete(m, "tenant_id") // recorded by Enqueue
	b, _ := json.Marshal(m)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return errors.New("args do not match the kind")
	}
	return nil
}
