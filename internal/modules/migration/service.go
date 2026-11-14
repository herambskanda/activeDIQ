package migration

import (
	"context"
	"crypto/rand"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Service is the intake entry point for callers (the API handlers, later). It runs the two Actions
// through the operation runner and maps their outcomes to typed errors.
type Service struct {
	Runner *operation.Runner
	DB     *store.DB
}

// Job is the recorded intake of one source.
type Job struct {
	ID, ProjectID, Actor, SourceKind, State, LimitHit string
	SourceSHA256                                      []byte
	SizeBytes                                         int64
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

func (s *Service) req(t tenant.ID, actor authority.Chain, id operation.ActionID, in any) (operation.Request, error) {
	raw, err := jsonv2.Marshal(in)
	if err != nil {
		return operation.Request{}, err
	}
	op, err := newUUID()
	if err != nil {
		return operation.Request{}, err
	}
	return operation.Request{Tenant: t, Actor: actor, Action: id, Input: raw, Operation: step.OperationID("op-" + op)}, nil
}

// CreateProject creates a project and returns its ID. A caller without migration.import gets
// operation.ErrDenied and a denied audit event.
func (s *Service) CreateProject(ctx context.Context, t tenant.ID, actor authority.Chain, name string) (string, error) {
	rq, err := s.req(t, actor, CreateProjectActionID, CreateProjectInput{Name: name})
	if err != nil {
		return "", err
	}
	res, err := s.Runner.RunStore(ctx, rq)
	if err != nil {
		return "", err
	}
	if len(res.Steps) != 1 {
		return "", errors.New("migration: project create returned no outcome")
	}
	var out ProjectOutcome
	if err := jsonv2.Unmarshal(res.Steps[0].Outcome.Payload, &out); err != nil || out.ProjectID == "" {
		return "", errors.New("migration: project create outcome unreadable")
	}
	return out.ProjectID, nil
}

// SubmitJob records the intake of one source. The size gate runs on in.SizeBytes alone, before the
// source is read: over the limit the job is stored `rejected` with the limit hit and the error is
// ErrSizeLimit (the returned Job is still set). Quota refusals are ErrQuotaUser and ErrQuotaTenant.
func (s *Service) SubmitJob(ctx context.Context, t tenant.ID, actor authority.Chain, in SubmitJobInput) (Job, error) {
	if in.JobID == "" {
		id, err := newUUID()
		if err != nil {
			return Job{}, err
		}
		in.JobID = id
	}
	rq, err := s.req(t, actor, SubmitJobActionID, in)
	if err != nil {
		return Job{}, err
	}
	if _, err := s.Runner.RunStore(ctx, rq); err != nil {
		var pr *operation.PlanRefusal
		switch {
		case errors.Is(err, ErrQuotaUser):
			return Job{}, ErrQuotaUser
		case errors.Is(err, ErrQuotaTenant):
			return Job{}, ErrQuotaTenant
		case errors.As(err, &pr) && pr.Code == "quota_tenant":
			return Job{}, ErrQuotaTenant
		case errors.As(err, &pr) && pr.Code == "no_such_project":
			return Job{}, ErrNoSuchProject
		}
		return Job{}, err
	}
	var j jobRow
	err = s.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		var found bool
		j, found, err = getJob(ctx, tx, in.JobID)
		if err == nil && !found {
			err = errors.New("migration: job not found after submit")
		}
		return err
	})
	if err != nil {
		return Job{}, err
	}
	out := Job{ID: j.JobID, ProjectID: j.ProjectID, Actor: j.Actor, SourceKind: j.Kind, State: j.State, LimitHit: j.LimitHit, SourceSHA256: j.SHA, SizeBytes: j.Size}
	if j.State == "rejected" {
		return out, fmt.Errorf("%w: %s", ErrSizeLimit, j.LimitHit)
	}
	return out, nil
}
