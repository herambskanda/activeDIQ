package migration

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
)

// Actions, permission, audit kinds and target class. migration.import is not a control-plane permission:
// the tenant may delegate it, and the importer needs no directory privilege (spec §9).
const (
	CreateProjectActionID operation.ActionID = "migration.project.create"
	SubmitJobActionID     operation.ActionID = "migration.job.submit"
	PermImport            authz.Permission   = "migration.import"
	AuditProjectCreated   audit.Kind         = "migration.project.created"
	AuditJobSubmitted     audit.Kind         = "migration.job.submitted"
	TargetClassProject                       = "migration_project"
)

var (
	uuidRe  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	buildRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// CreateProjectInput names a new project.
type CreateProjectInput struct {
	Name string `json:"name"`
}

type projectPayload struct {
	Tenant string `json:"tenant"`
	Name   string `json:"name"`
}

// ProjectOutcome is the project written.
type ProjectOutcome struct {
	ProjectID string `json:"projectId"`
}

func tenantOf(ctx context.Context, pc operation.PlanContext) (string, error) {
	var tid string
	if err := pc.Tx.QueryRow(ctx, `SELECT coalesce(current_setting('app.tenant_id', true), '')`).Scan(&tid); err != nil || tid == "" {
		return "", errors.New("migration: no tenant context")
	}
	return tid, nil
}

// CreateProject builds the migration.project.create Action.
func CreateProject() (operation.Action, error) {
	return operation.Define(operation.Typed[CreateProjectInput, projectPayload, ProjectOutcome]{
		Descriptor: operation.Descriptor{
			ID: CreateProjectActionID, Version: 1, Permission: PermImport,
			Input:  "#/components/schemas/MigrationProjectCreate",
			Target: operation.TargetStore, TargetClass: TargetClassProject,
			Reversibility: operation.Irreversible, AuditKind: AuditProjectCreated,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in CreateProjectInput) ([]operation.TypedStep[projectPayload], error) {
			if n := len([]rune(in.Name)); n < 1 || n > 200 {
				return nil, fmt.Errorf("%w: project name must be 1 to 200 characters", operation.ErrInvalid)
			}
			tid, err := tenantOf(ctx, pc)
			if err != nil {
				return nil, err
			}
			return []operation.TypedStep[projectPayload]{{
				Plan: operation.StepPlan{
					Target:              authority.TargetRef{GUID: tid, Class: TargetClassProject},
					Kind:                string(CreateProjectActionID),
					Diff:                []operation.Change{{Attribute: "name", After: []string{in.Name}}},
					Reversibility:       operation.Irreversible,
					ReversibilityReason: "a project is closed, never deleted",
				},
				Payload: projectPayload{Tenant: tid, Name: in.Name},
			}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, p operation.TypedStep[projectPayload]) (ProjectOutcome, error) {
			id, err := insertProject(ctx, s, p.Payload.Tenant, p.Payload.Name, string(s.Actor().Requester.ID))
			return ProjectOutcome{ProjectID: id}, err
		},
		Verify: func(ctx context.Context, s step.Step, p operation.TypedStep[projectPayload], o ProjectOutcome) (operation.Verdict, error) {
			ok, err := projectOpen(ctx, s.Tx(), p.Payload.Tenant, o.ProjectID)
			if err != nil {
				return operation.Verdict{}, err
			}
			return operation.Verdict{OK: ok, Reason: "project_not_as_applied"}, nil
		},
		Inverse: func(operation.TypedStep[projectPayload], ProjectOutcome) (CreateProjectInput, error) {
			return CreateProjectInput{}, operation.ErrIrreversible
		},
	})
}

// SubmitJobInput is one intake. SizeBytes is the declared size (Content-Length or stat): the size gate
// decides on it alone, before any byte is read. SourceSHA256 is the hex digest of the source, taken while
// the upload streamed to quarantine; it is not needed (and not stored) for a source over its limit.
type SubmitJobInput struct {
	JobID        string `json:"jobId"`
	ProjectID    string `json:"projectId"`
	SourceKind   string `json:"sourceKind"`
	SourceSHA256 string `json:"sourceSha256,omitempty"`
	ADMPBuild    string `json:"admpBuild"`
	SizeBytes    int64  `json:"sizeBytes"`
}

type jobPayload struct {
	Tenant   string `json:"tenant"`
	In       SubmitJobInput
	LimitHit string `json:"limitHit,omitempty"`
}

// JobOutcome is the state the job was recorded in.
type JobOutcome struct {
	State string `json:"state"`
}

// SubmitJob builds the migration.job.submit Action.
func SubmitJob() (operation.Action, error) {
	return operation.Define(operation.Typed[SubmitJobInput, jobPayload, JobOutcome]{
		Descriptor: operation.Descriptor{
			ID: SubmitJobActionID, Version: 1, Permission: PermImport,
			Input:  "#/components/schemas/MigrationJobSubmit",
			Target: operation.TargetStore, TargetClass: TargetClassProject,
			Reversibility: operation.Irreversible, AuditKind: AuditJobSubmitted,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in SubmitJobInput) ([]operation.TypedStep[jobPayload], error) {
			if !uuidRe.MatchString(in.JobID) || !uuidRe.MatchString(in.ProjectID) || !buildRe.MatchString(in.ADMPBuild) {
				return nil, fmt.Errorf("%w: job id, project id or ADMP build malformed", operation.ErrInvalid)
			}
			limit, err := SizeGate(SourceKind(in.SourceKind), in.SizeBytes)
			if err != nil {
				return nil, fmt.Errorf("%w: %s", operation.ErrInvalid, err.Error())
			}
			if limit == "" {
				if b, err := hex.DecodeString(in.SourceSHA256); err != nil || len(b) != 32 || in.SourceSHA256 != hex.EncodeToString(b) {
					return nil, fmt.Errorf("%w: source SHA-256 must be 64 lower-case hex characters", operation.ErrInvalid)
				}
			}
			tid, err := tenantOf(ctx, pc)
			if err != nil {
				return nil, err
			}
			target := authority.TargetRef{GUID: in.ProjectID, Class: TargetClassProject}
			open, err := projectOpen(ctx, pc.Tx, tid, in.ProjectID)
			if err != nil {
				return nil, err
			}
			if !open {
				return nil, &operation.PlanRefusal{Code: "no_such_project", Target: target}
			}
			state := "quarantined"
			after := []operation.Change{
				{Attribute: "source_kind", After: []string{in.SourceKind}},
				{Attribute: "admp_build", After: []string{in.ADMPBuild}},
				{Attribute: "size_bytes", After: []string{strconv.FormatInt(in.SizeBytes, 10)}},
			}
			if limit != "" {
				state = "rejected"
				after = append(after, operation.Change{Attribute: "limit_hit", After: []string{limit}})
			} else {
				after = append(after, operation.Change{Attribute: "source_sha256", After: []string{in.SourceSHA256}})
				// The actor is not known to Plan: the per-user quota is checked in Apply, under the lock.
				tn, _, err := activeCounts(ctx, pc.Tx, tid, "")
				if err != nil {
					return nil, err
				}
				if tn >= MaxActivePerTenant {
					return nil, &operation.PlanRefusal{Code: "quota_tenant", Target: target}
				}
			}
			after = append(after, operation.Change{Attribute: "state", After: []string{state}})
			if limit != "" {
				in.SourceSHA256 = ""
			}
			return []operation.TypedStep[jobPayload]{{
				Plan: operation.StepPlan{
					Target: target, Kind: string(SubmitJobActionID), Diff: after,
					Reversibility:       operation.Irreversible,
					ReversibilityReason: "the intake record is kept; a job is cancelled by its own action",
				},
				Payload: jobPayload{Tenant: tid, In: in, LimitHit: limit},
			}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, p operation.TypedStep[jobPayload]) (JobOutcome, error) {
			in := p.Payload.In
			j := jobRow{JobID: in.JobID, ProjectID: in.ProjectID, Actor: string(s.Actor().Requester.ID), Kind: in.SourceKind,
				Build: in.ADMPBuild, Size: in.SizeBytes, State: "quarantined"}
			if p.Payload.LimitHit != "" {
				j.State, j.LimitHit = "rejected", p.Payload.LimitHit
			} else {
				j.SHA, _ = hex.DecodeString(in.SourceSHA256)
			}
			if err := insertJob(ctx, s, p.Payload.Tenant, j); err != nil {
				return JobOutcome{}, err
			}
			return JobOutcome{State: j.State}, nil
		},
		Verify: func(ctx context.Context, s step.Step, p operation.TypedStep[jobPayload], o JobOutcome) (operation.Verdict, error) {
			j, found, err := getJob(ctx, s.Tx(), p.Payload.In.JobID)
			if err != nil {
				return operation.Verdict{}, err
			}
			sha, _ := hex.DecodeString(p.Payload.In.SourceSHA256)
			if !found || j.State != o.State || j.Size != p.Payload.In.SizeBytes || !bytes.Equal(j.SHA, sha) && p.Payload.LimitHit == "" {
				return operation.Verdict{Reason: "job_not_as_applied"}, nil
			}
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(operation.TypedStep[jobPayload], JobOutcome) (SubmitJobInput, error) {
			return SubmitJobInput{}, operation.ErrIrreversible
		},
	})
}
