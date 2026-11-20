package migration

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
)

// The fidelity Action, its audit kind and target class.
const (
	RecordFidelityActionID operation.ActionID = "migration.fidelity.record"
	AuditFidelityRecorded  audit.Kind         = "migration.fidelity.recorded"
	TargetClassJob                            = "migration_job"
)

// RecordFidelityInput is the whole parsed result of one job: every item, once. The classification is done
// server-side in Plan from what the importer describes; an importer cannot ask for a proposal.
type RecordFidelityInput struct {
	JobID string `json:"jobId"`
	Items []Item `json:"items"`
}

type fidelityPayload struct {
	Tenant string       `json:"tenant"`
	JobID  string       `json:"jobId"`
	Rows   []Classified `json:"rows"`
}

// FidelityOutcome counts what was stored, per class. It never carries item content.
type FidelityOutcome struct {
	Items     int            `json:"items"`
	ByClass   map[string]int `json:"byClass"`
	Proposals int            `json:"proposals"`
}

// RecordFidelity builds the migration.fidelity.record Action: one fidelity row per item and one inert
// proposal per applicable item, in one transaction. r decides tier0 scopes; nil refuses every directory
// scope (fail closed).
func RecordFidelity(r Tier0Resolver) (operation.Action, error) {
	return operation.Define(operation.Typed[RecordFidelityInput, fidelityPayload, FidelityOutcome]{
		Descriptor: operation.Descriptor{
			ID: RecordFidelityActionID, Version: 1, Permission: PermImport,
			Input:  "#/components/schemas/MigrationFidelityRecord",
			Target: operation.TargetStore, TargetClass: TargetClassJob,
			Reversibility: operation.Irreversible, AuditKind: AuditFidelityRecorded,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in RecordFidelityInput) ([]operation.TypedStep[fidelityPayload], error) {
			if !uuidRe.MatchString(in.JobID) {
				return nil, fmt.Errorf("%w: job id malformed", operation.ErrInvalid)
			}
			if len(in.Items) > MaxItemsPerRecord {
				return nil, fmt.Errorf("%w: more than %d items in one record", operation.ErrInvalid, MaxItemsPerRecord)
			}
			tid, err := tenantOf(ctx, pc)
			if err != nil {
				return nil, err
			}
			target := authority.TargetRef{GUID: in.JobID, Class: TargetClassJob}
			st, found, err := jobState(ctx, pc.Tx, in.JobID)
			if err != nil {
				return nil, err
			}
			switch {
			case !found:
				return nil, &operation.PlanRefusal{Code: "no_such_job", Target: target}
			case st != "running":
				return nil, &operation.PlanRefusal{Code: "job_not_running", Target: target}
			}
			byClass, _, err := counts(ctx, pc.Tx, in.JobID)
			if err != nil {
				return nil, err
			}
			if len(byClass) > 0 {
				return nil, &operation.PlanRefusal{Code: "already_recorded", Target: target}
			}
			rows := make([]Classified, 0, len(in.Items))
			seen := make(map[string]struct{}, len(in.Items))
			for i, it := range in.Items {
				if _, dup := seen[it.Ref]; dup {
					return nil, fmt.Errorf("%w: item %d repeats a ref: one row per item", operation.ErrInvalid, i)
				}
				seen[it.Ref] = struct{}{}
				c, err := Classify(ctx, pc.Tx, r, i, it)
				if err != nil {
					if errors.Is(err, ErrInvalid) {
						return nil, fmt.Errorf("%w: %s", operation.ErrInvalid, err.Error())
					}
					return nil, err
				}
				rows = append(rows, c)
			}
			// The audited diff carries counts only: never a script body, name or config.
			tally := map[Class]int{}
			props := 0
			for _, c := range rows {
				tally[c.Class]++
				if c.Proposal != nil {
					props++
				}
			}
			diff := []operation.Change{{Attribute: "items", After: []string{strconv.Itoa(len(rows))}}, {Attribute: "proposals", After: []string{strconv.Itoa(props)}}}
			for _, c := range []Class{ClassExact, ClassChanged, ClassManual, ClassNotSupported} {
				diff = append(diff, operation.Change{Attribute: "class_" + string(c), After: []string{strconv.Itoa(tally[c])}})
			}
			return []operation.TypedStep[fidelityPayload]{{
				Plan: operation.StepPlan{
					Target: target, Kind: string(RecordFidelityActionID), Diff: diff,
					Reversibility:       operation.Irreversible,
					ReversibilityReason: "the fidelity report is a record of the import; it is never edited",
				},
				Payload: fidelityPayload{Tenant: tid, JobID: in.JobID, Rows: rows},
			}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, p operation.TypedStep[fidelityPayload]) (FidelityOutcome, error) {
			if err := insertFidelity(ctx, s, p.Payload.Tenant, p.Payload.JobID, p.Payload.Rows); err != nil {
				return FidelityOutcome{}, err
			}
			out := FidelityOutcome{Items: len(p.Payload.Rows), ByClass: map[string]int{}}
			for _, c := range p.Payload.Rows {
				out.ByClass[string(c.Class)]++
				if c.Proposal != nil {
					out.Proposals++
				}
			}
			return out, nil
		},
		Verify: func(ctx context.Context, s step.Step, p operation.TypedStep[fidelityPayload], o FidelityOutcome) (operation.Verdict, error) {
			by, props, err := counts(ctx, s.Tx(), p.Payload.JobID)
			if err != nil {
				return operation.Verdict{}, err
			}
			total := 0
			for c, n := range by {
				total += n
				if o.ByClass[c] != n {
					return operation.Verdict{Reason: "fidelity_not_as_applied"}, nil
				}
			}
			return operation.Verdict{OK: total == o.Items && props == o.Proposals, Reason: "fidelity_not_as_applied"}, nil
		},
		Inverse: func(operation.TypedStep[fidelityPayload], FidelityOutcome) (RecordFidelityInput, error) {
			return RecordFidelityInput{}, operation.ErrIrreversible
		},
	})
}
