package schedule

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
)

// Action ids (ADR-0005 rule 10). Runs and deliveries are not Actions: a fire is a job.
const (
	CreateID   operation.ActionID = "reports.schedule.create"
	UpdateID   operation.ActionID = "reports.schedule.update"
	PauseID    operation.ActionID = "reports.schedule.pause"
	ResumeID   operation.ActionID = "reports.schedule.resume"
	ReassignID operation.ActionID = "reports.schedule.reassign"
	DeleteID   operation.ActionID = "reports.schedule.delete"
	RestoreID  operation.ActionID = "reports.schedule.restore"
)

// IDInput is the input of pause and delete.
type IDInput struct {
	ScheduleID string `json:"scheduleId"`
}

// ResumeInput is the API's ReportScheduleResume plus the id: the caller confirms every external recipient
// classified now (R5).
type ResumeInput struct {
	ScheduleID        string   `json:"scheduleId"`
	ConfirmedExternal []string `json:"confirmedExternal"`
}

// ReassignInput is the API's ReportScheduleReassign plus the id.
type ReassignInput struct {
	ScheduleID     string `json:"scheduleId"`
	OwnerAccountID string `json:"ownerAccountId"`
}

// Restore modes: the inverse of each Action (reports.md 8 "Preview and undo").
const (
	ModeVersion      = "version"       // the content of a version
	ModeArchive      = "archive"       // undo of create
	ModeReassignBack = "reassign_back" // undo of reassign: the previous owner, still paused (Lossy)
)

// RestoreInput is the input of reports.schedule.restore, the inverse of every other Action.
type RestoreInput struct {
	ScheduleID string `json:"scheduleId"`
	Mode       string `json:"mode"`
	// Version is the version whose content is restored (ModeVersion, ModeReassignBack).
	Version int `json:"version,omitempty"`
	// Expect is the version the undone operation wrote: a different current version is "superseded".
	Expect int `json:"expect"`
	// ConfirmedExternal is the external set the restored content held when it was written; the step-up
	// predicate reads it, and Plan requires every external recipient classified now to be in it.
	ConfirmedExternal []string `json:"confirmedExternal,omitempty"`
}

type payload struct {
	ScheduleID string   `json:"scheduleId"`
	From       int      `json:"from"`
	Prev       *Content `json:"prev,omitempty"`
	Next       Content  `json:"next"`
	Mode       string   `json:"mode,omitempty"`
}

// Outcome is what an Action did: the version the schedule is at now.
type Outcome struct {
	Version int `json:"version"`
}

func target(id string) authority.TargetRef {
	return authority.TargetRef{GUID: id, Class: rbac.TargetClassReportSchedule}
}

func ids(in string) error {
	if !uuidRe.MatchString(in) {
		return fmt.Errorf("%w: scheduleId must be a canonical lower-case UUID", operation.ErrInvalid)
	}
	return nil
}

// stepUpIfExternal is the SX-1 predicate: the after-state has an external recipient, as the caller confirmed
// it. Plan refuses a write whose confirmed set is not the classified set, so the predicate cannot be dodged.
func stepUpIfExternal(set func(in operation.Input) ([]string, error)) func(operation.Input) (bool, error) {
	return func(in operation.Input) (bool, error) {
		s, err := set(in)
		return len(s) > 0, err
	}
}

func confirmedOf[T any](get func(T) []string) func(operation.Input) ([]string, error) {
	return func(in operation.Input) ([]string, error) {
		var v T
		if err := jsonv2.Unmarshal(in, &v); err != nil {
			return nil, err
		}
		return get(v), nil
	}
}

// diff is the preview of a write: each changed attribute, before and after.
func diff(prev *Content, next Content, ext []string) []operation.Change {
	var out []operation.Change
	add := func(attr, before, after string) {
		if before != after {
			out = append(out, operation.Change{Attribute: attr, Before: one(before), After: one(after)})
		}
	}
	var p Content
	if prev != nil {
		p = *prev
	}
	add("name", p.Name, next.Name)
	add("definition", strings.TrimSpace(p.DefinitionID+" v"+itoa(p.DefinitionVersion)), next.DefinitionID+" v"+itoa(next.DefinitionVersion))
	add("preset", p.Preset, next.Preset)
	add("parameters", string(p.Params), string(next.Params))
	add("recurrence", recText(p), recText(next))
	add("time_zone", p.TimeZone, next.TimeZone)
	add("owner", p.Owner, next.Owner)
	add("notify_only_if_data", fmtBool(prev != nil && p.NotifyOnlyIfData), fmtBool(next.NotifyOnlyIfData))
	add("state", string(p.State), string(next.State))
	add("pause_reason", p.PauseReason, next.PauseReason)
	add("recipients", recipientsText(p.Recipients), recipientsText(next.Recipients))
	if len(ext) > 0 {
		out = append(out, operation.Change{Attribute: "data_leaves_organisation", After: ext})
	}
	return out
}

func one(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
func itoa(n int) string { return strconv.Itoa(n) }
func fmtBool(b bool) string {
	return strconv.FormatBool(b)
}
func recText(c Content) string {
	if c.Recurrence.Kind == "" {
		return ""
	}
	b, _ := jsonv2.Marshal(c.Recurrence, jsonv2.Deterministic(true))
	return string(b) + " " + c.TimeZone
}
func recipientsText(rs []Recipient) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		k, _ := r.key()
		l := ""
		if r.AsLink {
			l = " link"
		}
		parts = append(parts, k+" ["+strings.Join(r.Formats, ",")+"]"+l)
	}
	return strings.Join(parts, "; ")
}

func (e *Env) step(tr string, prev *Content, from int, next Content, ext []string, mode string, class operation.Reversibility, id string) []operation.TypedStep[payload] {
	var conf []operation.Confirmation
	if len(ext) > 0 {
		conf = []operation.Confirmation{{Kind: ConfirmExternal, Items: ext}}
	}
	return []operation.TypedStep[payload]{{
		Plan: operation.StepPlan{Target: target(id), Kind: "reports.schedule." + tr, Diff: diff(prev, next, ext),
			Reversibility: class, Confirmations: conf},
		Payload: payload{ScheduleID: id, From: from, Prev: prev, Next: next, Mode: mode},
	}}
}

// actor is the id of the principal the plan is for.
func actor(pc operation.PlanContext) string { return string(pc.Actor.Requester.ID) }

func (e *Env) current(ctx context.Context, pc operation.PlanContext, id string) (Schedule, error) {
	if err := ids(id); err != nil {
		return Schedule{}, err
	}
	cur, err := e.Store.Get(ctx, pc.Tx, id, false)
	if errors.Is(err, ErrNotFound) {
		return Schedule{}, fmt.Errorf("%w: no such schedule", operation.ErrInvalid)
	}
	if err != nil {
		return Schedule{}, err
	}
	if cur.State == Archived {
		return Schedule{}, refuse(CodeNotActive)
	}
	return cur, nil
}

// checkExternal applies R4 and the confirmation rule to the after-state's external recipients. exact is the
// rule of a write the caller confirmed (the set must equal the classified one); a restore accepts a superset.
func (e *Env) checkExternal(ctx context.Context, pc operation.PlanContext, rs []Recipient, confirmed []string, exact bool) ([]string, error) {
	ext, err := e.External(ctx, pc.Tx, rs)
	if err != nil || len(ext) == 0 {
		return nil, err
	}
	if ok, err := e.allow(ctx, pc.Tenant, pc.Actor, e.Perm.DeliverExternal); err != nil {
		return nil, err
	} else if !ok {
		return nil, refuse(CodeExternalNotAllowed)
	}
	if (exact && !SameSet(confirmed, ext)) || (!exact && !subset(ext, confirmed)) {
		return nil, refuse(CodeExternalUnconfirm)
	}
	return ext, nil
}

func (e *Env) content(in WriteInput, owner string, state State, reason string, ck Checked, ext []string) Content {
	return Content{Name: in.Name, DefinitionID: in.DefinitionID, DefinitionVersion: ck.Version, Preset: ck.Preset, Params: jsontext.Value(ck.Params),
		Recurrence: in.Recurrence, TimeZone: in.TimeZone, Owner: owner, NotifyOnlyIfData: in.NotifyOnlyIfData, ConfirmedExternal: ext,
		State: state, PauseReason: reason, Recipients: in.Recipients}
}

func (e *Env) apply(tr string) func(ctx context.Context, s step.Step, p operation.TypedStep[payload]) (Outcome, error) {
	return func(ctx context.Context, s step.Step, p operation.TypedStep[payload]) (Outcome, error) {
		tx := s.Tx()
		if tx == nil {
			return Outcome{}, errors.New("schedule: a schedule write needs the runner's transaction")
		}
		by, pl, now := string(s.Actor().Requester.ID), p.Payload, e.now()
		if pl.From == 0 { // create
			if err := e.Store.Create(ctx, tx, pl.ScheduleID, pl.Next, by, now); err != nil {
				return Outcome{}, err
			}
			return Outcome{Version: 1}, nil
		}
		v, err := e.Store.Replace(ctx, tx, pl.ScheduleID, pl.From, pl.Next, by, now)
		if errors.Is(err, ErrStale) {
			return Outcome{}, fmt.Errorf("%w: the schedule changed since the plan", operation.ErrStaleState)
		}
		return Outcome{Version: v}, err
	}
}

func (e *Env) verify(ctx context.Context, s step.Step, p operation.TypedStep[payload], o Outcome) (operation.Verdict, error) {
	got, err := e.Store.Get(ctx, s.Tx(), p.Payload.ScheduleID, false)
	if err != nil {
		return operation.Verdict{}, err
	}
	if got.Version != o.Version || got.State != p.Payload.Next.State || got.Owner != p.Payload.Next.Owner {
		return operation.Verdict{Reason: "schedule_state_not_as_applied"}, nil
	}
	return operation.Verdict{OK: true}, nil
}

// restoreOf is the inverse of every Action but restore itself.
func restoreOf(p operation.TypedStep[payload], o Outcome) (RestoreInput, error) {
	pl := p.Payload
	switch {
	case pl.From == 0:
		return RestoreInput{ScheduleID: pl.ScheduleID, Mode: ModeArchive, Expect: o.Version}, nil
	case pl.Mode == ModeReassignBack:
		return RestoreInput{ScheduleID: pl.ScheduleID, Mode: ModeReassignBack, Version: pl.From, Expect: o.Version}, nil
	}
	in := RestoreInput{ScheduleID: pl.ScheduleID, Mode: ModeVersion, Version: pl.From, Expect: o.Version}
	if pl.Prev != nil {
		in.ConfirmedExternal = pl.Prev.ConfirmedExternal
	}
	return in, nil
}

func (e *Env) typed(id operation.ActionID, in string, audit audit.Kind, perm authz.Permission, class operation.Reversibility, stepUp func(operation.Input) (bool, error)) operation.Descriptor {
	return operation.Descriptor{ID: id, Version: 1, Permission: perm, Input: operation.SchemaRef("#/components/schemas/" + in), Target: operation.TargetStore,
		Reversibility: class, AuditKind: audit, StepUpWhen: stepUp}
}

// Actions builds the seven schedule Actions over the environment.
func (e *Env) Actions() ([]operation.Action, error) {
	var out []operation.Action
	for _, f := range []func() (operation.Action, error){e.create, e.update, e.pause, e.resume, e.reassign, e.delete, e.restore} {
		a, err := f()
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func (e *Env) write(tr string, id operation.ActionID, kind audit.Kind, create bool) (operation.Action, error) {
	return withRestore(operation.Define(operation.Typed[WriteInput, payload, Outcome]{
		Descriptor: e.typed(id, "ReportScheduleWrite", kind, e.Perm.Schedule, operation.Reversible,
			stepUpIfExternal(confirmedOf(func(w WriteInput) []string { return w.ConfirmedExternal }))),
		Plan: func(ctx context.Context, pc operation.PlanContext, in WriteInput) ([]operation.TypedStep[payload], error) {
			if err := ids(in.ScheduleID); err != nil {
				return nil, err
			}
			if err := in.Validate(); err != nil {
				return nil, fmt.Errorf("%w: %w", operation.ErrInvalid, err)
			}
			var cur Schedule
			var prev *Content
			owner, from, state, reason := actor(pc), 0, Active, ""
			if create {
				if taken, err := e.Store.Exists(ctx, pc.Tx, in.ScheduleID); err != nil {
					return nil, err
				} else if taken {
					return nil, fmt.Errorf("%w: the schedule id is taken", operation.ErrInvalid)
				}
			} else {
				var err error
				if cur, err = e.current(ctx, pc, in.ScheduleID); err != nil {
					return nil, err
				}
				if cur.Owner != owner {
					return nil, refuse(CodeNotOwner) // manage_all never edits (R1)
				}
				c := cur.Content()
				prev, from, state, reason = &c, cur.Version, cur.State, cur.PauseReason
			}
			ck, err := e.CheckDefinition(in)
			if err != nil {
				return nil, err
			}
			ext, err := e.checkExternal(ctx, pc, in.Recipients, in.ConfirmedExternal, true)
			if err != nil {
				return nil, err
			}
			if state == Active {
				if err := e.CanWriteActive(ctx, pc.Tx, pc.Tenant, pc.Actor); err != nil {
					return nil, err
				}
			}
			next := e.content(in, owner, state, reason, ck, ext)
			return e.step(tr, prev, from, next, ext, "", operation.Reversible, in.ScheduleID), nil
		},
		Apply:   e.apply(tr),
		Verify:  e.verify,
		Inverse: func(operation.TypedStep[payload], Outcome) (WriteInput, error) { var z WriteInput; return z, nil }, // replaced by withRestore
	}))
}

func (e *Env) create() (operation.Action, error) {
	return e.write("create", CreateID, AuditCreated, true)
}
func (e *Env) update() (operation.Action, error) {
	return e.write("update", UpdateID, AuditUpdated, false)
}

// transition builds pause, resume, reassign and delete: the same row, a different state.
func (e *Env) pause() (operation.Action, error) {
	return withRestore(operation.Define(operation.Typed[IDInput, payload, Outcome]{
		Descriptor: e.typed(PauseID, "ReportSchedulePause", AuditPaused, e.Perm.Schedule, operation.Reversible, nil),
		Plan: func(ctx context.Context, pc operation.PlanContext, in IDInput) ([]operation.TypedStep[payload], error) {
			cur, err := e.current(ctx, pc, in.ScheduleID)
			if err != nil {
				return nil, err
			}
			if cur.State != Active {
				return nil, refuse(CodeAlreadyPaused)
			}
			if cur.Owner != actor(pc) { // the owner, or manage_all (R1: pause is see, pause, reassign)
				if ok, err := e.allow(ctx, pc.Tenant, pc.Actor, e.Perm.ManageAll); err != nil {
					return nil, err
				} else if !ok {
					return nil, refuse(CodeNotOwner)
				}
			}
			prev := cur.Content()
			next := prev
			next.State, next.PauseReason = Paused, PauseByUser
			return e.step("pause", &prev, cur.Version, next, nil, "", operation.Reversible, cur.ID), nil
		},
		Apply: e.apply("pause"), Verify: e.verify,
		Inverse: func(operation.TypedStep[payload], Outcome) (IDInput, error) { var z IDInput; return z, nil }, // replaced by withRestore
	}))
}

func (e *Env) resume() (operation.Action, error) {
	return withRestore(operation.Define(operation.Typed[ResumeInput, payload, Outcome]{
		Descriptor: e.typed(ResumeID, "ReportScheduleResume", AuditResumed, e.Perm.Schedule, operation.Reversible,
			stepUpIfExternal(confirmedOf(func(r ResumeInput) []string { return r.ConfirmedExternal }))),
		Plan: func(ctx context.Context, pc operation.PlanContext, in ResumeInput) ([]operation.TypedStep[payload], error) {
			cur, err := e.current(ctx, pc, in.ScheduleID)
			if err != nil {
				return nil, err
			}
			if cur.State != Paused {
				return nil, refuse(CodeAlreadyActive)
			}
			if cur.Owner != actor(pc) {
				return nil, refuse(CodeNotOwner)
			}
			ext, err := e.checkExternal(ctx, pc, cur.Recipients, in.ConfirmedExternal, true)
			if err != nil {
				return nil, err
			}
			if err := e.CanWriteActive(ctx, pc.Tx, pc.Tenant, pc.Actor); err != nil {
				return nil, err
			}
			prev := cur.Content()
			next := prev
			next.State, next.PauseReason, next.ConfirmedExternal = Active, "", ext
			return e.step("resume", &prev, cur.Version, next, ext, "", operation.Reversible, cur.ID), nil
		},
		Apply: e.apply("resume"), Verify: e.verify,
		Inverse: func(operation.TypedStep[payload], Outcome) (ResumeInput, error) { var z ResumeInput; return z, nil }, // replaced by withRestore
	}))
}

func (e *Env) reassign() (operation.Action, error) {
	return withRestore(operation.Define(operation.Typed[ReassignInput, payload, Outcome]{
		Descriptor: e.typed(ReassignID, "ReportScheduleReassign", AuditReassign, e.Perm.ManageAll, operation.Lossy, nil),
		Plan: func(ctx context.Context, pc operation.PlanContext, in ReassignInput) ([]operation.TypedStep[payload], error) {
			cur, err := e.current(ctx, pc, in.ScheduleID)
			if err != nil {
				return nil, err
			}
			if ok, err := e.allow(ctx, pc.Tenant, pc.Actor, e.Perm.ManageAll); err != nil {
				return nil, err
			} else if !ok {
				return nil, refuse(CodeManageAllRequired)
			}
			if !uuidRe.MatchString(in.OwnerAccountID) {
				return nil, fmt.Errorf("%w: ownerAccountId must be a UUID", operation.ErrInvalid)
			}
			if active, err := e.Owners.Active(ctx, pc.Tx, pc.Tenant, in.OwnerAccountID); err != nil {
				return nil, err
			} else if !active {
				return nil, refuse(CodeOwnerNotActive)
			}
			prev := cur.Content()
			next := prev
			// The new owner's authority is not the old one's: the schedule waits, paused, for the new owner to resume it.
			next.Owner, next.State, next.PauseReason = in.OwnerAccountID, Paused, PauseReassigned
			return e.step("reassign", &prev, cur.Version, next, nil, ModeReassignBack, operation.Lossy, cur.ID), nil
		},
		Apply: e.apply("reassign"), Verify: e.verify,
		Inverse: func(operation.TypedStep[payload], Outcome) (ReassignInput, error) { var z ReassignInput; return z, nil }, // replaced by withRestore
	}))
}

func (e *Env) delete() (operation.Action, error) {
	return withRestore(operation.Define(operation.Typed[IDInput, payload, Outcome]{
		Descriptor: e.typed(DeleteID, "ReportScheduleDelete", AuditDeleted, e.Perm.Schedule, operation.Reversible, nil),
		Plan: func(ctx context.Context, pc operation.PlanContext, in IDInput) ([]operation.TypedStep[payload], error) {
			cur, err := e.current(ctx, pc, in.ScheduleID)
			if err != nil {
				return nil, err
			}
			if cur.Owner != actor(pc) { // manage_all never deletes (R2)
				return nil, refuse(CodeNotOwner)
			}
			prev := cur.Content()
			next := prev
			next.State, next.PauseReason = Archived, ""
			return e.step("delete", &prev, cur.Version, next, nil, "", operation.Reversible, cur.ID), nil
		},
		Apply: e.apply("delete"), Verify: e.verify,
		Inverse: func(operation.TypedStep[payload], Outcome) (IDInput, error) { var z IDInput; return z, nil }, // replaced by withRestore
	}))
}

// restore is the inverse of every Action, planned for the principal undoing (ADR-0005 rule 10): it makes the
// checks of the transition it performs, and is refused as superseded when the schedule moved on.
func (e *Env) restore() (operation.Action, error) {
	return operation.Define(operation.Typed[RestoreInput, payload, Outcome]{
		Descriptor: e.typed(RestoreID, "ReportScheduleRestore", AuditRestored, e.Perm.Schedule, operation.Reversible,
			stepUpIfExternal(confirmedOf(func(r RestoreInput) []string { return r.ConfirmedExternal }))),
		Plan: func(ctx context.Context, pc operation.PlanContext, in RestoreInput) ([]operation.TypedStep[payload], error) {
			if err := ids(in.ScheduleID); err != nil {
				return nil, err
			}
			cur, err := e.Store.Get(ctx, pc.Tx, in.ScheduleID, false)
			if errors.Is(err, ErrNotFound) {
				return nil, fmt.Errorf("%w: no such schedule", operation.ErrInvalid)
			}
			if err != nil {
				return nil, err
			}
			if cur.Version != in.Expect {
				return nil, refuse(CodeSuperseded)
			}
			prev := cur.Content()
			var next Content
			switch in.Mode {
			case ModeArchive:
				next = prev
				next.State, next.PauseReason = Archived, ""
			case ModeVersion, ModeReassignBack:
				if next, err = e.Store.Version(ctx, pc.Tx, in.ScheduleID, in.Version); err != nil {
					return nil, fmt.Errorf("%w: no such version", operation.ErrInvalid)
				}
				if in.Mode == ModeReassignBack {
					next.State, next.PauseReason = Paused, PauseReassigned
				}
			default:
				return nil, fmt.Errorf("%w: unknown restore mode", operation.ErrInvalid)
			}
			isOwner := cur.Owner == actor(pc)
			var ext []string
			switch {
			case in.Mode == ModeReassignBack:
				if ok, err := e.allow(ctx, pc.Tenant, pc.Actor, e.Perm.ManageAll); err != nil {
					return nil, err
				} else if !ok {
					return nil, refuse(CodeManageAllRequired)
				}
			case next.State == Paused && cur.State == Active && in.Mode == ModeVersion: // undo of a resume is a pause
				if !isOwner {
					if ok, err := e.allow(ctx, pc.Tenant, pc.Actor, e.Perm.ManageAll); err != nil {
						return nil, err
					} else if !ok {
						return nil, refuse(CodeNotOwner)
					}
				}
			default:
				if !isOwner {
					return nil, refuse(CodeNotOwner)
				}
				if in.Mode != ModeArchive {
					if ext, err = e.checkExternal(ctx, pc, next.Recipients, in.ConfirmedExternal, false); err != nil {
						return nil, err
					}
					next.ConfirmedExternal = ext
					if next.State == Active {
						if err := e.CanWriteActive(ctx, pc.Tx, pc.Tenant, pc.Actor); err != nil {
							return nil, err
						}
					}
				}
			}
			return e.step("restore", &prev, cur.Version, next, ext, in.Mode, operation.Reversible, cur.ID), nil
		},
		Apply: e.apply("restore"), Verify: e.verify,
		// The inverse of a restore is a restore of the version it replaced.
		Inverse: func(p operation.TypedStep[payload], o Outcome) (RestoreInput, error) {
			in := RestoreInput{ScheduleID: p.Payload.ScheduleID, Mode: ModeVersion, Version: p.Payload.From, Expect: o.Version}
			if p.Payload.Prev != nil {
				in.ConfirmedExternal = p.Payload.Prev.ConfirmedExternal
			}
			return in, nil
		},
	})
}

// withRestore makes the kernel's inverse of a schedule Action a reports.schedule.restore input: the Typed form
// can only return the Action's own input type, and the inverse of every schedule write is a restore.
func withRestore(a operation.Action, err error) (operation.Action, error) {
	if err != nil {
		return nil, err
	}
	return restoring{a}, nil
}

type restoring struct{ operation.Action }

// Inverse implements operation.Action.
func (r restoring) Inverse(p operation.StepPlan, o operation.Outcome) (operation.Input, error) {
	var pl payload
	if err := jsonv2.Unmarshal(p.Payload, &pl); err != nil {
		return nil, fmt.Errorf("%w: payload does not decode", operation.ErrInvalid)
	}
	var out Outcome
	if len(o.Payload) > 0 {
		if err := jsonv2.Unmarshal(o.Payload, &out); err != nil {
			return nil, fmt.Errorf("%w: outcome does not decode", operation.ErrInvalid)
		}
	}
	in, err := restoreOf(operation.TypedStep[payload]{Plan: p, Payload: pl}, out)
	if err != nil {
		return nil, err
	}
	return jsonv2.Marshal(in, jsonv2.Deterministic(true))
}
