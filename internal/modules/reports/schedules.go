package reports

import (
	"context"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/api"
	"github.com/skenzeriq/activediq/internal/modules/reports/export"
	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/modules/reports/schedule"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/notify/delivery"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/opapi"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Schedules is what the schedule handlers need beyond the run and export services (reports.md 8, row B11).
type Schedules struct {
	Env        *schedule.Env
	Fire       *schedule.Fire
	Runner     *operation.Runner
	DB         *store.DB
	Deliveries *delivery.Deliveries
	// FreshStepUp answers whether the session is inside the step-up window (nil: never).
	FreshStepUp func(ctx context.Context, t tenant.ID, sessionID string) (bool, error)
	Family      opapi.Family
}

func (h *Handlers) sched() (*Schedules, error) {
	if h.Schedules == nil || h.Schedules.Runner == nil || h.Schedules.DB == nil {
		return nil, apitypes.NotImplemented("report schedules are not configured")
	}
	return h.Schedules, nil
}

// freshCaller is opapi.Caller: the tenant, the chain and whether the session is inside the step-up window.
func (h *Handlers) freshCaller(ctx context.Context) (tenant.ID, authority.Chain, bool, error) {
	tid, chain, err := h.caller(ctx)
	if err != nil {
		return tid, chain, false, err
	}
	fresh := false
	if p, ok := apihost.PrincipalFrom(ctx); ok && h.Schedules != nil && h.Schedules.FreshStepUp != nil && p.SessionID != "" {
		if fresh, err = h.Schedules.FreshStepUp(ctx, tid, p.SessionID); err != nil {
			return tid, chain, false, apitypes.Internal("")
		}
	}
	return tid, chain, fresh, nil
}

func etag(v int) string { return `"` + strconv.Itoa(v) + `"` }

// ---- reads ------------------------------------------------------------------------------------

// visible reads a schedule the caller may see: its owner, or a holder of reports.schedule.manage_all. Anyone
// else, and a missing id, answer 404 (a schedule's existence is not disclosed).
func (h *Handlers) visible(ctx context.Context, sd *Schedules, tid tenant.ID, c authority.Chain, id string) (schedule.Schedule, error) {
	var s schedule.Schedule
	err := sd.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) (err error) {
		s, err = sd.Env.Store.Get(ctx, tx, id, false)
		return err
	})
	if errors.Is(err, schedule.ErrNotFound) {
		return s, apitypes.NotFound("")
	}
	if err != nil {
		return s, apitypes.Internal("")
	}
	if s.State == schedule.Archived {
		return s, apitypes.NotFound("")
	}
	if s.Owner != string(c.Requester.ID) {
		ok, err := sd.Env.CanManageAll(ctx, tid, c)
		if err != nil {
			return s, apitypes.Internal("")
		}
		if !ok {
			return s, apitypes.NotFound("")
		}
	}
	return s, nil
}

// view builds the API schedule: the stored header, the recipients with their delivery state from the latest
// fire, and the external flag classified now.
func (h *Handlers) view(ctx context.Context, sd *Schedules, tx store.Tx, s schedule.Schedule) (api.ReportSchedule, error) {
	ext, err := sd.Env.External(ctx, tx, s.Recipients)
	if err != nil {
		return api.ReportSchedule{}, err
	}
	last, err := sd.Env.Store.LastFire(ctx, tx, s.ID)
	if err != nil {
		return api.ReportSchedule{}, err
	}
	rs := make([]map[string]any, 0, len(s.Recipients))
	for i, r := range s.Recipients {
		m := map[string]any{"kind": r.Kind, "formats": r.Formats, "delivery": h.deliveryView(ctx, sd, tx, last, i, r)}
		if r.Kind == "account" {
			m["accountId"], m["asLink"] = r.AccountID, r.AsLink
		} else {
			a, err := schedule.CanonicalAddress(r.Address)
			if err != nil {
				a = r.Address
			}
			m["address"], m["external"] = a, containsStr(ext, a)
		}
		rs = append(rs, m)
	}
	var preset any
	if s.Preset != "" {
		preset = s.Preset
	}
	var next any
	if s.NextRunAt != nil {
		next = s.NextRunAt.UTC().Format(time.RFC3339Nano)
	}
	m := map[string]any{"id": s.ID, "name": s.Name, "ownerAccountId": s.Owner, "definitionId": s.DefinitionID,
		"definitionVersion": s.DefinitionVersion, "presetId": preset,
		"parameters": paramsView(run.Run{Params: s.Params, Columns: sd.Env.Columns(s)}), "recurrence": s.Recurrence,
		"timeZone": s.TimeZone, "recipients": rs, "notifyOnlyIfData": s.NotifyOnlyIfData, "state": string(s.State), "nextRunAt": next,
		"createdAt": s.CreatedAt.UTC().Format(time.RFC3339Nano), "updatedAt": s.UpdatedAt.UTC().Format(time.RFC3339Nano)}
	if s.State == schedule.Paused {
		m["pausedReason"] = s.PauseReason
	}
	if lr := lastRun(last); lr != nil {
		m["lastRun"] = lr
	}
	b, err := jsonv2.Marshal(m)
	if err != nil {
		return api.ReportSchedule{}, err
	}
	var out api.ReportSchedule
	return out, jsonv2.Unmarshal(b, &out)
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func lastRun(l *schedule.Last) map[string]any {
	if l == nil || l.RunID == "" || l.State == "queued" || l.State == "running" {
		return nil
	}
	outcome := "failed"
	switch l.State {
	case "nothing_to_send":
		outcome = "nothing_to_send"
	case "sent":
		outcome = "sent"
		for _, r := range l.Recipients {
			if r.Outcome == "failed" {
				outcome = "partly_failed"
			}
		}
	}
	return map[string]any{"runId": l.RunID, "startedAt": l.StartedAt.UTC().Format(time.RFC3339Nano), "outcome": outcome}
}

// deliveryReason maps a fire's recipient reason to the contract's open ReportDeliveryReason.
func deliveryReason(code string) string {
	switch code {
	case schedule.ReasonOwnerExternal:
		return "external_not_permitted"
	case schedule.ReasonBecameExternal, schedule.ReasonAccountExternal:
		return "address_no_longer_allowed"
	case schedule.ReasonTooLarge:
		return "attachment_too_large"
	}
	return "internal"
}

// deliveryView is the delivery state of recipient i for the latest fire: what the fire decided, then what the
// DM-84 row says once it was queued.
func (h *Handlers) deliveryView(ctx context.Context, sd *Schedules, tx store.Tx, l *schedule.Last, i int, r schedule.Recipient) map[string]any {
	none := map[string]any{"state": "none_yet", "updatedAt": nil}
	if l == nil {
		return none
	}
	at := l.UpdatedAt.UTC().Format(time.RFC3339Nano)
	for _, x := range l.Recipients {
		if x.Ordinal != i {
			continue
		}
		if x.Outcome == "failed" {
			return map[string]any{"state": "failed", "reason": deliveryReason(x.Reason), "updatedAt": at}
		}
		state := "queued"
		if sd.Deliveries != nil {
			rc := delivery.Recipient{Account: r.AccountID}
			if r.Kind != "account" {
				rc = delivery.Recipient{Address: r.Address}
			}
			if d, ok, err := sd.Deliveries.ForSource(ctx, tx, delivery.SourceRef{Kind: export.SourceKind, ID: l.ExportFor(r)}, rc); err == nil && ok {
				state = string(d.State)
				if d.State == delivery.Failed {
					return map[string]any{"state": "failed", "reason": "mail_rejected", "updatedAt": at}
				}
				if d.State == delivery.GivenUp {
					return map[string]any{"state": "given_up", "reason": "mail_rejected", "updatedAt": at}
				}
			}
		}
		return map[string]any{"state": state, "updatedAt": at}
	}
	return none
}

// GetReportSchedule implements api.Handlers.
func (h *Handlers) GetReportSchedule(ctx context.Context, in api.GetReportScheduleInput) (api.GetReportScheduleOutput, error) {
	sd, err := h.sched()
	if err != nil {
		return nil, err
	}
	tid, c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	s, err := h.visible(ctx, sd, tid, c, in.ScheduleID.String())
	if err != nil {
		return nil, err
	}
	var v api.ReportSchedule
	if err := sd.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) (err error) {
		v, err = h.view(ctx, sd, tx, s)
		return err
	}); err != nil {
		return nil, apitypes.Internal("")
	}
	return api.GetReportSchedule200{Body: v, ETag: etag(s.Version)}, nil
}

// ListReportSchedules implements api.Handlers: the caller's own schedules, or (owner=any) every owner's for
// a holder of reports.schedule.manage_all.
func (h *Handlers) ListReportSchedules(ctx context.Context, in api.ListReportSchedulesInput) (api.ListReportSchedulesOutput, error) {
	sd, err := h.sched()
	if err != nil {
		return nil, err
	}
	tid, c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	owner := string(c.Requester.ID)
	if in.Owner != nil && *in.Owner == api.ReportScheduleOwnerAny {
		ok, err := sd.Env.CanManageAll(ctx, tid, c)
		if err != nil {
			return nil, apitypes.Internal("")
		}
		if !ok {
			return nil, apitypes.Forbidden("")
		}
		owner = ""
	}
	limit := 50
	if in.Limit != nil {
		limit = int(*in.Limit)
	}
	var after *schedule.Cursor
	if in.Cursor != nil {
		if after, err = decodeScheduleCursor(string(*in.Cursor)); err != nil {
			return nil, apitypes.Validation("the cursor is not valid")
		}
	}
	items := []api.ReportSchedule{}
	var next *string
	err = sd.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		pg, err := sd.Env.Store.List(ctx, tx, owner, after, limit)
		if err != nil {
			return err
		}
		for _, s := range pg.Items {
			v, err := h.view(ctx, sd, tx, s)
			if err != nil {
				return err
			}
			items = append(items, v)
		}
		if pg.Next != nil {
			x := encodeScheduleCursor(*pg.Next)
			next = &x
		}
		return nil
	})
	if err != nil {
		return nil, apitypes.Internal("")
	}
	return api.ListReportSchedules200{Body: api.ReportScheduleList{Items: items, Page: apitypes.PageInfo{NextCursor: next}}}, nil
}

func encodeScheduleCursor(c schedule.Cursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(c.At.UTC().Format(time.RFC3339Nano) + "|" + c.ID))
}

func decodeScheduleCursor(s string) (*schedule.Cursor, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	at, id, ok := strings.Cut(string(b), "|")
	if !ok {
		return nil, errors.New("cursor")
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return nil, err
	}
	if _, err := apitypes.ParseUUID(id); err != nil {
		return nil, err
	}
	return &schedule.Cursor{At: t, ID: id}, nil
}

// ---- writes -----------------------------------------------------------------------------------

// refusalProblem maps a Plan refusal to its problem (reports.md 8 "refusal codes"): 403 for the rules of
// authority, 409 for a state that moved, 404 for an unknown definition, 400 for the rest, each with the
// stable code in errors[].
func refusalProblem(code string) *apitypes.Problem {
	var p *apitypes.Problem
	switch code {
	case schedule.CodeNotOwner, schedule.CodeManageAllRequired, schedule.CodeExternalNotAllowed:
		p = apitypes.Forbidden("")
	case schedule.CodeSuperseded, schedule.CodeNotActive, schedule.CodeAlreadyPaused, schedule.CodeAlreadyActive:
		p = apitypes.Conflict("The schedule is not in a state this change applies to.")
	case schedule.CodeUnknownDefinition:
		p = apitypes.NotFound("")
	default:
		p = apitypes.Validation("The schedule is refused: " + code)
	}
	p.Errors = []apitypes.ProblemError{{Code: code, Detail: code, In: apitypes.ProblemErrorInBody, Pointer: ""}}
	return p
}

func (h *Handlers) scheduleErr(err error) error {
	var pr *operation.PlanRefusal
	switch {
	case err == nil:
		return nil
	case errors.As(err, &pr):
		return refusalProblem(pr.Code)
	case errors.Is(err, schedule.ErrInvalid):
		return apitypes.Validation(err.Error())
	case errors.Is(err, operation.ErrStaleState), errors.Is(err, schedule.ErrStale):
		return apitypes.Conflict("The schedule changed since it was read.")
	}
	return opapi.Problem(err)
}

func newOpID() (step.OperationID, error) {
	return step.OperationID(run.NewID().String()), nil
}

func (h *Handlers) toWrite(id string, body api.ReportScheduleWrite) (schedule.WriteInput, error) {
	raw, err := jsonv2.Marshal(body)
	if err != nil {
		return schedule.WriteInput{}, apitypes.Validation("the schedule could not be read")
	}
	var in schedule.WriteInput
	if err := jsonv2.Unmarshal(raw, &in); err != nil {
		return in, apitypes.Validation("the schedule could not be read")
	}
	in.ScheduleID = id
	return in, nil
}

func confirmations(items []string) []operation.Confirmation {
	if len(items) == 0 {
		return nil
	}
	return []operation.Confirmation{{Kind: schedule.ConfirmExternal, Items: items}}
}

// classify returns the external set of the recipients now: a preview is filled with it so its step-up flag
// and its required confirmations are the ones a write must carry.
func (h *Handlers) classify(ctx context.Context, sd *Schedules, tid tenant.ID, rs []schedule.Recipient) ([]string, error) {
	var ext []string
	err := sd.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) (err error) {
		ext, err = sd.Env.External(ctx, tx, rs)
		return err
	})
	if errors.Is(err, schedule.ErrInvalid) {
		return nil, apitypes.Validation(err.Error())
	}
	if err != nil {
		return nil, apitypes.Internal("")
	}
	return ext, nil
}

func (h *Handlers) preview(ctx context.Context, sd *Schedules, tid tenant.ID, c authority.Chain, action operation.ActionID, input any) (api.PreviewCreateReportSchedule200, error) {
	raw, err := jsonv2.Marshal(input)
	if err != nil {
		return api.PreviewCreateReportSchedule200{}, apitypes.Internal("")
	}
	p, err := sd.Runner.PreviewStore(ctx, operation.Request{Tenant: tid, Actor: c, Action: action, Input: raw})
	if err != nil {
		return api.PreviewCreateReportSchedule200{}, h.scheduleErr(err)
	}
	return api.PreviewCreateReportSchedule200{Body: opapi.PreviewOf(p)}, nil
}

func (h *Handlers) submit(ctx context.Context, sd *Schedules, action operation.ActionID, input any, conf []operation.Confirmation) (operation.Result, apitypes.OperationRef, error) {
	tid, c, fresh, err := h.freshCaller(ctx)
	if err != nil {
		return operation.Result{}, apitypes.OperationRef{}, err
	}
	raw, err := jsonv2.Marshal(input)
	if err != nil {
		return operation.Result{}, apitypes.OperationRef{}, apitypes.Internal("")
	}
	op, err := newOpID()
	if err != nil {
		return operation.Result{}, apitypes.OperationRef{}, apitypes.Internal("")
	}
	res, err := sd.Runner.SubmitStore(ctx, operation.Request{Tenant: tid, Actor: c, Action: action, Input: raw, Operation: op, Confirmed: conf, FreshStepUp: fresh})
	if err != nil {
		return res, apitypes.OperationRef{}, h.scheduleErr(err)
	}
	ref, err := opapi.RefOf(res)
	return res, ref, err
}

// current re-reads the schedule after a write for the 200 body and the new ETag.
func (h *Handlers) current(ctx context.Context, sd *Schedules, tid tenant.ID, id string) (api.ReportSchedule, int, error) {
	var v api.ReportSchedule
	var ver int
	err := sd.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		s, err := sd.Env.Store.Get(ctx, tx, id, false)
		if err != nil {
			return err
		}
		ver = s.Version
		v, err = h.view(ctx, sd, tx, s)
		return err
	})
	if err != nil {
		return v, 0, apitypes.Internal("")
	}
	return v, ver, nil
}

func (h *Handlers) ifMatch(s schedule.Schedule, header string) error {
	h2 := strings.TrimPrefix(strings.TrimSpace(header), "W/")
	if h2 == "" {
		return apitypes.PreconditionRequired("")
	}
	if strings.Trim(h2, `"`) != strconv.Itoa(s.Version) {
		return apitypes.PreconditionFailed("")
	}
	return nil
}

// CreateReportSchedule implements api.Handlers.
func (h *Handlers) CreateReportSchedule(ctx context.Context, in api.CreateReportScheduleInput) (api.CreateReportScheduleOutput, error) {
	sd, err := h.sched()
	if err != nil {
		return nil, err
	}
	tid, _, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	id := run.NewID().String()
	w, err := h.toWrite(id, in.Body)
	if err != nil {
		return nil, err
	}
	res, ref, err := h.submit(ctx, sd, schedule.CreateID, w, confirmations(w.ConfirmedExternal))
	if err != nil {
		return nil, err
	}
	if res.Held {
		return api.CreateReportSchedule202{Body: ref, ActiveDiqOperationID: ref.ID.String()}, nil
	}
	v, ver, err := h.current(ctx, sd, tid, id)
	if err != nil {
		return nil, err
	}
	return api.CreateReportSchedule201{Body: v, ActiveDiqOperationID: ref.ID.String(), ETag: etag(ver), Location: "/api/v1/reports/schedules/" + id}, nil
}

// PreviewCreateReportSchedule implements api.Handlers.
func (h *Handlers) PreviewCreateReportSchedule(ctx context.Context, in api.PreviewCreateReportScheduleInput) (api.PreviewCreateReportScheduleOutput, error) {
	sd, err := h.sched()
	if err != nil {
		return nil, err
	}
	tid, c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	w, err := h.toWrite(run.NewID().String(), in.Body)
	if err != nil {
		return nil, err
	}
	if w.ConfirmedExternal, err = h.classify(ctx, sd, tid, w.Recipients); err != nil {
		return nil, err
	}
	return h.preview(ctx, sd, tid, c, schedule.CreateID, w)
}

// UpdateReportSchedule implements api.Handlers.
func (h *Handlers) UpdateReportSchedule(ctx context.Context, in api.UpdateReportScheduleInput) (api.UpdateReportScheduleOutput, error) {
	sd, tid, s, err := h.target(ctx, in.ScheduleID)
	if err != nil {
		return nil, err
	}
	if err := h.ifMatch(s, in.IfMatch); err != nil {
		return nil, err
	}
	w, err := h.toWrite(s.ID, in.Body)
	if err != nil {
		return nil, err
	}
	res, ref, err := h.submit(ctx, sd, schedule.UpdateID, w, confirmations(w.ConfirmedExternal))
	if err != nil {
		return nil, err
	}
	if res.Held {
		return api.UpdateReportSchedule202{Body: ref, ActiveDiqOperationID: ref.ID.String()}, nil
	}
	v, ver, err := h.current(ctx, sd, tid, s.ID)
	if err != nil {
		return nil, err
	}
	return api.UpdateReportSchedule200{Body: v, ActiveDiqOperationID: ref.ID.String(), ETag: etag(ver)}, nil
}

// PreviewUpdateReportSchedule implements api.Handlers.
func (h *Handlers) PreviewUpdateReportSchedule(ctx context.Context, in api.PreviewUpdateReportScheduleInput) (api.PreviewUpdateReportScheduleOutput, error) {
	sd, tid, s, err := h.target(ctx, in.ScheduleID)
	if err != nil {
		return nil, err
	}
	if err := h.ifMatch(s, in.IfMatch); err != nil {
		return nil, err
	}
	w, err := h.toWrite(s.ID, in.Body)
	if err != nil {
		return nil, err
	}
	if w.ConfirmedExternal, err = h.classify(ctx, sd, tid, w.Recipients); err != nil {
		return nil, err
	}
	_, c, _ := h.caller(ctx)
	p, err := h.preview(ctx, sd, tid, c, schedule.UpdateID, w)
	return api.PreviewUpdateReportSchedule200(p), err
}

// target resolves the path schedule for a write or a preview: the caller must see it (404 otherwise).
func (h *Handlers) target(ctx context.Context, id apitypes.UUID) (sd *Schedules, tid tenant.ID, _ schedule.Schedule, err error) {
	sd, err = h.sched()
	if err != nil {
		return nil, tid, schedule.Schedule{}, err
	}
	tid, c, err := h.caller(ctx)
	if err != nil {
		return nil, tid, schedule.Schedule{}, err
	}
	s, err := h.visible(ctx, sd, tid, c, id.String())
	return sd, tid, s, err
}

// simple runs an Action whose input is the schedule id (pause, delete) or the id plus a small body.
func (h *Handlers) done(ctx context.Context, sd *Schedules, tid tenant.ID, id string, res operation.Result, ref apitypes.OperationRef) (api.ReportSchedule, string, int, bool, error) {
	if res.Held {
		return api.ReportSchedule{}, ref.ID.String(), 0, true, nil
	}
	v, ver, err := h.current(ctx, sd, tid, id)
	return v, ref.ID.String(), ver, false, err
}

// PauseReportSchedule implements api.Handlers.
func (h *Handlers) PauseReportSchedule(ctx context.Context, in api.PauseReportScheduleInput) (api.PauseReportScheduleOutput, error) {
	sd, tid, s, err := h.target(ctx, in.ScheduleID)
	if err != nil {
		return nil, err
	}
	res, ref, err := h.submit(ctx, sd, schedule.PauseID, schedule.IDInput{ScheduleID: s.ID}, nil)
	if err != nil {
		return nil, err
	}
	v, op, ver, held, err := h.done(ctx, sd, tid, s.ID, res, ref)
	if err != nil {
		return nil, err
	}
	if held {
		return api.PauseReportSchedule202{Body: ref, ActiveDiqOperationID: op}, nil
	}
	return api.PauseReportSchedule200{Body: v, ActiveDiqOperationID: op, ETag: etag(ver)}, nil
}

// PreviewPauseReportSchedule implements api.Handlers.
func (h *Handlers) PreviewPauseReportSchedule(ctx context.Context, in api.PreviewPauseReportScheduleInput) (api.PreviewPauseReportScheduleOutput, error) {
	sd, tid, s, err := h.target(ctx, in.ScheduleID)
	if err != nil {
		return nil, err
	}
	_, c, _ := h.caller(ctx)
	p, err := h.preview(ctx, sd, tid, c, schedule.PauseID, schedule.IDInput{ScheduleID: s.ID})
	return api.PreviewPauseReportSchedule200(p), err
}

// DeleteReportSchedule implements api.Handlers.
func (h *Handlers) DeleteReportSchedule(ctx context.Context, in api.DeleteReportScheduleInput) (api.DeleteReportScheduleOutput, error) {
	sd, _, s, err := h.target(ctx, in.ScheduleID)
	if err != nil {
		return nil, err
	}
	if err := h.ifMatch(s, in.IfMatch); err != nil {
		return nil, err
	}
	res, ref, err := h.submit(ctx, sd, schedule.DeleteID, schedule.IDInput{ScheduleID: s.ID}, nil)
	if err != nil {
		return nil, err
	}
	if res.Held {
		return api.DeleteReportSchedule202{Body: ref, ActiveDiqOperationID: ref.ID.String()}, nil
	}
	return api.DeleteReportSchedule204{ActiveDiqOperationID: ref.ID.String()}, nil
}

// PreviewDeleteReportSchedule implements api.Handlers.
func (h *Handlers) PreviewDeleteReportSchedule(ctx context.Context, in api.PreviewDeleteReportScheduleInput) (api.PreviewDeleteReportScheduleOutput, error) {
	sd, tid, s, err := h.target(ctx, in.ScheduleID)
	if err != nil {
		return nil, err
	}
	if err := h.ifMatch(s, in.IfMatch); err != nil {
		return nil, err
	}
	_, c, _ := h.caller(ctx)
	p, err := h.preview(ctx, sd, tid, c, schedule.DeleteID, schedule.IDInput{ScheduleID: s.ID})
	return api.PreviewDeleteReportSchedule200(p), err
}

// ResumeReportSchedule implements api.Handlers.
func (h *Handlers) ResumeReportSchedule(ctx context.Context, in api.ResumeReportScheduleInput) (api.ResumeReportScheduleOutput, error) {
	sd, tid, s, err := h.target(ctx, in.ScheduleID)
	if err != nil {
		return nil, err
	}
	ri := schedule.ResumeInput{ScheduleID: s.ID, ConfirmedExternal: in.Body.ConfirmedExternal}
	res, ref, err := h.submit(ctx, sd, schedule.ResumeID, ri, confirmations(ri.ConfirmedExternal))
	if err != nil {
		return nil, err
	}
	v, op, ver, held, err := h.done(ctx, sd, tid, s.ID, res, ref)
	if err != nil {
		return nil, err
	}
	if held {
		return api.ResumeReportSchedule202{Body: ref, ActiveDiqOperationID: op}, nil
	}
	return api.ResumeReportSchedule200{Body: v, ActiveDiqOperationID: op, ETag: etag(ver)}, nil
}

// PreviewResumeReportSchedule implements api.Handlers.
func (h *Handlers) PreviewResumeReportSchedule(ctx context.Context, in api.PreviewResumeReportScheduleInput) (api.PreviewResumeReportScheduleOutput, error) {
	sd, tid, s, err := h.target(ctx, in.ScheduleID)
	if err != nil {
		return nil, err
	}
	ext, err := h.classify(ctx, sd, tid, s.Recipients)
	if err != nil {
		return nil, err
	}
	_, c, _ := h.caller(ctx)
	p, err := h.preview(ctx, sd, tid, c, schedule.ResumeID, schedule.ResumeInput{ScheduleID: s.ID, ConfirmedExternal: ext})
	return api.PreviewResumeReportSchedule200(p), err
}

// ReassignReportSchedule implements api.Handlers.
func (h *Handlers) ReassignReportSchedule(ctx context.Context, in api.ReassignReportScheduleInput) (api.ReassignReportScheduleOutput, error) {
	sd, tid, s, err := h.target(ctx, in.ScheduleID)
	if err != nil {
		return nil, err
	}
	if err := h.ifMatch(s, in.IfMatch); err != nil {
		return nil, err
	}
	res, ref, err := h.submit(ctx, sd, schedule.ReassignID, schedule.ReassignInput{ScheduleID: s.ID, OwnerAccountID: in.Body.OwnerAccountID.String()}, nil)
	if err != nil {
		return nil, err
	}
	v, op, ver, held, err := h.done(ctx, sd, tid, s.ID, res, ref)
	if err != nil {
		return nil, err
	}
	if held {
		return api.ReassignReportSchedule202{Body: ref, ActiveDiqOperationID: op}, nil
	}
	return api.ReassignReportSchedule200{Body: v, ActiveDiqOperationID: op, ETag: etag(ver)}, nil
}

// PreviewReassignReportSchedule implements api.Handlers.
func (h *Handlers) PreviewReassignReportSchedule(ctx context.Context, in api.PreviewReassignReportScheduleInput) (api.PreviewReassignReportScheduleOutput, error) {
	sd, tid, s, err := h.target(ctx, in.ScheduleID)
	if err != nil {
		return nil, err
	}
	if err := h.ifMatch(s, in.IfMatch); err != nil {
		return nil, err
	}
	_, c, _ := h.caller(ctx)
	p, err := h.preview(ctx, sd, tid, c, schedule.ReassignID, schedule.ReassignInput{ScheduleID: s.ID, OwnerAccountID: in.Body.OwnerAccountID.String()})
	return api.PreviewReassignReportSchedule200(p), err
}

// RunReportScheduleNow implements api.Handlers: the owner only (another account's schedule is 404 even for a
// manage_all holder, R1). It queues a fire due now and answers the run it makes once the fire job has started
// it; the fire runs under the owner's authority and scope like any other.
func (h *Handlers) RunReportScheduleNow(ctx context.Context, in api.RunReportScheduleNowInput) (api.RunReportScheduleNowOutput, error) {
	sd, err := h.sched()
	if err != nil {
		return nil, err
	}
	tid, c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	s, err := h.visible(ctx, sd, tid, c, in.ScheduleID.String())
	if err != nil {
		return nil, err
	}
	if s.Owner != string(c.Requester.ID) {
		return nil, apitypes.NotFound("")
	}
	if s.State != schedule.Active {
		return nil, apitypes.Conflict("A paused schedule does not run; resume it first.")
	}
	var fid string
	if err := sd.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) (err error) {
		fid, err = sd.Fire.QueueNow(ctx, tx, tid, s.ID)
		return err
	}); err != nil {
		return nil, apitypes.Internal("")
	}
	if fid == "" {
		return nil, apitypes.Conflict("A run was just queued for this schedule; try again in a moment.")
	}
	// The fire job creates the run as the owner; wait briefly for it so the caller can follow it.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var rid string
		_ = sd.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT COALESCE(run_id::text, '') FROM public.report_schedule_fires WHERE id = $1::uuid`, fid).Scan(&rid)
		})
		if rid != "" {
			id, err := run.ParseID(rid)
			if err != nil {
				return nil, apitypes.Internal("")
			}
			var r run.Run
			if err := h.Runs.Read(ctx, tid, run.OpGet, id, c, run.ForGet, func(_ context.Context, _ store.Tx, got run.Run) error {
				r = got
				return nil
			}); err != nil {
				return nil, h.problem(err)
			}
			return api.RunReportScheduleNow202{Body: runView(r, h.Runs.HiddenGroups(r), h.now()), Location: location(r.ID)}, nil
		}
		select {
		case <-ctx.Done():
			return nil, apitypes.Internal("")
		case <-time.After(250 * time.Millisecond):
		}
	}
	return nil, apitypes.Conflict("The run is queued; it appears in the run history shortly.")
}

// ---- undo -------------------------------------------------------------------------------------

// UndoReportScheduleOperation implements api.Handlers.
func (h *Handlers) UndoReportScheduleOperation(ctx context.Context, in api.UndoReportScheduleOperationInput) (api.UndoReportScheduleOperationOutput, error) {
	sd, err := h.sched()
	if err != nil {
		return nil, err
	}
	ref, err := sd.Family.Undo(ctx, in.OperationID, in.Body)
	if err != nil {
		return nil, err
	}
	if ref.State == apitypes.OperationStateValueAwaitingApproval {
		return api.UndoReportScheduleOperation202{Body: ref, ActiveDiqOperationID: ref.ID.String()}, nil
	}
	return api.UndoReportScheduleOperation200{Body: ref, ActiveDiqOperationID: ref.ID.String()}, nil
}

// PreviewUndoReportScheduleOperation implements api.Handlers.
func (h *Handlers) PreviewUndoReportScheduleOperation(ctx context.Context, in api.PreviewUndoReportScheduleOperationInput) (api.PreviewUndoReportScheduleOperationOutput, error) {
	sd, err := h.sched()
	if err != nil {
		return nil, err
	}
	p, err := sd.Family.PreviewUndo(ctx, in.OperationID)
	if err != nil {
		return nil, err
	}
	return api.PreviewUndoReportScheduleOperation200{Body: p}, nil
}
