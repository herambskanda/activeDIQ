package operation

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// The two sources of a tier0_after_write finding (ADR-0005 rule 7), and the Action's own Verify.
const (
	Tier0SourceConnector = "connector_report"
	Tier0SourceServer    = "server_reread"
	Tier0SourceAction    = "action_verify"
)

// Toucher is implemented by an Action that names the objects, besides the target, that a step's typed
// change touches. The server's Tier-0 re-read covers each (ADR-0005 rule 7). Actions made by Define
// implement it.
type Toucher interface {
	Touched(p StepPlan) []authority.TargetRef
}

// AlsoAuthorizer is implemented by an Action whose step needs authority over objects besides its
// target (a move's destination parent). The runner authorises each one live at Plan and again
// immediately before Apply, with the step's own permission. Actions made by Define implement it.
type AlsoAuthorizer interface {
	AlsoAuthorize(p StepPlan) []authority.TargetRef
}

// tier0Report is one tier0_after_write finding: what, from which source, on which DC.
type tier0Report struct {
	findings []step.Tier0Finding
	source   string
	dc       string
	also     string // another Verify reason seen on the same step, recorded in the event's detail only
}

// unclassified is the audit/alert text of a finding with no basis.
const unclassified = "unclassified"

// render gives "guid:C2,C5" or "guid:unclassified" per finding.
func render(fs []step.Tier0Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		b := unclassified
		if len(f.Bases) > 0 {
			b = strings.Join(f.Bases, ",")
		}
		out[i] = f.Object + ":" + b
	}
	return out
}

// details are the audit details of the verify_failed event. Details are sorted by key.
func (t *tier0Report) details(c *claimed) []audit.Detail {
	if t == nil {
		return nil
	}
	findings := t.findings
	if len(findings) == 0 { // the Action reported none: the target is the finding, unclassified
		findings = []step.Tier0Finding{{Object: c.plan.Target.GUID}}
	}
	kv := []any{"dc", t.dc, "objects", strings.Join(render(findings), ";")}
	if t.also != "" {
		kv = append(kv, "other_reason", t.also)
	}
	kv = append(kv, "source", t.source)
	return detail(kv...)
}

// otherReason is the Verify reason that tier0_after_write outranked, kept for the event's detail.
func otherReason(merr, verr error, v Verdict) string {
	switch {
	case merr != nil:
		return "mint_failed"
	case verr != nil && !errors.Is(verr, ErrDeferVerify):
		return "verify_error"
	case verr == nil && !v.OK && v.Reason != "" && v.Reason != ReasonTier0AfterWrite:
		return v.Reason
	}
	return ""
}

// tier0Alert raises the critical alert after the recording transaction committed. It names the
// objects, their bases or unclassified, the source, the DC, the step and the initiator chain.
func (r *Runner) tier0Alert(ctx context.Context, c *claimed, rep *tier0Report) {
	a := Alert{Severity: "critical", Reason: ReasonTier0AfterWrite, Operation: string(c.key.Operation),
		Step: c.key, Initiator: c.op.Chain, Source: Tier0SourceAction, DC: c.op.Pins[c.plan.Target.NC]}
	if rep != nil {
		a.Objects, a.Source, a.DC = rep.findings, rep.source, rep.dc
	}
	if len(a.Objects) == 0 {
		a.Objects = []step.Tier0Finding{{Object: c.plan.Target.GUID}}
	}
	r.alert(ctx, a)
}

// rereadTier0 is the server's own guard (source 2): it reads, live, the Tier-0 fact of the target and
// every object the step touches, retrying on the pin and then trying one other DC of the naming
// context. A fact that is tier0 on any read, or still unknown after both, is a finding; a pin outage
// alone is not. It returns nil when nothing is tier0 (or no facts reader is wired).
func (r *Runner) rereadTier0(ctx context.Context, c *claimed) *tier0Report {
	if r.cfg.Facts == nil {
		return nil
	}
	targets := []authority.TargetRef{c.plan.Target}
	if tc, ok := c.act.(Toucher); ok {
		for _, x := range tc.Touched(c.plan) {
			if !slices.ContainsFunc(targets, func(y authority.TargetRef) bool { return y.GUID == x.GUID }) {
				targets = append(targets, x)
			}
		}
	}
	rep := &tier0Report{source: Tier0SourceServer, dc: c.op.Pins[c.plan.Target.NC]}
	for _, tg := range targets {
		hit, dc := r.readTier0(ctx, c, tg)
		if hit {
			rep.findings = append(rep.findings, step.Tier0Finding{Object: tg.GUID}) // the facts carry no basis
			rep.dc = dc
		}
	}
	if len(rep.findings) == 0 {
		return nil
	}
	return rep
}

// readTier0 reports whether tg counts as tier0 and the DC the deciding read was made on.
func (r *Runner) readTier0(ctx context.Context, c *claimed, tg authority.TargetRef) (bool, string) {
	q := authority.FactsQuery{Target: tg, Tier0: true}
	pin := c.op.Pins[tg.NC]
	for try := 1; ; try++ {
		f, err := r.cfg.Facts.Facts(rereadCtx(ctx, c.op.Tenant, c.op.DSAs), c.op.Pins, q)
		if err == nil {
			return f.Tier0, pin
		}
		if try >= max(r.cfg.Attempts, 1) || ctx.Err() != nil {
			break
		}
		r.sleep(r.backoffFor(try))
	}
	// One other DC: chosen explicitly (never the pinned one), and read by its host and its DSA GUID.
	if fp, ok := r.cfg.Pinner.(FallbackPinner); ok {
		pctx := authority.WithTenant(ctx, c.op.Tenant.String())
		if p, err := fp.PinOther(pctx, tg.Connection, tg.NC, DCPin{Host: pin, DSAGUID: c.op.DSAs[tg.NC]}); err == nil &&
			p.Host != "" && validDSAGUID(p.DSAGUID) && !strings.EqualFold(p.Host, pin) && !strings.EqualFold(p.DSAGUID, c.op.DSAs[tg.NC]) {
			pins := cloneMap(c.op.Pins)
			pins[tg.NC] = p.Host
			dsas := maps.Clone(c.op.DSAs)
			if dsas == nil {
				dsas = authority.DSAPins{}
			}
			dsas[tg.NC] = p.DSAGUID
			if f, err := r.cfg.Facts.Facts(rereadCtx(ctx, c.op.Tenant, dsas), pins, q); err == nil {
				return f.Tier0, p.Host
			}
		}
	}
	return true, pin // still unknown on every DC tried: counts as tier0
}

// rereadCtx carries what every live read needs: the tenant and the DSA GUID pins (as liveFacts does).
func rereadCtx(ctx context.Context, tn tenant.ID, dsas authority.DSAPins) context.Context {
	return authority.WithDSAPins(authority.WithTenant(ctx, tn.String()), maps.Clone(dsas))
}

func cloneMap(m authority.Pins) authority.Pins { return maps.Clone(m) }
