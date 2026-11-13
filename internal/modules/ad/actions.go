package ad

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/accountkind"
	"github.com/skenzeriq/activediq/internal/directory/attr/flags"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
)

// The Actions, their permissions and the events the runner writes.
const (
	ResetPasswordID operation.ActionID = "ad.user.resetPassword"
	UnlockID        operation.ActionID = "ad.user.unlock"
	EnableID        operation.ActionID = "ad.user.enable"
	DisableID       operation.ActionID = "ad.user.disable"

	PermResetPassword authz.Permission = "objects.user.reset_password"
	PermUnlock        authz.Permission = "objects.user.unlock"
	PermEnable        authz.Permission = "objects.user.enable"
	PermDisable       authz.Permission = "objects.user.disable"

	AuditPasswordReset audit.Kind = "ad.user.password_reset"
	AuditUnlocked      audit.Kind = "ad.user.unlocked"
	AuditEnabled       audit.Kind = "ad.user.enabled"
	AuditDisabled      audit.Kind = "ad.user.disabled"

	// ClassUser is the target class of every Action here; the kinds also allow computers, and an
	// Action for them is a later row.
	ClassUser = accountkind.ClassUser
)

// Stable reasons for a refusal the caller can act on. None carries a directory value.
const (
	ReasonTier0       = "tier0_target"
	ReasonRefused     = "refused_by_directory_guard"
	ReasonNotFound    = "target_not_found"
	ReasonNotUser     = "target_not_a_user"
	ReasonUnavailable = "directory_unavailable"
)

var (
	errUnavailable = fmt.Errorf("%w: %s: the directory connector is not wired", operation.ErrTransient, ReasonUnavailable)
	// ErrNothingToUndo is returned by Inverse when the step changed nothing, so undoing it must change
	// nothing. It is an ErrIrreversible so a caller that only knows the kernel's errors treats it as
	// "no inverse step".
	ErrNothingToUndo = fmt.Errorf("%w: the step changed nothing, there is nothing to undo", operation.ErrIrreversible)
)

// Target names the account every Action here changes. The naming context is part of the plan digest
// and keys the DC pin, so it is explicit input (canonical lower-case UUID text), not a guess.
type Target struct {
	ConnectionID  string `json:"connectionId"`
	ObjectGUID    string `json:"objectGuid"`
	NamingContext string `json:"namingContext"`
}

// AccountInput is the input of unlock, enable and disable.
type AccountInput struct {
	Target
}

// ResetInput is the input of reset password. The new password is not here: it is a transient secret
// input of the submission (rule 9), sealed outside the input, the plan, every event and every log.
type ResetInput struct {
	Target
	MustChangeAtNextLogon bool `json:"mustChangeAtNextLogon"`
}

// Outcome is what Apply did. It holds no secret.
type Outcome struct {
	// NoOp: the account was already in the requested state and nothing was sent.
	NoOp  bool                `json:"noOp,omitempty"`
	Tier0 []step.Tier0Finding `json:"tier0,omitempty"`
}

// payload is what Plan read, carried to Apply, Verify, Observe and Inverse. It holds raw directory
// state text and never a secret.
type payload struct {
	Target     Target `json:"target"`
	MustChange bool   `json:"mustChange,omitempty"`
	UAC        string `json:"uac"`
	Lockout    string `json:"lockout"`
	PwdLastSet string `json:"pwdLastSet"`
}

type ports struct {
	reader client.AccountReader
	writer client.AccountWriter
}

// spec is one account kind's row: what differs between the four Actions.
type spec struct {
	id            operation.ActionID
	key           string // accountkind digest key
	perm          authz.Permission
	schema        operation.SchemaRef
	audit         audit.Kind
	reversibility operation.Reversibility
	reason        string
	stepUp        bool
	secret        bool
	// satisfied reports whether the state already shows the kind's after-state (Verify, Observe, and
	// the change-nothing case of Inverse).
	satisfied func(p payload, st client.AccountState, claimedAt time.Time) (bool, error)
}

var specs = []spec{
	{
		id: ResetPasswordID, key: accountkind.KeyResetPassword, perm: PermResetPassword,
		schema: "#/components/schemas/AdUserResetPassword", audit: AuditPasswordReset,
		reversibility: operation.Irreversible, stepUp: true, secret: true,
		reason: "a password cannot be restored: the previous one is not readable; reset again to set another",
		satisfied: func(p payload, st client.AccountState, claimedAt time.Time) (bool, error) {
			if p.MustChange {
				return st.PwdLastSet == "0", nil
			}
			if claimedAt.IsZero() {
				return st.PwdLastSet != p.PwdLastSet, nil
			}
			t, ok := fileTime(st.PwdLastSet)
			return ok && t.After(claimedAt), nil
		},
	},
	{
		id: UnlockID, key: accountkind.KeyUnlock, perm: PermUnlock,
		schema: "#/components/schemas/AdUserAccount", audit: AuditUnlocked,
		reversibility: operation.Irreversible,
		reason:        "the directory owns the lockout state: only the lockout policy can lock an account again",
		satisfied: func(_ payload, st client.AccountState, _ time.Time) (bool, error) {
			return st.LockoutTime == "" || st.LockoutTime == "0", nil
		},
	},
	{
		id: EnableID, key: accountkind.KeyEnable, perm: PermEnable,
		schema: "#/components/schemas/AdUserAccount", audit: AuditEnabled,
		reversibility: operation.Reversible,
		satisfied: func(_ payload, st client.AccountState, _ time.Time) (bool, error) {
			d, err := disabled(st)
			return !d, err
		},
	},
	{
		id: DisableID, key: accountkind.KeyDisable, perm: PermDisable,
		schema: "#/components/schemas/AdUserAccount", audit: AuditDisabled,
		reversibility: operation.Reversible,
		satisfied: func(_ payload, st client.AccountState, _ time.Time) (bool, error) {
			return disabled(st)
		},
	},
}

// InverseAction names the Action that undoes id when the step changed something. A Typed Action's
// Inverse can return only an input of its own shape; enable and disable share AccountInput, so the
// undo layer applies the returned input to this Action. An Action with no entry is irreversible.
func InverseAction(id operation.ActionID) (operation.ActionID, bool) {
	switch id {
	case EnableID:
		return DisableID, true
	case DisableID:
		return EnableID, true
	}
	return "", false
}

// Actions builds the four Actions. A nil reader or writer builds them anyway and every Plan and Apply
// refuses: the module never runs without the directory.
func Actions(r client.AccountReader, w client.AccountWriter) ([]operation.Action, error) {
	p := ports{reader: r, writer: w}
	var out []operation.Action
	for _, sp := range specs {
		var (
			a   operation.Action
			err error
		)
		if sp.secret {
			a, err = build(p, sp, func(in ResetInput) Target { return in.Target }, func(in ResetInput) bool { return in.MustChangeAtNextLogon })
		} else {
			a, err = build(p, sp, func(in AccountInput) Target { return in.Target }, func(AccountInput) bool { return false })
		}
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func build[In any](p ports, sp spec, target func(In) Target, mustChange func(In) bool) (operation.Action, error) {
	return operation.Define(operation.Typed[In, payload, Outcome]{
		Descriptor: operation.Descriptor{
			ID: sp.id, Version: 1, Permission: sp.perm, Input: sp.schema,
			Target: operation.TargetAD, TargetClass: ClassUser, Reversibility: sp.reversibility,
			AuditKind: sp.audit, StepUp: sp.stepUp, SecretInput: sp.secret,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in In) ([]operation.TypedStep[payload], error) {
			t := target(in)
			if err := t.validate(); err != nil {
				return nil, err
			}
			if p.reader == nil {
				return nil, errUnavailable
			}
			ref := t.ref()
			st, err := p.reader.Account(ctx, pc.Pins, ref)
			if err != nil {
				return nil, readError(err)
			}
			if err := checkTarget(st); err != nil {
				return nil, err
			}
			pl := payload{Target: t, MustChange: mustChange(in), UAC: st.UserAccountControl, Lockout: st.LockoutTime, PwdLastSet: st.PwdLastSet}
			sp1 := operation.StepPlan{
				Target: ref, Kind: sp.key, Reversibility: sp.reversibility, ReversibilityReason: sp.reason,
				Diff: diffOf(sp, pl), Preconditions: preconditions(sp, st), Credential: sp.secret,
			}
			return []operation.TypedStep[payload]{{Plan: sp1, Payload: pl}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, tp operation.TypedStep[payload]) (Outcome, error) {
			if p.writer == nil {
				return Outcome{}, errUnavailable
			}
			pl := tp.Payload
			res, err := p.writer.Write(ctx, s, client.WriteOp{
				DigestKind: sp.key, Target: pl.Target.ref(), Attrs: attrsOf(sp, pl),
			})
			if err != nil {
				return Outcome{}, writeError(err, sp.secret)
			}
			out := Outcome{NoOp: res.NoOp}
			if res.Apply != nil {
				out.Tier0 = res.Tier0AfterWrite()
			}
			return out, nil
		},
		Verify: func(ctx context.Context, s step.Step, tp operation.TypedStep[payload], _ Outcome) (operation.Verdict, error) {
			if p.reader == nil {
				return operation.Verdict{}, errUnavailable
			}
			pl := tp.Payload
			st, err := p.reader.Account(pinned(ctx, s, pl.Target), stepPins(s, pl.Target), pl.Target.ref())
			if err != nil {
				return operation.Verdict{}, readError(err)
			}
			if !st.Exists {
				return operation.Verdict{Reason: "target_gone"}, nil
			}
			// Rule 7: the Tier-0 guard runs again on the read-back. An account that became tier0 while
			// the write ran counts at once and outranks every other reason.
			if st.Tier0 {
				return operation.Verdict{Reason: "tier0_after_write", Tier0: []step.Tier0Finding{{Object: pl.Target.ObjectGUID}}}, nil
			}
			ok, err := sp.satisfied(pl, st, time.Time{})
			if err != nil {
				return operation.Verdict{}, err
			}
			if !ok {
				return operation.Verdict{Reason: "account_not_as_planned"}, nil
			}
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(tp operation.TypedStep[payload], o Outcome) (In, error) {
			var zero In
			if _, ok := InverseAction(sp.id); !ok {
				return zero, operation.ErrIrreversible
			}
			if o.NoOp {
				return zero, ErrNothingToUndo
			}
			// Nothing to undo when the before-state already was the after-state (a decoded outcome of
			// a recovered step carries no NoOp flag).
			if was, err := sp.satisfied(tp.Payload, client.AccountState{UserAccountControl: tp.Payload.UAC, LockoutTime: tp.Payload.Lockout, PwdLastSet: tp.Payload.PwdLastSet}, time.Time{}); err != nil {
				return zero, err
			} else if was {
				return zero, ErrNothingToUndo
			}
			return inverseInput[In](tp.Payload.Target)
		},
		Observe: func(ctx context.Context, pins authority.Pins, tp operation.TypedStep[payload], claimedAt time.Time) (operation.Observation, error) {
			if p.reader == nil {
				return "", errUnavailable
			}
			pl := tp.Payload
			st, err := p.reader.Account(ctx, pins, pl.Target.ref())
			if err != nil {
				return "", readError(err)
			}
			if !st.Exists {
				return operation.ObservedOther, nil
			}
			after, err := sp.satisfied(pl, st, claimedAt)
			if err != nil {
				return "", err
			}
			if sp.secret {
				// A credential's after-state is "last set after the claim"; a must-change reset leaves
				// pwdLastSet 0 whether or not it ran, so it cannot be told apart from before.
				if pl.MustChange && pl.PwdLastSet == "0" {
					return operation.ObservedOther, nil
				}
				if after {
					return operation.ObservedAfter, nil
				}
				if st.PwdLastSet == pl.PwdLastSet {
					return operation.ObservedBefore, nil
				}
				return operation.ObservedOther, nil
			}
			if after {
				return operation.ObservedAfter, nil
			}
			if st.UserAccountControl == pl.UAC && st.LockoutTime == pl.Lockout {
				return operation.ObservedBefore, nil
			}
			return operation.ObservedOther, nil
		},
		Tier0: func(o Outcome) []step.Tier0Finding { return o.Tier0 },
	})
}

func inverseInput[In any](t Target) (In, error) {
	var in In
	switch v := any(&in).(type) {
	case *AccountInput:
		v.Target = t
	default:
		return in, operation.ErrIrreversible
	}
	return in, nil
}

func (t Target) ref() authority.TargetRef {
	return accountkind.Target(t.ConnectionID, t.ObjectGUID, ClassUser, t.NamingContext)
}

func (t Target) validate() error {
	if t.ConnectionID == "" || !accountkind.Canonical(t.ObjectGUID) || !accountkind.Canonical(t.NamingContext) {
		return fmt.Errorf("%w: connectionId, objectGuid and namingContext are required (canonical lower-case UUID text)", operation.ErrInvalid)
	}
	return nil
}

func checkTarget(st client.AccountState) error {
	switch {
	case !st.Exists:
		return fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonNotFound)
	case st.Class != ClassUser:
		return fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonNotUser)
	case st.Tier0:
		return fmt.Errorf("%w: %s", operation.ErrDenied, ReasonTier0)
	}
	return nil
}

// diffOf is the digest-bound change. The connector recomputes the digest from the typed request, and
// the kinds' attributes are exactly (accountkind.AttrsOf): reset has the must-change flag and the
// presence of the secret; the other three have none, so their before and after are in Preconditions.
func diffOf(sp spec, p payload) []operation.Change {
	if !sp.secret {
		return nil
	}
	before := strconv.FormatBool(p.PwdLastSet == "0")
	return []operation.Change{
		{Attribute: accountkind.AttrMustChange, Before: []string{before}, After: []string{strconv.FormatBool(p.MustChange)}},
		{Attribute: accountkind.AttrSecret, Secret: true},
	}
}

func attrsOf(sp spec, p payload) []step.Attr {
	var out []step.Attr
	for _, c := range diffOf(sp, p) {
		out = append(out, step.Attr{Name: c.Attribute, Values: c.After, Secret: c.Secret})
	}
	return out
}

// preconditions state the before-state in words the plan view shows. They are not digested.
func preconditions(sp spec, st client.AccountState) []string {
	switch sp.id {
	case UnlockID:
		if st.LockoutTime == "" || st.LockoutTime == "0" {
			return []string{"account is not locked out: nothing will change"}
		}
		return []string{"lockoutTime: set → 0"}
	case EnableID, DisableID:
		d, err := disabled(st)
		switch {
		case err != nil:
			return []string{"userAccountControl: unreadable"}
		case d && sp.id == EnableID:
			return []string{"ACCOUNTDISABLE: set → cleared"}
		case !d && sp.id == DisableID:
			return []string{"ACCOUNTDISABLE: cleared → set"}
		case d:
			return []string{"account is already disabled: nothing will change"}
		}
		return []string{"account is already enabled: nothing will change"}
	}
	return nil
}

func disabled(st client.AccountState) (bool, error) {
	u, err := flags.DecodeUAC(st.UserAccountControl)
	if err != nil {
		return false, fmt.Errorf("%w: userAccountControl is not readable", operation.ErrInvalid)
	}
	return u.Has(flags.UACAccountDisable), nil
}

// fileTime parses a Windows FILETIME (100 ns ticks since 1601-01-01 UTC).
func fileTime(s string) (time.Time, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, false
	}
	const epochDiff = 11644473600 // seconds from 1601 to 1970
	return time.Unix(n/1e7-epochDiff, (n%1e7)*100).UTC(), true
}

func stepPins(s step.Step, t Target) authority.Pins {
	nc := authority.NamingContextID(t.NamingContext)
	host, _ := s.DC(nc)
	return authority.Pins{nc: host}
}

// pinned returns ctx carrying the step's DSA pin, which the connector read needs (rule 5).
func pinned(ctx context.Context, s step.Step, t Target) context.Context {
	nc := authority.NamingContextID(t.NamingContext)
	dsa, _ := s.DSA(nc)
	return authority.WithDSAPins(ctx, authority.DSAPins{nc: dsa})
}

// readError maps a failed live read. The cause can name a connector or a DC, never a stored value.
func readError(err error) error {
	if errors.Is(err, client.ErrReadPin) || errors.Is(err, client.ErrReadConnection) {
		return fmt.Errorf("%w: the target is not readable on the pinned DC", operation.ErrInvalid)
	}
	return fmt.Errorf("%w: reading the account failed", operation.ErrTransient)
}

// writeError maps a failed write onto the pipeline's typed errors. Nothing of the cause, which may
// carry a DN or a directory message, is kept in the text.
func writeError(err error, credential bool) error {
	switch {
	case errors.Is(err, step.ErrDenied), errors.Is(err, operation.ErrDenied):
		return err
	case errors.Is(err, client.ErrTransport):
		if credential {
			return fmt.Errorf("%w: the connector call failed after the request may have been sent", operation.ErrOutcomeUnknown)
		}
		return fmt.Errorf("%w: the connector call failed", operation.ErrTransient)
	case isClientRefusal(err):
		return fmt.Errorf("%w: the write was refused before it reached the directory: %s", operation.ErrInvalid, err.Error())
	}
	o := client.MapError(err)
	switch {
	case o == nil:
		return nil
	case o.Status == client.StatusStaleState:
		return fmt.Errorf("%w: the account changed since the plan", operation.ErrStaleState)
	case o.Status == client.StatusRefused:
		return fmt.Errorf("%w: %s", operation.ErrDenied, ReasonRefused)
	case o.Retryable:
		return fmt.Errorf("%w: the directory asked for a retry", operation.ErrTransient)
	case credential && o.Code == 0:
		return fmt.Errorf("%w: the write's outcome is not known", operation.ErrOutcomeUnknown)
	}
	return fmt.Errorf("ad: the directory refused the write (%s)", o.Audit["code"])
}

// isClientRefusal is true for the client's own pre-flight refusals: fixed texts, no data.
func isClientRefusal(err error) bool {
	for _, e := range []error{client.ErrNoTier0Builder, client.ErrNoTransport, client.ErrNoFacts, client.ErrNoTier0, client.ErrDigest,
		client.ErrInvalidOp, client.ErrBadResponse, client.ErrUnknownKind, client.ErrNoNC, client.ErrNoDCPin, client.ErrDCMismatch,
		client.ErrNoDSAPin, client.ErrKindAttrs, client.ErrKindClass, client.ErrNoSecret, client.ErrNotCanonical} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
