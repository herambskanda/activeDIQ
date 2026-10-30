// Package signin is the AN-3 core: console single sign-on from Start to the first factor's outcome
// (console-sso.md sections 3, 6, 7.2). It holds no net/http (ADR-0004 A6); httpx/ssohttp is the route binding.
//
// Start asks the IdP's Verifier for the redirect and stores the Transaction it must come back to. The
// callback consumes that Transaction first (SSO-1), lets the Verifier decide whether the response is
// genuine, finds the console account by (issuer, subject), applies the anchor rules of DM-30.I5, and then
// decides between a session and a pending sign-in:
//
//   - A session only when the IdP is MFA-asserting, the response proved it (Verified.MFAAsserted, MFA-3),
//     and the account holds neither tenant-owner nor a control-plane permission (MFA-5). An error while
//     asking about privilege counts as "privileged".
//   - Otherwise a pending sign-in (AN-10), never a session.
//
// Every refusal is the one ErrSignInFailed; the reason code goes to the Recorder only.
package signin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ErrSignInFailed is the one answer to every way an SSO sign-in can fail.
var ErrSignInFailed = errors.New("signin: sign-in failed")

// ErrIdPNotFound is what IdPs returns for an IdP the tenant does not have.
var ErrIdPNotFound = errors.New("signin: no such identity provider")

// Reasons recorded for a refusal (audit and log only). Verifier reasons ("oidc.nonce", "saml.wrap", ...)
// are recorded as they are.
const (
	ReasonNoTransaction     = "sso.no_transaction"
	ReasonTransactionAge    = "sso.transaction_expired"
	ReasonTransactionIdP    = "sso.transaction_idp"
	ReasonTransactionIntent = "sso.transaction_intent"
	ReasonIdP               = "sso.idp_unavailable" // unknown, disabled, or no verifier for its protocol
	ReasonNotAdmitted       = "sso.not_admitted"
	ReasonInactive          = "sso.account_inactive"
	ReasonAnchorChanged     = "sso.anchor_changed"
	ReasonAnchorMissing     = "sso.anchor_missing"
	ReasonChanged           = "sso.credentials_changed"

	// WarnMFAEvidenceAbsent is recorded with a successful pending sign-in (MFA-3).
	WarnMFAEvidenceAbsent = "sso.mfa_evidence_absent"
	// WarnBindingUnresolved: the anchor named no single directory object; the account stays unbound.
	WarnBindingUnresolved = "sso.anchor_unresolved"
)

// IdPs gives the verifier's view of an IdP of the tenant (DM-39), or ErrIdPNotFound.
type IdPs interface {
	IdP(ctx context.Context, t tenant.ID, idpID string) (sso.IdP, error)
}

// Accounts finds and binds console accounts.
type Accounts interface {
	LookupSSO(ctx context.Context, t tenant.ID, issuer, subject string) (authn.Account, error)
	Bind(ctx context.Context, t tenant.ID, id string, an authn.Anchor, ref authn.DirectoryRef, by authority.Chain) (authn.Account, error)
}

// Epochs reads an account's session epoch (T-0429).
type Epochs interface {
	Epoch(ctx context.Context, t tenant.ID, account string) (authn.Epoch, error)
}

// Sessions creates sessions.
type Sessions interface {
	Create(ctx context.Context, in authn.CreateInput) (authn.CreateResult, error)
}

// Pending creates pending sign-ins.
type Pending interface {
	Begin(ctx context.Context, in authn.BeginInput) (authn.PendingHandle, error)
}

// Transactions stores the SSO Transactions.
type Transactions interface {
	Put(ctx context.Context, t tenant.ID, tx sso.Transaction) (Handle, error)
	Consume(ctx context.Context, t tenant.ID, h Handle) (sso.Transaction, error)
}

// Privileges answers MFA-5: does the account hold tenant-owner or any control_plane permission? Held only
// by assignment to the account itself (DM-36.I4), so the answer is about the account alone.
type Privileges interface {
	HoldsControlPlane(ctx context.Context, t tenant.ID, account string) (bool, error)
}

// Outcome is what the Recorder is told about a finished callback.
type Outcome struct {
	Tenant      tenant.ID
	IdP         string
	Reason      string // refusal reason, or "" on success
	Warnings    []string
	Issuer      string // only from a verified response
	Subject     string // only from a verified response
	Account     string
	MFAAsserted bool
	Methods     []string
	Kind        ResultKind // for a success
	Ref         string     // session or pending-sign-in handle ID for audit; never the token
	ResponseID  string
	ClientIP    netip.Addr
}

// Recorder takes the SSO audit record (SSO-4): auth.sso.succeeded or auth.sso.refused. Its error is
// logged by the service; it does not change the answer.
type Recorder interface {
	Record(ctx context.Context, o Outcome) error
}

// Service is the AN-3 core. Every field except Log, Clock and ReturnOK is required.
type Service struct {
	IdPs       IdPs
	Verifiers  map[sso.Protocol]sso.Verifier
	Txs        Transactions
	Accounts   Accounts
	Anchors    authn.DirectoryAnchors
	Epochs     Epochs
	Sessions   Sessions
	Pending    Pending
	Privileges Privileges
	Recorder   Recorder
	Log        *slog.Logger
	// ReturnOK, when set, must accept a return path for it to be used: the console's route table. A path
	// it refuses becomes the console root (X-12).
	ReturnOK func(path string) bool
	Clock    func() time.Time // nil: time.Now
}

// ResultKind says what a successful callback produced.
type ResultKind string

// The kinds.
const (
	ResultSession ResultKind = "session"
	ResultPending ResultKind = "pending"
)

// Result is a successful callback. Exactly one of Session and Pending is set, by Kind.
type Result struct {
	Kind       ResultKind
	Session    authn.CreateResult
	Pending    authn.PendingHandle
	ReturnPath string
}

// StartRequest is one GET /auth/sso/{idpId}/start.
type StartRequest struct {
	Tenant     tenant.ID
	IdPID      string
	ReturnPath string // from the query; validated here
	ClientIP   netip.Addr
}

// StartResult is where to send the browser and the cookie that binds it.
type StartResult struct {
	Redirect *url.URL
	Handle   Handle
	Protocol sso.Protocol
}

// ConsoleRoot is the return path when none was asked for or the one asked for is refused.
const ConsoleRoot = "/"

// maxReturnPath bounds a stored return path.
const maxReturnPath = 512

// ValidReturnPath reports whether p has the shape of a console-relative path: one leading slash, no
// authority, no backslash, no control character, no query or fragment, no dot segments. The console's
// route table is checked on top of this by Service.ReturnOK.
func ValidReturnPath(p string) bool {
	if p == "" || len(p) > maxReturnPath || p[0] != '/' || strings.HasPrefix(p, "//") {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c < 0x21 || c == 0x7f || c == '\\' || c == '?' || c == '#' || c == '%' {
			return false
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." {
			return false
		}
	}
	return true
}

func (s *Service) returnPath(p string) string {
	if !ValidReturnPath(p) || (s.ReturnOK != nil && !s.ReturnOK(p)) {
		return ConsoleRoot
	}
	return p
}

func (s *Service) ready() bool {
	return s.IdPs != nil && s.Txs != nil && s.Accounts != nil && s.Anchors != nil && s.Epochs != nil &&
		s.Sessions != nil && s.Pending != nil && s.Privileges != nil && s.Recorder != nil && len(s.Verifiers) > 0
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) idp(ctx context.Context, t tenant.ID, id string) (sso.IdP, sso.Verifier, bool, error) {
	idp, err := s.IdPs.IdP(ctx, t, id)
	if errors.Is(err, ErrIdPNotFound) {
		return sso.IdP{}, nil, false, nil
	}
	if err != nil {
		return sso.IdP{}, nil, false, fmt.Errorf("signin: read idp: %w", err)
	}
	v := s.Verifiers[idp.Protocol]
	if idp.ID != id || !idp.Enabled || v == nil {
		return sso.IdP{}, nil, false, nil // SSO-2: disabled refuses at Start and at Complete
	}
	return idp, v, true, nil
}

// Start builds the redirect to the IdP and stores the Transaction. A refusal is ErrSignInFailed (and is
// recorded); any other error is an infrastructure failure.
func (s *Service) Start(ctx context.Context, req StartRequest) (StartResult, error) {
	if req.Tenant.IsZero() || !s.ready() {
		return StartResult{}, errors.New("signin: service not configured")
	}
	idp, v, ok, err := s.idp(ctx, req.Tenant, req.IdPID)
	if err != nil {
		return StartResult{}, err
	}
	if !ok {
		return StartResult{}, s.refuse(ctx, Outcome{Tenant: req.Tenant, IdP: req.IdPID, Reason: ReasonIdP, ClientIP: req.ClientIP})
	}
	redirect, tx, err := v.Start(ctx, req.Tenant, idp, sso.IntentSignin)
	if err != nil {
		return StartResult{}, fmt.Errorf("signin: start: %w", err)
	}
	tx.IdPID = idp.ID
	tx.Intent = sso.IntentSignin
	tx.ReturnPath = s.returnPath(req.ReturnPath) // chosen here, never taken from the callback
	h, err := s.Txs.Put(ctx, req.Tenant, tx)
	if err != nil {
		return StartResult{}, err
	}
	return StartResult{Redirect: redirect, Handle: h, Protocol: idp.Protocol}, nil
}

// CallbackRequest is one return from the IdP.
type CallbackRequest struct {
	Tenant tenant.ID
	IdPID  string // the {idpId} path segment
	// Cookie is the raw value of the browser-binding cookie, "" when absent.
	Cookie   string
	Callback sso.Callback
	ClientIP netip.Addr
}

// Callback completes a sign-in. Every refusal is ErrSignInFailed; any other error is an infrastructure
// failure the caller answers as an internal error.
func (s *Service) Callback(ctx context.Context, req CallbackRequest) (Result, error) {
	if req.Tenant.IsZero() || !s.ready() {
		return Result{}, errors.New("signin: service not configured")
	}
	base := Outcome{Tenant: req.Tenant, IdP: req.IdPID, ClientIP: req.ClientIP}
	refuse := func(reason string) error { o := base; o.Reason = reason; return s.refuse(ctx, o) }

	// SSO-1: consume first, whatever happens next.
	h, err := ParseHandle(req.Cookie)
	if err != nil {
		return Result{}, refuse(ReasonNoTransaction)
	}
	tx, err := s.Txs.Consume(ctx, req.Tenant, h)
	switch {
	case errors.Is(err, ErrNoTransaction):
		return Result{}, refuse(ReasonNoTransaction)
	case errors.Is(err, ErrTransactionExpired):
		return Result{}, refuse(ReasonTransactionAge)
	case err != nil:
		return Result{}, err
	}
	if tx.IdPID != req.IdPID || req.Callback.IdPID != req.IdPID {
		return Result{}, refuse(ReasonTransactionIdP)
	}
	if tx.Intent != sso.IntentSignin {
		return Result{}, refuse(ReasonTransactionIntent)
	}
	idp, v, ok, err := s.idp(ctx, req.Tenant, req.IdPID)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{}, refuse(ReasonIdP)
	}

	ver, err := v.Complete(ctx, req.Tenant, idp, tx, req.Callback)
	if err != nil {
		reason := sso.ReasonOf(err)
		if reason == "" {
			// A verifier fault that is not a Refusal (for example a replay store that is down). Fail
			// closed, and tell the log; the browser still sees the generic failure.
			if s.Log != nil {
				s.Log.ErrorContext(ctx, "sso: verifier failed", "idp", req.IdPID, "error", err)
			}
			reason = "sso.verifier_error"
		}
		return Result{}, refuse(reason)
	}
	// From here the response is genuine, so issuer and subject may be recorded.
	base.Issuer, base.Subject, base.ResponseID = ver.Issuer, ver.Subject, ver.ResponseID
	base.Methods = ver.Methods
	base.Warnings = append(base.Warnings, ver.Warnings...)
	refuse = func(reason string) error { o := base; o.Reason = reason; return s.refuse(ctx, o) }

	acct, err := s.Accounts.LookupSSO(ctx, req.Tenant, ver.Issuer, ver.Subject)
	if errors.Is(err, authn.ErrAccountNotFound) {
		return Result{}, refuse(ReasonNotAdmitted) // admission by invitation only (mapped admission is a later ticket)
	}
	if err != nil {
		return Result{}, fmt.Errorf("signin: find account: %w", err)
	}
	base.Account = acct.ID
	if acct.State != authn.AccountActive {
		return Result{}, refuse(ReasonInactive)
	}

	if reason, err := s.applyAnchor(ctx, req.Tenant, acct, ver, &base); err != nil {
		return Result{}, err
	} else if reason != "" {
		return Result{}, refuse(reason)
	}

	epoch, err := s.Epochs.Epoch(ctx, req.Tenant, acct.ID)
	switch {
	case errors.Is(err, authn.ErrAccountInactive):
		return Result{}, refuse(ReasonInactive)
	case err != nil:
		return Result{}, fmt.Errorf("signin: read epoch: %w", err)
	}

	asserted := ver.MFAAsserted && mfaMode(idp) == sso.MFAClaim
	base.MFAAsserted = asserted
	if mfaMode(idp) == sso.MFAClaim && !ver.MFAAsserted {
		base.Warnings = append(base.Warnings, WarnMFAEvidenceAbsent)
	}
	if asserted {
		privileged, perr := s.Privileges.HoldsControlPlane(ctx, req.Tenant, acct.ID)
		if perr != nil {
			if s.Log != nil {
				s.Log.ErrorContext(ctx, "sso: privilege check failed; completing with the second factor", "error", perr)
			}
			privileged = true // fail closed
		}
		if !privileged {
			return s.session(ctx, req, tx, acct, ver, epoch, base, refuse)
		}
	}
	return s.pending(ctx, req, tx, acct, epoch, base, refuse)
}

func mfaMode(idp sso.IdP) string {
	switch {
	case idp.OIDC != nil:
		return idp.OIDC.MFAMode
	case idp.SAML != nil:
		return idp.SAML.MFAMode
	}
	return sso.MFAOff
}

func (s *Service) session(ctx context.Context, req CallbackRequest, tx sso.Transaction, acct authn.Account, ver sso.Verified,
	epoch authn.Epoch, base Outcome, refuse func(string) error) (Result, error) {
	now := s.now()
	res, err := s.Sessions.Create(ctx, authn.CreateInput{Tenant: req.Tenant, Account: acct.ID,
		Methods: []string{"sso", "idp_mfa"}, MFAAt: &now, ClientIP: req.ClientIP, Epoch: epoch})
	switch {
	case errors.Is(err, authn.ErrCredentialsChanged):
		return Result{}, refuse(ReasonChanged)
	case errors.Is(err, authn.ErrAccountInactive):
		return Result{}, refuse(ReasonInactive)
	case err != nil:
		return Result{}, fmt.Errorf("signin: create session: %w", err)
	}
	base.Kind, base.Ref, base.Methods = ResultSession, res.Session.ID, append(append([]string{}, ver.Methods...), "idp_mfa")
	s.record(ctx, base)
	return Result{Kind: ResultSession, Session: res, ReturnPath: tx.ReturnPath}, nil
}

func (s *Service) pending(ctx context.Context, req CallbackRequest, tx sso.Transaction, acct authn.Account,
	epoch authn.Epoch, base Outcome, refuse func(string) error) (Result, error) {
	h, err := s.Pending.Begin(ctx, authn.BeginInput{Tenant: req.Tenant, Account: acct.ID,
		FirstFactor: authn.FirstSSO, ClientIP: req.ClientIP, Epoch: epoch})
	switch {
	case errors.Is(err, authn.ErrCredentialsChanged):
		return Result{}, refuse(ReasonChanged)
	case errors.Is(err, authn.ErrAccountInactive):
		return Result{}, refuse(ReasonInactive)
	case err != nil:
		return Result{}, fmt.Errorf("signin: begin pending: %w", err)
	}
	base.Kind, base.Ref = ResultPending, "pending"
	s.record(ctx, base)
	return Result{Kind: ResultPending, Pending: h, ReturnPath: tx.ReturnPath}, nil
}

func (s *Service) record(ctx context.Context, o Outcome) {
	if err := s.Recorder.Record(ctx, o); err != nil && s.Log != nil {
		s.Log.ErrorContext(ctx, "sso: audit record failed", "tenant_id", o.Tenant.String(), "reason", o.Reason, "error", err)
	}
}

func (s *Service) refuse(ctx context.Context, o Outcome) error {
	s.record(ctx, o)
	return ErrSignInFailed
}

// anchorKind maps a verifier's claim name to the only two kinds that bind (DM-30.I5). Anything else,
// a UPN or an email included, maps to "" and binds nothing.
func anchorKind(claim string) authn.AnchorKind {
	switch claim {
	case "oid":
		return authn.AnchorOID
	case "onprem_sid":
		return authn.AnchorOnpremSID
	}
	return ""
}

// applyAnchor binds an unbound account once, or checks a bound account against the verified anchor
// (DM-30.I5, console-sso.md 7.2). It never rebinds. A non-empty reason is a refusal.
func (s *Service) applyAnchor(ctx context.Context, t tenant.ID, acct authn.Account, ver sso.Verified, o *Outcome) (string, error) {
	var an *authn.Anchor
	if ver.Anchor != nil {
		if k := anchorKind(ver.Anchor.Claim); k != "" {
			an = &authn.Anchor{Kind: k, Value: ver.Anchor.Value, TenantID: ver.Anchor.TID}
		}
	}
	if acct.Anchor != nil {
		// A bound account must prove the same anchor: absent evidence is not enough to keep the
		// directory-derived grants (fail closed).
		if an == nil {
			return ReasonAnchorMissing, nil
		}
		ref, err := s.Anchors.Resolve(ctx, t, *an)
		switch {
		case errors.Is(err, authn.ErrAnchorNoMatch):
			return ReasonAnchorChanged, nil
		case err != nil:
			return "", fmt.Errorf("signin: resolve anchor: %w", err)
		}
		if acct.Ref == nil || ref != *acct.Ref {
			return ReasonAnchorChanged, nil
		}
		return "", nil
	}
	if an == nil {
		return "", nil // no usable anchor claim: no binding, the sign-in goes on
	}
	ref, err := s.Anchors.Resolve(ctx, t, *an)
	switch {
	case errors.Is(err, authn.ErrAnchorNoMatch):
		o.Warnings = append(o.Warnings, WarnBindingUnresolved)
		return "", nil
	case err != nil:
		return "", fmt.Errorf("signin: resolve anchor: %w", err)
	}
	by := authority.Chain{Requester: authority.Principal{ID: "system", Kind: authority.System}}
	if _, err := s.Accounts.Bind(ctx, t, acct.ID, *an, ref, by); err != nil {
		switch {
		case errors.Is(err, authn.ErrAlreadyBound), errors.Is(err, authn.ErrAccountExists):
			// Another sign-in bound it, or another account already holds that object. Never rebind.
			return ReasonAnchorChanged, nil
		case errors.Is(err, authn.ErrInvalidInput):
			o.Warnings = append(o.Warnings, WarnBindingUnresolved)
			return "", nil
		}
		return "", fmt.Errorf("signin: bind account: %w", err)
	}
	return "", nil
}
