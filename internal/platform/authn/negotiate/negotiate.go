// Package negotiate is the sign-in core of AN-9, SPNEGO sign-in (threat model §7.6 rules 2, 5, 6, 7;
// console-sso.md §9 NEG-1..9): a Kerberos AP-REQ for our HTTP service principal, verified by an
// Acceptor, becomes a pending sign-in (AN-10) for exactly one console account, never a session.
//
// It holds no net/http (ADR-0004 A6); httpx/negotiatehttp is the header binding. The rules it enforces:
//   - Kerberos only. A token that is not a SPNEGO NegTokenInit offering Kerberos first is refused by
//     structure (RequireKerberos) before any acceptor sees it, so NTLM is never reachable (TM-X2).
//   - The principal maps by the PAC logon-info user SID the acceptor verified, resolved to an
//     objectGUID through the Directory port (the composition root fills it from the inventory), never
//     by name or UPN (NEG-2).
//   - Every failure is the same ErrSignInFailed: unmapped, ambiguous, disabled, replayed, malformed,
//     credentials changed. The reason goes only to the Recorder (audit) and the log.
package negotiate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ErrSignInFailed is the one answer to every way a Negotiate sign-in can fail. The caller renders the
// generic 401; the reasons differ only in the audit trail.
var ErrSignInFailed = errors.New("negotiate: sign-in failed")

// Reasons recorded for a refusal (audit and log only, never shown to the client).
const (
	ReasonNotKerberos = "not_kerberos"
	ReasonRejected    = "ticket_rejected" // bad, expired, replayed or wrong-service ticket
	ReasonUnmapped    = "unmapped"        // no inventory object, or no console account, for the SID
	ReasonAmbiguous   = "ambiguous"       // more than one object or account for the SID
	ReasonInactive    = "account_inactive"
	ReasonChanged     = "credentials_changed"
)

// Principal is what an Acceptor proved: the user SID of the PAC logon-info, verified with the service
// key, as canonical SID text ("S-1-..."). It carries no name; names are mutable and are not an identity.
type Principal struct{ SID string }

// Acceptor verifies a SPNEGO/Kerberos token for our HTTP service principal. Implementations must
// refuse a replayed AP-REQ (NEG-6), verify the PAC signature with the service key, and never fall back
// to NTLM. Any error is a refusal; the service does not look at its text.
type Acceptor interface {
	Accept(ctx context.Context, token []byte) (Principal, error)
}

// Directory is the port that resolves a SID to the live directory objects carrying it. The composition
// root fills it; this package imports no directory package. sid is canonical SID text. An absent or
// malformed SID is an empty answer (unmapped), not an error; an error is an infrastructure failure.
// The implementation need not return more than a few matches: this package treats more than one as
// ambiguous (NEG-2) and looks no further.
type Directory interface {
	ObjectsBySID(ctx context.Context, t tenant.ID, sid string) ([]authn.DirectoryRef, error)
}

// Accounts finds and reads console accounts.
type Accounts interface {
	BackedBy(ctx context.Context, t tenant.ID, ref authn.DirectoryRef) ([]string, error)
	Get(ctx context.Context, t tenant.ID, id string) (authn.Account, error)
}

// Epochs reads an account's session epoch (T-0429).
type Epochs interface {
	Epoch(ctx context.Context, t tenant.ID, account string) (authn.Epoch, error)
}

// Pending creates pending sign-ins.
type Pending interface {
	Begin(ctx context.Context, in authn.BeginInput) (authn.PendingHandle, error)
}

// Recorder takes the audit record of a refusal (negotiate.unmapped, negotiate.ambiguous, ...). It must
// not fail the sign-in path differently from a success: its error is logged by the service only.
type Recorder interface {
	Refused(ctx context.Context, t tenant.ID, reason string, from netip.Addr) error
}

// Service is the AN-9 core. All fields are required.
type Service struct {
	Acceptor  Acceptor
	Directory Directory
	Accounts  Accounts
	Epochs    Epochs
	Pending   Pending
	Recorder  Recorder
	Log       *slog.Logger
}

// decoyAccount is a well-formed account ID no account has, used to run the same calls on the unmapped
// path as on the mapped one so the two do not differ by a database round trip.
const decoyAccount = "00000000-0000-4000-8000-00000000d0c0"

// Request is one Negotiate sign-in attempt.
type Request struct {
	Tenant   tenant.ID
	Token    []byte     // the decoded Negotiate token, at most MaxTokenBytes
	ClientIP netip.Addr // zero when unknown
}

// SignIn accepts a Kerberos token and returns the pending-sign-in handle for the cookie. Every refusal
// is ErrSignInFailed; a returned error that is not ErrSignInFailed is an infrastructure failure the
// caller answers as an internal error.
//
// Order note for the T-0429 contract: the account is not known until the ticket has been verified and
// the SID mapped, so Epoch is read right after the mapping and before Begin, not before verification.
// There is no console credential to verify here (the ticket is the AD plane's proof), so a reset that
// lands between verification and the Epoch read is a reset that precedes the pending sign-in.
func (s *Service) SignIn(ctx context.Context, req Request) (authn.PendingHandle, error) {
	if req.Tenant.IsZero() || s.Acceptor == nil || s.Directory == nil || s.Accounts == nil || s.Epochs == nil || s.Pending == nil || s.Recorder == nil {
		return authn.PendingHandle{}, errors.New("negotiate: service not configured")
	}
	if err := RequireKerberos(req.Token); err != nil {
		return s.refuse(ctx, req, ReasonNotKerberos)
	}
	p, err := s.Acceptor.Accept(ctx, req.Token)
	if err != nil {
		return s.refuse(ctx, req, ReasonRejected)
	}

	account, reason, err := s.mapAccount(ctx, req.Tenant, p.SID)
	if err != nil {
		return authn.PendingHandle{}, err
	}
	if reason != "" {
		// Same calls as a mapped account, on a decoy, before answering.
		_, _ = s.Accounts.Get(ctx, req.Tenant, decoyAccount)
		_, _ = s.Epochs.Epoch(ctx, req.Tenant, decoyAccount)
		return s.refuse(ctx, req, reason)
	}

	acct, err := s.Accounts.Get(ctx, req.Tenant, account)
	if err != nil {
		if errors.Is(err, authn.ErrAccountNotFound) {
			_, _ = s.Epochs.Epoch(ctx, req.Tenant, decoyAccount)
			return s.refuse(ctx, req, ReasonUnmapped)
		}
		return authn.PendingHandle{}, fmt.Errorf("negotiate: read account: %w", err)
	}
	epoch, err := s.Epochs.Epoch(ctx, req.Tenant, account)
	switch {
	case errors.Is(err, authn.ErrAccountInactive):
		return s.refuse(ctx, req, ReasonInactive)
	case err != nil:
		return authn.PendingHandle{}, fmt.Errorf("negotiate: read epoch: %w", err)
	}
	if acct.State != authn.AccountActive {
		return s.refuse(ctx, req, ReasonInactive)
	}
	h, err := s.Pending.Begin(ctx, authn.BeginInput{Tenant: req.Tenant, Account: account,
		FirstFactor: authn.FirstKerberos, ClientIP: req.ClientIP, Epoch: epoch})
	switch {
	case errors.Is(err, authn.ErrCredentialsChanged):
		return s.refuse(ctx, req, ReasonChanged)
	case errors.Is(err, authn.ErrAccountInactive):
		return s.refuse(ctx, req, ReasonInactive)
	case err != nil:
		return authn.PendingHandle{}, fmt.Errorf("negotiate: begin pending: %w", err)
	}
	return h, nil
}

// mapAccount resolves the SID to exactly one console account (NEG-2). A non-empty reason is a refusal.
func (s *Service) mapAccount(ctx context.Context, t tenant.ID, sid string) (account, reason string, err error) {
	objs, err := s.Directory.ObjectsBySID(ctx, t, sid)
	if err != nil {
		return "", "", fmt.Errorf("negotiate: resolve sid: %w", err)
	}
	switch len(objs) {
	case 0:
		_, _ = s.Accounts.BackedBy(ctx, t, authn.DirectoryRef{ConnectionID: decoyAccount, ObjectGUID: decoyAccount})
		return "", ReasonUnmapped, nil
	case 1:
	default:
		return "", ReasonAmbiguous, nil
	}
	ids, err := s.Accounts.BackedBy(ctx, t, objs[0])
	if err != nil {
		return "", "", fmt.Errorf("negotiate: find account: %w", err)
	}
	switch len(ids) {
	case 0:
		return "", ReasonUnmapped, nil
	case 1:
		return ids[0], "", nil
	default:
		return "", ReasonAmbiguous, nil
	}
}

func (s *Service) refuse(ctx context.Context, req Request, reason string) (authn.PendingHandle, error) {
	if err := s.Recorder.Refused(ctx, req.Tenant, reason, req.ClientIP); err != nil && s.Log != nil {
		s.Log.ErrorContext(ctx, "negotiate: refusal not recorded", "tenant_id", req.Tenant.String(), "reason", reason, "error", err)
	}
	return authn.PendingHandle{}, ErrSignInFailed
}
