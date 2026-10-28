package authn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

func init() {
	for _, n := range []string{"authn_authority_challenges", "authn_authority_approvals", "authn_authority_notices"} {
		_ = tablekind.Declare(tablekind.Table{Name: "public." + n, Entity: "DM-37", Kind: tablekind.Tenant})
	}
}

// The authority factor (threat model §6.9, TM-D19 rules 1 and 2; DM-37 webauthn, DM-30.I6).
//
// An sso account reaches AD-side grants through a correlation only in a session that verified an
// activeDIQ-held WebAuthn credential of that account. The Entra sign-in alone never carries that
// authority, whoever can issue a TAP or reset methods in Entra. This file owns:
//
//   - enrolment, anchored OUTSIDE Entra: a connector proof of the correlated AD account (ADProver), or a
//     tenant-owner's approval given with step-up. Exactly one of the two; neither is a refusal;
//   - reset and removal: a tenant-owner with step-up only. The owner set is the account store's
//     OwnerSource (direct tenant-owner assignments; control-plane authority is personal and never
//     derived from a group or a correlation, DM-36.I4), so no Entra-derived role can qualify;
//   - the per-session verification that sets authority_factor_at (and mfa_at: a user-verified WebAuthn
//     assertion is a valid step-up). Session.AuthorityCurrent says whether it still counts;
//   - the audit trail and the notices (the account and every tenant-owner) of every change.
//
// Nothing here reads an Entra fact. An Entra-side method reset or TAP changes none of the tables below,
// so the factor stays required (acceptance 4).

// Audit kinds of the authority factor. None carries a credential, a challenge or an AD secret.
const (
	KindAuthorityApproved       audit.Kind = "authn.authority.approved"
	KindAuthorityEnrolled       audit.Kind = "authn.authority.enrolled"
	KindAuthorityEnrolRefused   audit.Kind = "authn.authority.enrol_refused"
	KindAuthorityReset          audit.Kind = "authn.authority.reset"
	KindAuthorityRemoved        audit.Kind = "authn.authority.removed"
	KindAuthorityChangeRefused  audit.Kind = "authn.authority.change_refused"
	KindAuthorityVerified       audit.Kind = "authn.authority.verified"
	KindAuthorityVerifyRefused  audit.Kind = "authn.authority.verify_refused"
	authorityApprovalTTL                   = 15 * time.Minute
	authorityChallengeTTL                  = 5 * time.Minute
	noticeEnrolled, noticeReset            = "enrolled", "reset"
	noticeRemoved                          = "removed"
)

// Refusal reasons, recorded in the audit event and on the typed error. Stable and safe to log.
const (
	AuthorityNoProof          = "no_proof"             // neither an AD-plane proof nor an owner approval
	AuthorityTwoProofs        = "two_proofs"           // both given: the caller must say which anchors the enrolment
	AuthorityADProofRefused   = "ad_proof_refused"     // the connector did not prove the correlated AD account
	AuthorityADProofMissing   = "ad_proof_unavailable" // no connector port is configured: fail closed
	AuthorityApprovalInvalid  = "approval_invalid"     // unknown, expired, used, another account's, or the approver lost ownership
	AuthorityNotEligible      = "not_eligible"         // not an active, bound sso account
	AuthorityAlreadyEnrolled  = "already_enrolled"     // an authority credential is active: reset it first
	AuthorityNotOwner         = "not_owner"            // the actor is not a tenant-owner by direct assignment
	AuthorityStepUpRequired   = "step_up_required"     // no fresh step-up
	AuthorityNoSession        = "no_session"           // the session is not active or is not the actor's
	AuthorityNoChallenge      = "no_challenge"         // none issued, expired, or already used
	AuthorityAttestationBad   = "attestation_invalid"
	AuthorityNoCredential     = "no_credential" // nothing enrolled
	AuthorityAssertionInvalid = RefusedAssertionInvalid
	AuthorityCounter          = RefusedCounterRegression
)

// ErrAuthorityRefused is every refusal of the authority factor. Use errors.As with *AuthorityRefusal for
// the reason; the HTTP layer maps the reason to a problem document and never echoes more.
var ErrAuthorityRefused = errors.New("authn: authority factor request refused")

// AuthorityRefusal carries the reason of a refusal.
type AuthorityRefusal struct{ Reason string }

func (r *AuthorityRefusal) Error() string {
	return "authn: authority factor request refused: " + r.Reason
}
func (r *AuthorityRefusal) Is(target error) bool { return target == ErrAuthorityRefused }

func refused(reason string) error { return &AuthorityRefusal{Reason: reason} }

// ErrADProofRefused is what an ADProver returns when the credential does not prove the AD account.
// Any other error is an infrastructure fault and is returned as such, never as a refusal.
var ErrADProofRefused = errors.New("authn: AD proof refused")

// ADProver is the connector's VerifyUser (BP §11) as this package needs it: prove that the holder of
// credential knows the AD account ref names, with nothing written and nothing returned. The credential
// is never logged, stored or put in an audit event; the caller zeroes it after the call.
type ADProver interface {
	VerifyUser(ctx context.Context, t tenant.ID, ref DirectoryRef, credential []byte) error
}

// Actor is the human behind a request: the account and the console session it acts through.
type Actor struct{ Account, SessionID string }

func (a Actor) valid() bool { return validAccount(a.Account) && validAccount(a.SessionID) }

// AuthorityFactors is the service. Every field is required except AD (nil refuses the AD-proof path).
type AuthorityFactors struct {
	DB       *store.DB
	Sessions *Store
	Accounts *Accounts
	Owners   OwnerSource
	StepUp   apihost.StepUpChecker
	AD       ADProver

	wa *webauthn.WebAuthn
}

// NewAuthorityFactors validates the relying party and returns the service.
func NewAuthorityFactors(cfg WebAuthnConfig, db *store.DB, sessions *Store, accounts *Accounts, owners OwnerSource, stepUp apihost.StepUpChecker, ad ADProver) (*AuthorityFactors, error) {
	if db == nil || sessions == nil || accounts == nil || owners == nil || stepUp == nil || len(cfg.Origins) == 0 {
		return nil, errors.New("authn: AuthorityFactors is not fully configured")
	}
	wa, err := webauthn.New(&webauthn.Config{RPID: cfg.RPID, RPDisplayName: cfg.RPDisplayName, RPOrigins: cfg.Origins,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: authorityChallengeTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: authorityChallengeTTL}}})
	if err != nil {
		return nil, fmt.Errorf("authn: WebAuthn relying party: %w", err)
	}
	return &AuthorityFactors{DB: db, Sessions: sessions, Accounts: accounts, Owners: owners, StepUp: stepUp, AD: ad, wa: wa}, nil
}

// ---------------------------------------------------------------------------------------------------
// shared checks

// session checks, inside tx, that the actor's session is active and is the account's, and that the
// account is an active sso account. It locks the session row.
func (f *AuthorityFactors) session(ctx context.Context, tx store.Tx, t tenant.ID, a Actor, now time.Time) error {
	var n int
	err := tx.QueryRow(ctx, `SELECT 1 FROM public.authn_sessions s
JOIN public.authn_accounts c ON c.tenant_id = s.tenant_id AND c.id = s.account_id
WHERE s.tenant_id = $1::uuid AND s.id = $2::uuid AND s.account_id = $3::uuid AND s.state = 'active'
  AND s.idle_expiry > $4 AND s.absolute_expiry > $4 AND c.state = 'active' FOR UPDATE OF s`,
		t.String(), a.SessionID, a.Account, now).Scan(&n)
	if store.IsNoRows(err) {
		return refused(AuthorityNoSession)
	}
	return err
}

// requireOwner is the gate of approve, reset and remove: a fresh step-up of the actor's own session, and
// a direct tenant-owner assignment. fresh is read before the transaction (it opens its own).
func (f *AuthorityFactors) requireOwner(ctx context.Context, tx store.Tx, t tenant.ID, a Actor, fresh bool) error {
	if !fresh {
		return refused(AuthorityStepUpRequired)
	}
	owners, err := f.Owners.TenantOwners(ctx, tx, t)
	if err != nil {
		return err
	}
	for _, o := range owners {
		if o == a.Account {
			return nil
		}
	}
	return refused(AuthorityNotOwner)
}

func (f *AuthorityFactors) freshStepUp(ctx context.Context, t tenant.ID, a Actor) (bool, error) {
	return f.StepUp.Fresh(ctx, apihost.Principal{ID: a.Account, Tenant: t.String(), Kind: apihost.KindSession, SessionID: a.SessionID})
}

// eligible reads the account that an authority factor can be held by: active, sso, bound to a directory
// object. It returns the directory reference the AD proof is about.
func eligible(ctx context.Context, tx store.Tx, t tenant.ID, account string) (DirectoryRef, error) {
	var ref DirectoryRef
	err := tx.QueryRow(ctx, `SELECT directory_connection_id::text, directory_object_guid::text FROM public.authn_accounts
WHERE tenant_id = $1::uuid AND id = $2::uuid AND kind = 'sso' AND state = 'active'
  AND directory_connection_id IS NOT NULL AND directory_object_guid IS NOT NULL`, t.String(), account).Scan(&ref.ConnectionID, &ref.ObjectGUID)
	if store.IsNoRows(err) {
		return DirectoryRef{}, refused(AuthorityNotEligible)
	}
	return ref, err
}

func hasAuthorityCredential(ctx context.Context, tx store.Tx, t tenant.ID, account string) (bool, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_webauthn_credentials
WHERE tenant_id = $1::uuid AND account_id = $2::uuid AND purpose = 'authority' AND state = 'active'`, t.String(), account).Scan(&n)
	return n > 0, err
}

// event builds an audit event; details must be in strictly increasing key order.
func (f *AuthorityFactors) event(now time.Time, kind audit.Kind, out audit.Outcome, actor Actor, target, reason string, details ...audit.Detail) audit.Event {
	return audit.Event{
		ID: "authn.authority." + target + "." + string(kind) + "." + strconv.FormatInt(now.UnixNano(), 10), Kind: kind, At: now,
		Actor: accountChain(actor.Account), Target: authority.TargetRef{GUID: target, Class: "account"},
		Component: "authn", Outcome: out, Reason: reason, Details: details,
	}
}

func (f *AuthorityFactors) appendEvent(ctx context.Context, tx store.Tx, ev audit.Event) error {
	if err := f.Sessions.audit.Append(ctx, tx, ev); err != nil {
		return fmt.Errorf("authn: audit authority factor: %w", err)
	}
	return nil
}

// deny records a refusal in its own committed transaction and returns the refusal (or the audit failure).
// clearFactor also drops the session's authority_factor_at: a failed verification must not leave AD-side
// authority standing (DM-31.I3).
func (f *AuthorityFactors) deny(ctx context.Context, t tenant.ID, kind audit.Kind, a Actor, target string, err error, clearFactor bool) error {
	var r *AuthorityRefusal
	if !errors.As(err, &r) {
		return err
	}
	aerr := f.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := f.Sessions.now(ctx, tx)
		if err != nil {
			return err
		}
		if clearFactor && validAccount(a.SessionID) {
			if _, err := tx.Exec(ctx, `UPDATE public.authn_sessions SET authority_factor_at = NULL
WHERE tenant_id = $1::uuid AND id = $2::uuid AND account_id = $3::uuid AND state = 'active'`, t.String(), a.SessionID, a.Account); err != nil {
				return err
			}
		}
		return f.appendEvent(ctx, tx, f.event(now, kind, audit.Denied, a, target, r.Reason))
	})
	if aerr != nil {
		return fmt.Errorf("authn: record authority refusal: %w", aerr)
	}
	return err
}

// notify writes the outbox rows of a change: the account and every tenant-owner, once each.
func (f *AuthorityFactors) notify(ctx context.Context, tx store.Tx, t tenant.ID, now time.Time, event, subject, actor string) error {
	owners, err := f.Owners.TenantOwners(ctx, tx, t)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, r := range append([]string{subject}, owners...) {
		if seen[r] {
			continue
		}
		seen[r] = true
		if _, err := tx.Exec(ctx, `INSERT INTO public.authn_authority_notices (tenant_id, recipient_id, subject_id, event, actor_id, created_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::uuid, $6)`, t.String(), r, subject, event, actor, now); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------
// owner approval

// Approval is a tenant-owner's approval of one enrolment.
type Approval struct {
	ID        string
	ExpiresAt time.Time
}

// Approve records a tenant-owner's approval for target to enrol an authority factor (TM-D19 rule 2,
// second anchor). The approver needs a fresh step-up, must hold tenant-owner directly, and cannot approve
// for themselves. The approval is single-use and lives 15 minutes.
func (f *AuthorityFactors) Approve(ctx context.Context, t tenant.ID, approver Actor, target string) (Approval, error) {
	if t.IsZero() || !approver.valid() || !validAccount(target) {
		return Approval{}, ErrInvalid
	}
	fresh, err := f.freshStepUp(ctx, t, approver)
	if err != nil {
		return Approval{}, err
	}
	var out Approval
	err = f.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := f.Sessions.now(ctx, tx)
		if err != nil {
			return err
		}
		if err := f.session(ctx, tx, t, approver, now); err != nil {
			return err
		}
		if err := f.requireOwner(ctx, tx, t, approver, fresh); err != nil {
			return err
		}
		if target == approver.Account {
			return refused(AuthorityApprovalInvalid) // an owner enrols through an AD proof or another owner
		}
		if _, err := eligible(ctx, tx, t, target); err != nil {
			return err
		}
		out.ExpiresAt = now.Add(authorityApprovalTTL)
		if err := tx.QueryRow(ctx, `INSERT INTO public.authn_authority_approvals (tenant_id, account_id, approver_id, created_at, expires_at)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5) RETURNING id::text`, t.String(), target, approver.Account, now, out.ExpiresAt).Scan(&out.ID); err != nil {
			return err
		}
		return f.appendEvent(ctx, tx, f.event(now, KindAuthorityApproved, audit.Success, approver, target, "", audit.Detail{Key: "approval", Value: out.ID}))
	})
	if err != nil {
		return Approval{}, f.deny(ctx, t, KindAuthorityChangeRefused, approver, target, err, false)
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------------
// enrolment

// EnrolInput starts an enrolment. Exactly one proof: ADCredential (the AD password of the correlated
// account, handed to the connector's VerifyUser and zeroed) or ApprovalID (from Approve).
type EnrolInput struct {
	Actor        Actor
	ADCredential []byte
	ApprovalID   string
}

// BeginEnrol checks the proof and issues the registration options for navigator.credentials.create. The
// proof is spent here; a ceremony that then fails starts over with a new proof.
func (f *AuthorityFactors) BeginEnrol(ctx context.Context, t tenant.ID, in EnrolInput) (*protocol.CredentialCreation, error) {
	defer zero(in.ADCredential)
	a := in.Actor
	if t.IsZero() || !a.valid() || (in.ApprovalID != "" && !uuidRe.MatchString(in.ApprovalID)) {
		return nil, ErrInvalid
	}
	creation, err := f.beginEnrol(ctx, t, in)
	if err != nil {
		return nil, f.deny(ctx, t, KindAuthorityEnrolRefused, a, a.Account, err, false)
	}
	return creation, nil
}

func (f *AuthorityFactors) beginEnrol(ctx context.Context, t tenant.ID, in EnrolInput) (*protocol.CredentialCreation, error) {
	a := in.Actor
	switch hasAD, hasApproval := len(in.ADCredential) > 0, in.ApprovalID != ""; {
	case hasAD && hasApproval:
		return nil, refused(AuthorityTwoProofs)
	case !hasAD && !hasApproval:
		return nil, refused(AuthorityNoProof)
	}
	// Stage 1: who is asking, and which AD account the proof is about.
	var ref DirectoryRef
	err := f.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := f.Sessions.now(ctx, tx)
		if err != nil {
			return err
		}
		if err := f.session(ctx, tx, t, a, now); err != nil {
			return err
		}
		if ref, err = eligible(ctx, tx, t, a.Account); err != nil {
			return err
		}
		if has, err := hasAuthorityCredential(ctx, tx, t, a.Account); err != nil {
			return err
		} else if has {
			return refused(AuthorityAlreadyEnrolled)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// The connector call runs outside any transaction: it is a network round trip to a domain controller.
	proof := "owner_approval"
	if len(in.ADCredential) > 0 {
		proof = "ad_proof"
		if f.AD == nil {
			return nil, refused(AuthorityADProofMissing)
		}
		switch err := f.AD.VerifyUser(ctx, t, ref, in.ADCredential); {
		case err == nil:
		case errors.Is(err, ErrADProofRefused):
			return nil, refused(AuthorityADProofRefused)
		default:
			return nil, fmt.Errorf("authn: AD proof: %w", err)
		}
	}
	// Stage 2: spend the approval, if that is the proof, and issue the challenge, in one transaction.
	var creation *protocol.CredentialCreation
	err = f.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := f.Sessions.now(ctx, tx)
		if err != nil {
			return err
		}
		if err := f.session(ctx, tx, t, a, now); err != nil {
			return err
		}
		if proof == "owner_approval" {
			var approver string
			err := tx.QueryRow(ctx, `UPDATE public.authn_authority_approvals SET consumed_at = $4
WHERE tenant_id = $1::uuid AND id = $2::uuid AND account_id = $3::uuid AND consumed_at IS NULL AND expires_at > $4
RETURNING approver_id::text`, t.String(), in.ApprovalID, a.Account, now).Scan(&approver)
			if store.IsNoRows(err) {
				return refused(AuthorityApprovalInvalid)
			}
			if err != nil {
				return err
			}
			// The approver must still hold tenant-owner now (a demoted owner's approval dies with the role).
			owners, err := f.Owners.TenantOwners(ctx, tx, t)
			if err != nil {
				return err
			}
			if !contains(owners, approver) {
				return refused(AuthorityApprovalInvalid)
			}
		}
		handle, err := userHandle(ctx, tx, t, a.Account)
		if err != nil {
			return err
		}
		c, session, err := f.wa.BeginRegistration(waUser{handle: handle},
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				ResidentKey: protocol.ResidentKeyRequirementDiscouraged, UserVerification: protocol.VerificationRequired}),
			webauthn.WithConveyancePreference(protocol.PreferNoAttestation))
		if err != nil {
			return err
		}
		challenge, err := base64.RawURLEncoding.DecodeString(session.Challenge)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.authn_authority_challenges
  (tenant_id, kind, subject_id, account_id, challenge, user_handle, proof, created_at, expires_at)
VALUES ($1::uuid, 'register', $2::uuid, $2::uuid, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_id, kind, subject_id) DO UPDATE SET challenge = EXCLUDED.challenge, user_handle = EXCLUDED.user_handle,
  proof = EXCLUDED.proof, created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at, consumed_at = NULL`,
			t.String(), a.Account, challenge, handle, proof, now, now.Add(authorityChallengeTTL)); err != nil {
			return err
		}
		creation = c
		return nil
	})
	return creation, err
}

// userHandle is the account's stable WebAuthn user handle: the one its earlier authority credentials
// used, or a new random one.
func userHandle(ctx context.Context, tx store.Tx, t tenant.ID, account string) ([]byte, error) {
	var h []byte
	err := tx.QueryRow(ctx, `SELECT user_handle FROM public.authn_webauthn_credentials
WHERE tenant_id = $1::uuid AND account_id = $2::uuid AND purpose = 'authority' ORDER BY created_at LIMIT 1`, t.String(), account).Scan(&h)
	if store.IsNoRows(err) {
		h = make([]byte, 32)
		_, err = rand.Read(h)
	}
	return h, err
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// takeAuthorityChallenge consumes the live challenge of kind for subject in its own committed
// transaction (the response is looked at only afterwards, so a captured response verifies at most once).
func (f *AuthorityFactors) takeChallenge(ctx context.Context, t tenant.ID, kind, subject string) (challenge, handle []byte, proof string, err error) {
	var p *string
	err = f.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := f.Sessions.now(ctx, tx)
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `UPDATE public.authn_authority_challenges SET consumed_at = $4
WHERE tenant_id = $1::uuid AND kind = $2 AND subject_id = $3::uuid AND consumed_at IS NULL AND expires_at > $4
RETURNING challenge, user_handle, proof`, t.String(), kind, subject, now).Scan(&challenge, &handle, &p)
		if store.IsNoRows(err) {
			return refused(AuthorityNoChallenge)
		}
		return err
	})
	if p != nil {
		proof = *p
	}
	return
}

// FinishEnrolInput is the authenticator's registration response, each field base64url without padding.
type FinishEnrolInput struct {
	Actor                                           Actor
	Label                                           string
	CredentialID, AttestationObject, ClientDataJSON string
}

// FinishEnrol verifies the registration response against the challenge BeginEnrol issued and stores the
// credential. The enrolment is audited and the account and every tenant-owner are notified in the same
// transaction.
func (f *AuthorityFactors) FinishEnrol(ctx context.Context, t tenant.ID, in FinishEnrolInput) (string, error) {
	a := in.Actor
	if t.IsZero() || !a.valid() || in.Label == "" || len(in.Label) > 128 {
		return "", ErrInvalid
	}
	id, err := f.finishEnrol(ctx, t, in)
	if err != nil {
		return "", f.deny(ctx, t, KindAuthorityEnrolRefused, a, a.Account, err, false)
	}
	return id, nil
}

func (f *AuthorityFactors) finishEnrol(ctx context.Context, t tenant.ID, in FinishEnrolInput) (string, error) {
	a := in.Actor
	challenge, handle, proof, err := f.takeChallenge(ctx, t, "register", a.Account)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(map[string]any{"id": in.CredentialID, "rawId": in.CredentialID, "type": "public-key",
		"response": map[string]string{"clientDataJSON": in.ClientDataJSON, "attestationObject": in.AttestationObject}})
	if err != nil {
		return "", err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(raw)
	if err != nil {
		return "", refused(AuthorityAttestationBad)
	}
	cred, err := f.wa.CreateCredential(waUser{handle: handle}, webauthn.SessionData{
		Challenge: base64.RawURLEncoding.EncodeToString(challenge), RelyingPartyID: f.wa.Config.RPID, UserID: handle,
		UserVerification: protocol.VerificationRequired, CredParams: webauthn.CredentialParametersDefault()}, parsed)
	if err != nil {
		return "", refused(AuthorityAttestationBad)
	}
	var id string
	err = f.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := f.Sessions.now(ctx, tx)
		if err != nil {
			return err
		}
		if err := f.session(ctx, tx, t, a, now); err != nil {
			return err
		}
		if _, err := eligible(ctx, tx, t, a.Account); err != nil {
			return err
		}
		if has, err := hasAuthorityCredential(ctx, tx, t, a.Account); err != nil {
			return err
		} else if has {
			return refused(AuthorityAlreadyEnrolled)
		}
		id, err = insertCredential(ctx, tx, t, a.Account, purposeAuthority, WebAuthnCredential{CredentialID: cred.ID, PublicKey: cred.PublicKey,
			UserHandle: handle, BackupEligible: cred.Flags.BackupEligible, AAGUID: nilIfEmptyBytes(cred.Authenticator.AAGUID),
			SignCount: cred.Authenticator.SignCount, Label: in.Label})
		if err != nil {
			return err
		}
		if err := f.notify(ctx, tx, t, now, noticeEnrolled, a.Account, a.Account); err != nil {
			return err
		}
		return f.appendEvent(ctx, tx, f.event(now, KindAuthorityEnrolled, audit.Success, a, a.Account, proof, audit.Detail{Key: "credential", Value: id}))
	})
	return id, err
}

func nilIfEmptyBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// ---------------------------------------------------------------------------------------------------
// reset and removal

// Reset revokes target's authority factor so that it can be enrolled again (through an AD proof or an
// owner approval). Remove revokes it for good: until a new enrolment the account has no AD-side authority
// from a correlation. Both are tenant-owner actions with a fresh step-up; both audit and notify.
func (f *AuthorityFactors) Reset(ctx context.Context, t tenant.ID, owner Actor, target string) error {
	return f.revoke(ctx, t, owner, target, KindAuthorityReset, noticeReset)
}

// Remove: see Reset.
func (f *AuthorityFactors) Remove(ctx context.Context, t tenant.ID, owner Actor, target string) error {
	return f.revoke(ctx, t, owner, target, KindAuthorityRemoved, noticeRemoved)
}

func (f *AuthorityFactors) revoke(ctx context.Context, t tenant.ID, owner Actor, target string, kind audit.Kind, event string) error {
	if t.IsZero() || !owner.valid() || !validAccount(target) {
		return ErrInvalid
	}
	fresh, err := f.freshStepUp(ctx, t, owner)
	if err != nil {
		return err
	}
	err = f.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := f.Sessions.now(ctx, tx)
		if err != nil {
			return err
		}
		if err := f.session(ctx, tx, t, owner, now); err != nil {
			return err
		}
		if err := f.requireOwner(ctx, tx, t, owner, fresh); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE public.authn_webauthn_credentials SET state = 'revoked'
WHERE tenant_id = $1::uuid AND account_id = $2::uuid AND purpose = 'authority' AND state = 'active'`, t.String(), target)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return refused(AuthorityNoCredential)
		}
		// AD-side authority ends now, in every session of the account, and no approval granted before
		// the change can be used after it.
		if _, err := tx.Exec(ctx, `UPDATE public.authn_sessions SET authority_factor_at = NULL
WHERE tenant_id = $1::uuid AND account_id = $2::uuid AND state = 'active'`, t.String(), target); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE public.authn_authority_approvals SET consumed_at = $3
WHERE tenant_id = $1::uuid AND account_id = $2::uuid AND consumed_at IS NULL`, t.String(), target, now); err != nil {
			return err
		}
		if err := f.notify(ctx, tx, t, now, event, target, owner.Account); err != nil {
			return err
		}
		return f.appendEvent(ctx, tx, f.event(now, kind, audit.Success, owner, target, ""))
	})
	if err != nil {
		return f.deny(ctx, t, KindAuthorityChangeRefused, owner, target, err, false)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------
// per-session verification

// BeginVerify issues the assertion options for the actor's session.
func (f *AuthorityFactors) BeginVerify(ctx context.Context, t tenant.ID, a Actor) (WebAuthnOptions, error) {
	if t.IsZero() || !a.valid() {
		return WebAuthnOptions{}, ErrInvalid
	}
	var out WebAuthnOptions
	err := f.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := f.Sessions.now(ctx, tx)
		if err != nil {
			return err
		}
		if err := f.session(ctx, tx, t, a, now); err != nil {
			return err
		}
		cs, err := credentials(ctx, tx, t, a.Account, purposeAuthority)
		if err != nil {
			return err
		}
		if len(cs) == 0 {
			return refused(AuthorityNoCredential)
		}
		_, sd, err := f.wa.BeginLogin(toUser(cs), webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			return err
		}
		challenge, err := base64.RawURLEncoding.DecodeString(sd.Challenge)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.authn_authority_challenges
  (tenant_id, kind, subject_id, account_id, challenge, user_handle, created_at, expires_at)
VALUES ($1::uuid, 'assert', $2::uuid, $3::uuid, $4, $5, $6, $7)
ON CONFLICT (tenant_id, kind, subject_id) DO UPDATE SET challenge = EXCLUDED.challenge, user_handle = EXCLUDED.user_handle,
  created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at, consumed_at = NULL`,
			t.String(), a.SessionID, a.Account, challenge, cs[0].UserHandle, now, now.Add(authorityChallengeTTL)); err != nil {
			return err
		}
		out = WebAuthnOptions{Challenge: sd.Challenge, RPID: f.wa.Config.RPID, TimeoutMS: int64(authorityChallengeTTL / time.Millisecond),
			UserVerification: string(protocol.VerificationRequired)}
		for _, c := range cs {
			out.AllowCredentials = append(out.AllowCredentials, base64.RawURLEncoding.EncodeToString(c.CredentialID))
		}
		return nil
	})
	if err != nil {
		return WebAuthnOptions{}, f.deny(ctx, t, KindAuthorityVerifyRefused, a, a.Account, err, false)
	}
	return out, nil
}

// Verify checks the assertion for the actor's session. On success the session's authority_factor_at and
// mfa_at are both now: the factor is current, and the user-verified assertion is also a step-up. On a
// refusal the session's authority_factor_at is cleared (the refusal is audited and commits).
func (f *AuthorityFactors) Verify(ctx context.Context, t tenant.ID, a Actor, in WebAuthnAssertion) error {
	if t.IsZero() || !a.valid() {
		return ErrInvalid
	}
	if err := f.verify(ctx, t, a, in); err != nil {
		return f.deny(ctx, t, KindAuthorityVerifyRefused, a, a.Account, err, true)
	}
	return nil
}

func (f *AuthorityFactors) verify(ctx context.Context, t tenant.ID, a Actor, in WebAuthnAssertion) error {
	challenge, _, _, err := f.takeChallenge(ctx, t, "assert", a.SessionID)
	if err != nil {
		return err
	}
	parsed, err := parseAssertion(in)
	if err != nil {
		return refused(AuthorityAssertionInvalid)
	}
	return f.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := f.Sessions.now(ctx, tx)
		if err != nil {
			return err
		}
		if err := f.session(ctx, tx, t, a, now); err != nil {
			return err
		}
		cs, err := credentials(ctx, tx, t, a.Account, purposeAuthority)
		if err != nil {
			return err
		}
		if len(cs) == 0 {
			return refused(AuthorityNoCredential)
		}
		user := toUser(cs)
		allowed := make([][]byte, 0, len(cs))
		for _, c := range cs {
			allowed = append(allowed, c.CredentialID)
		}
		cred, err := f.wa.ValidateLogin(user, webauthn.SessionData{Challenge: base64.RawURLEncoding.EncodeToString(challenge),
			RelyingPartyID: f.wa.Config.RPID, UserID: user.handle, AllowedCredentialIDs: allowed,
			UserVerification: protocol.VerificationRequired}, parsed)
		if err != nil {
			return refused(AuthorityAssertionInvalid)
		}
		if reason, err := useCredential(ctx, tx, t, cs, cred.ID, parsed, now); err != nil {
			return err
		} else if reason != "" {
			return refused(reason)
		}
		if _, err := tx.Exec(ctx, `UPDATE public.authn_sessions SET authority_factor_at = $4, mfa_at = $4
WHERE tenant_id = $1::uuid AND id = $2::uuid AND account_id = $3::uuid AND state = 'active'`, t.String(), a.SessionID, a.Account, now); err != nil {
			return err
		}
		return f.appendEvent(ctx, tx, f.event(now, KindAuthorityVerified, audit.Success, a, a.Account, "", audit.Detail{Key: "session", Value: a.SessionID}))
	})
}
