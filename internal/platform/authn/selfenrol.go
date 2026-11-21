package authn

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.authn_enrolment_sessions", Entity: "DM-37", Kind: tablekind.Tenant})

// SelfEnrolment is the engine behind the end-user TOTP enrolment page, AN-5 (ENH-09 spec §6, TM-TB1-T13).
// It has no HTTP: the route that serves the page (and its own Negotiate exchange) calls it, and the route
// is the api-engineer's. What it fixes is the order and the rules, so no caller can skip them:
//
//  1. Own AD authentication, always. The only way to a handle is Authenticate (the connector's VerifyUser
//     behind the TM-TB1-T9 counter) or AuthenticateKerberos (the connector's SPNEGO acceptor). The handle
//     binds one directory user (connection and objectGUID); no later call takes a user ID, so a visitor
//     can enrol only the account they proved. A handle lives 10 minutes and allows 5 code confirmations.
//  2. Start creates the pending seed. It is refused without held contact data (the notice needs somewhere
//     to go), and refused when the user already has an active TOTP unless the current code of that factor
//     is given (6.3a) — a technician-verified reset (6.4) revokes the old factor first, so then nothing is
//     active and the rule is met. No seed exists after a refusal.
//  3. Confirm activates on the first valid code, revokes the replaced factor, queues the notice (6.5) and
//     audits (6.6), in one transaction. Delivery follows: the notice goes to contact data read live from
//     AD (never typed on the page); when the transport accepts it, cooling-off starts (24 hours), when it
//     fails the notice is retried every 15 minutes for 24 hours and then abandoned (RetryNotices).
//
// Everything a visitor can cause answers one error each: ErrEnrolRefused for any authentication failure
// (unknown, wrong password, disabled, throttled alike), ErrEnrolSession for a handle that is not live,
// ErrEnrolHelpDesk for "contact your help desk", ErrEnrolCodeRejected for a wrong code. The reason goes
// to the audit trail only. Enrolment is system bookkeeping (ADR-0005 rule 10): it writes only our own
// store, as a directory-user principal.
type SelfEnrolment struct {
	DB       *store.DB
	Factors  *Service
	Audit    audit.Sink // bound to DB (audit.NewChainer)
	Users    DirectoryUsers
	AD       ADProver
	Kerberos KerberosAcceptor
	Attempts *ADAttempts
	Contacts HeldContacts
	Sender   NoticeSender
	MAC      AttemptKeys
	// Floor is the least time Authenticate takes, so unknown accounts and wrong passwords answer in the
	// same time class (TM-TB11-T1). Zero disables it.
	Floor time.Duration
	// Now is the clock; nil means the database clock for sessions and time.Now for the factor store.
	Now func() time.Time
}

// Limits of the enrolment page.
const (
	// EnrolSessionTTL is the life of a pending enrolment: 10 minutes (spec 6.1, a deliberate deviation from
	// the 5 of a pending sign-in, so a user can install an authenticator app).
	EnrolSessionTTL = 10 * time.Minute
	// CoolingOff is the time after the notice was accepted before the factor can verify a caller (§5).
	CoolingOff = 24 * time.Hour
	// NoticeRetry and NoticeGiveUp are the delivery schedule of 6.5.
	NoticeRetry  = 15 * time.Minute
	NoticeGiveUp = 24 * time.Hour
	// noticeLease keeps two nodes from sending the same notice.
	noticeLease     = 5 * time.Minute
	maxPassword     = 256
	maxUsername     = 256
	enrolFactorName = "activeDIQ"
)

// Errors. None says why; the audit event does.
var (
	// ErrEnrolRefused: authentication failed, for whatever reason.
	ErrEnrolRefused = errors.New("authn: enrolment sign-in refused")
	// ErrEnrolSession: the handle is not live (unknown, expired, consumed or out of confirmations).
	ErrEnrolSession = errors.New("authn: no valid pending enrolment")
	// ErrEnrolHelpDesk: the user must contact the help desk (an active factor without its code, or no held
	// contact data). No seed was created.
	ErrEnrolHelpDesk = errors.New("authn: contact your help desk")
	// ErrEnrolCodeRejected: the confirmation code did not work.
	ErrEnrolCodeRejected = errors.New("authn: enrolment code rejected")
	// ErrNoDirectoryUser is what DirectoryUsers.Resolve returns for a name that is not an enabled AD user
	// able to authenticate.
	ErrNoDirectoryUser = errors.New("authn: no such directory user")
)

// DirectoryUser is the AD user a sign-in name resolves to. Domain and Account only key the attempt counter;
// the identity is Ref.
type DirectoryUser struct {
	Ref     DirectoryRef
	Domain  string
	Account string
}

// DirectoryUsers resolves the typed sign-in name on an ad_forest connection of the tenant. A user who is
// disabled, expired, must change the password at next logon, or is not in scope is ErrNoDirectoryUser.
type DirectoryUsers interface {
	Resolve(ctx context.Context, t tenant.ID, username string) (DirectoryUser, error)
}

// KerberosAcceptor is the connector's SPNEGO acceptor (ADR-0002 rule 3). Accept validates the AP-REQ of an
// HTTP Negotiate token and returns the authenticated AD user. A token that offers only NTLM, or anything
// that does not validate, is ErrADProofRefused.
type KerberosAcceptor interface {
	Accept(ctx context.Context, t tenant.ID, token []byte) (DirectoryUser, error)
}

// Contact is a destination already held in AD or HR. It is read live and never typed on the page.
type Contact struct {
	Kind    string // "email" or "sms"
	Address string
}

// HeldContacts lists the user's held destinations, leaving out any changed in the last 24 hours (rule 4.13).
type HeldContacts interface {
	Held(ctx context.Context, t tenant.ID, ref DirectoryRef) ([]Contact, error)
}

// NoticeSender hands a fixed-text message to the mail or SMS transport. An error is a rejection.
type NoticeSender interface {
	Send(ctx context.Context, t tenant.ID, to Contact, subject, body string) error
}

// AttemptKeys gives the server key that keys the attempt counter's HMAC.
type AttemptKeys interface {
	Key(ctx context.Context, t tenant.ID) ([]byte, error)
}

// Audit kinds of the enrolment page, verbatim from spec 6.6.
const (
	KindEnrolStarted   audit.Kind = "authenticator.enrol.started"
	KindEnrolConfirmed audit.Kind = "authenticator.enrol.confirmed"
	KindEnrolFailed    audit.Kind = "authenticator.enrol.failed"
	KindEnrolRefused   audit.Kind = "authenticator.enrol.refused"
	KindEnrolReplaced  audit.Kind = "authenticator.enrol.replaced"
	KindNoticeSent     audit.Kind = "authenticator.notice.sent"
	KindNoticeFailed   audit.Kind = "authenticator.notice.failed"
	KindNoticeAbandon  audit.Kind = "authenticator.notice.abandoned"
)

// Reasons of an enrolment refusal or failure, for the audit trail only.
const (
	EnrolPasswordRefused   = "password_refused"
	EnrolThrottled         = "throttled"
	EnrolKerberosRefused   = "kerberos_refused"
	EnrolNoContact         = "no_contact_data"
	EnrolFactorRequired    = "existing_factor_required"
	EnrolFactorNotProved   = "existing_factor_not_proved"
	EnrolCodeRejected      = "code_rejected"
	EnrolAttemptsExhausted = "attempts_exhausted"
)

// EnrolHandle is the secret behind the AN-5 cookie: 256 random bits, distinct from a session or pending
// sign-in token (its own hash prefix), so none of them can be presented as another. String redacts.
type EnrolHandle struct{ tok Token }

// Reveal returns the handle text for the one response that sets the cookie.
func (h EnrolHandle) Reveal() string { return h.tok.Reveal() }

// String redacts.
func (EnrolHandle) String() string { return "authn.EnrolHandle(redacted)" }

// GoString redacts for %#v.
func (EnrolHandle) GoString() string { return "authn.EnrolHandle(redacted)" }

func (h EnrolHandle) hash() []byte {
	sum := sha256.Sum256([]byte("activediq enrol v1\x00" + h.tok.text))
	return sum[:]
}

// ParseEnrolHandle reads handle text from a client; shape only.
func ParseEnrolHandle(s string) (EnrolHandle, error) {
	t, err := ParseToken(s)
	if err != nil {
		return EnrolHandle{}, ErrEnrolSession
	}
	return EnrolHandle{tok: t}, nil
}

func (s *SelfEnrolment) ready() error {
	if s == nil || s.DB == nil || s.Factors == nil || s.Audit == nil || s.Users == nil || s.AD == nil ||
		s.Kerberos == nil || s.Attempts == nil || s.Contacts == nil || s.Sender == nil || s.MAC == nil {
		return errors.New("authn: SelfEnrolment is not fully configured")
	}
	return nil
}

// Validate reports a missing dependency. The page is not offered until it returns nil (no AD proof, no
// mail transport: no enrolment).
func (s *SelfEnrolment) Validate() error { return s.ready() }

func (s *SelfEnrolment) now(ctx context.Context, tx store.Tx) (time.Time, error) {
	if s.Now != nil {
		return s.Now().UTC(), nil
	}
	var t time.Time
	if err := tx.QueryRow(ctx, sqlClock).Scan(&t); err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func directoryChain(ref DirectoryRef) authority.Chain {
	return authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(ref.ObjectGUID), Kind: authority.DirectoryUser}}
}

// event builds an enrolment event. Detail keys stay in increasing order.
func (s *SelfEnrolment) event(id string, kind audit.Kind, at time.Time, ref DirectoryRef, outcome audit.Outcome, reason string, from netip.Addr, extra ...audit.Detail) audit.Event {
	d := append([]audit.Detail(nil), extra...)
	d = append(d, audit.Detail{Key: "method", Value: methodTOTP})
	if from.IsValid() {
		d = append(d, audit.Detail{Key: "source_ip", Value: from.Unmap().String()})
	}
	sortDetails(d)
	return audit.Event{
		ID: id, Kind: kind, At: at, Actor: directoryChain(ref),
		Target:    authority.TargetRef{Connection: ref.ConnectionID, GUID: ref.ObjectGUID, Class: "user"},
		Component: "authn", Outcome: outcome, Reason: reason, Details: d,
	}
}

func sortDetails(d []audit.Detail) {
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && d[j].Key < d[j-1].Key; j-- {
			d[j], d[j-1] = d[j-1], d[j]
		}
	}
}

func (s *SelfEnrolment) emit(ctx context.Context, tx store.Tx, kind audit.Kind, stable string, ref DirectoryRef, outcome audit.Outcome, reason string, from netip.Addr, extra ...audit.Detail) error {
	now, err := s.now(ctx, tx)
	if err != nil {
		return err
	}
	id := stable
	if id == "" { // a refusal has no stable object: one event per occurrence
		if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&id); err != nil {
			return err
		}
	}
	if err := s.Audit.Append(ctx, tx, s.event(string(kind)+"."+id, kind, now, ref, outcome, reason, from, extra...)); err != nil {
		return fmt.Errorf("authn: audit %s: %w", kind, err)
	}
	return nil
}

// refuseAuth records a failed authentication against the user it named (when it resolved to one) and
// answers the one generic error. Unknown names are not audited: there is no target to name, and an
// anonymous caller would otherwise write unbounded rows (the per-IP limits of TM-TB1-T9 sit in front).
func (s *SelfEnrolment) refuseAuth(ctx context.Context, t tenant.ID, u *DirectoryUser, reason string, from netip.Addr) error {
	if u != nil {
		if err := s.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
			return s.emit(ctx, tx, KindEnrolRefused, "", u.Ref, audit.Denied, reason, from, audit.Detail{Key: "stage", Value: "authentication"})
		}); err != nil {
			return fmt.Errorf("authn: record enrolment refusal: %w", err)
		}
	}
	return ErrEnrolRefused
}

func (s *SelfEnrolment) attemptKey(ctx context.Context, t tenant.ID, u DirectoryUser) ([]byte, error) {
	k, err := s.MAC.Key(ctx, t)
	if err != nil || len(k) == 0 {
		return nil, fmt.Errorf("authn: attempt key: %w", errors.Join(err, ErrADAttemptsRefused))
	}
	m := hmac.New(sha256.New, k)
	for _, part := range []string{t.String(), strings.ToLower(u.Domain), strings.ToLower(u.Account)} {
		m.Write([]byte(part))
		m.Write([]byte{0})
	}
	return m.Sum(nil), nil
}

// Authenticate proves the visitor knows the AD password of username and opens a pending enrolment for that
// user. The password goes to the connector's VerifyUser behind the shared per-account counter, so the
// attempts stay below the domain lockout threshold; it is zeroed here and never stored or logged. Every
// failure is ErrEnrolRefused, after at least Floor.
func (s *SelfEnrolment) Authenticate(ctx context.Context, t tenant.ID, username string, password []byte, from netip.Addr) (EnrolHandle, error) {
	defer zero(password)
	start := time.Now()
	h, err := s.authenticate(ctx, t, username, password, from)
	s.floor(ctx, start)
	return h, err
}

func (s *SelfEnrolment) floor(ctx context.Context, start time.Time) {
	if s.Floor <= 0 {
		return
	}
	if rest := s.Floor - time.Since(start); rest > 0 {
		select {
		case <-time.After(rest):
		case <-ctx.Done():
		}
	}
}

func (s *SelfEnrolment) authenticate(ctx context.Context, t tenant.ID, username string, password []byte, from netip.Addr) (EnrolHandle, error) {
	if err := s.ready(); err != nil {
		return EnrolHandle{}, err
	}
	if t.IsZero() || username == "" || len(username) > maxUsername || len(password) == 0 || len(password) > maxPassword {
		return EnrolHandle{}, ErrEnrolRefused
	}
	u, err := s.Users.Resolve(ctx, t, username)
	if errors.Is(err, ErrNoDirectoryUser) {
		return EnrolHandle{}, ErrEnrolRefused
	}
	if err != nil {
		return EnrolHandle{}, fmt.Errorf("authn: resolve sign-in name: %w", err)
	}
	if !validDirectoryRef(u.Ref) || u.Domain == "" || u.Account == "" {
		return EnrolHandle{}, fmt.Errorf("authn: directory resolved an invalid user")
	}
	key, err := s.attemptKey(ctx, t, u)
	if err != nil {
		return EnrolHandle{}, err
	}
	if err := s.Attempts.Take(ctx, t, u.Domain, key); err != nil {
		return EnrolHandle{}, s.refuseAuth(ctx, t, &u, EnrolThrottled, from)
	}
	switch err := s.AD.VerifyUser(ctx, t, u.Ref, password); {
	case err == nil:
	case errors.Is(err, ErrADProofRefused):
		return EnrolHandle{}, s.refuseAuth(ctx, t, &u, EnrolPasswordRefused, from)
	default:
		return EnrolHandle{}, fmt.Errorf("authn: AD proof: %w", err)
	}
	if err := s.Attempts.Succeeded(ctx, t, key); err != nil {
		return EnrolHandle{}, err
	}
	return s.begin(ctx, t, u.Ref, "password", from)
}

// AuthenticateKerberos is the same step for a domain-joined browser: the connector's acceptor validates the
// AP-REQ of the Negotiate token (Kerberos only; NTLM-only is refused) and names the user.
func (s *SelfEnrolment) AuthenticateKerberos(ctx context.Context, t tenant.ID, token []byte, from netip.Addr) (EnrolHandle, error) {
	if err := s.ready(); err != nil {
		return EnrolHandle{}, err
	}
	if t.IsZero() || len(token) == 0 {
		return EnrolHandle{}, ErrEnrolRefused
	}
	u, err := s.Kerberos.Accept(ctx, t, token)
	switch {
	case errors.Is(err, ErrADProofRefused), errors.Is(err, ErrNoDirectoryUser):
		return EnrolHandle{}, ErrEnrolRefused
	case err != nil:
		return EnrolHandle{}, fmt.Errorf("authn: Kerberos accept: %w", err)
	case !validDirectoryRef(u.Ref):
		return EnrolHandle{}, fmt.Errorf("authn: directory accepted an invalid user")
	}
	return s.begin(ctx, t, u.Ref, "kerberos", from)
}

func validDirectoryRef(r DirectoryRef) bool {
	return validAccount(r.ConnectionID) && validAccount(r.ObjectGUID)
}

// begin records the pending enrolment of a user who passed authentication. Sessions that ended long ago are
// pruned here, a few at a time.
func (s *SelfEnrolment) begin(ctx context.Context, t tenant.ID, ref DirectoryRef, proof string, from netip.Addr) (EnrolHandle, error) {
	tok, err := newToken(t)
	if err != nil {
		return EnrolHandle{}, err
	}
	h := EnrolHandle{tok: tok}
	var ip *netip.Addr
	if from.IsValid() {
		a := from.Unmap()
		ip = &a
	}
	err = s.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := s.now(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM public.authn_enrolment_sessions WHERE tenant_id = $1::uuid AND expires_at < $2`,
			t.String(), now.Add(-24*time.Hour)); err != nil {
			return err
		}
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO public.authn_enrolment_sessions
  (tenant_id, handle_hash, connection_id, object_guid, proof, client_ip, created_at, expires_at)
VALUES ($1::uuid, $2, $3::uuid, $4::uuid, $5, $6, $7, $8) RETURNING id::text`,
			t.String(), h.hash(), ref.ConnectionID, ref.ObjectGUID, proof, ip, now, now.Add(EnrolSessionTTL)).Scan(&id); err != nil {
			return err
		}
		return s.emit(ctx, tx, KindEnrolStarted, id, ref, audit.Success, proof, from, audit.Detail{Key: "proof", Value: proof})
	})
	if err != nil {
		return EnrolHandle{}, fmt.Errorf("authn: begin enrolment: %w", err)
	}
	return h, nil
}
