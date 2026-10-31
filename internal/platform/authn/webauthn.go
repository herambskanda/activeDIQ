package authn

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

func init() {
	_ = tablekind.Declare(tablekind.Table{Name: "public.authn_webauthn_credentials", Entity: "DM-37", Kind: tablekind.Tenant})
	_ = tablekind.Declare(tablekind.Table{Name: "public.authn_webauthn_challenges", Entity: "DM-37", Kind: tablekind.Tenant})
}

// WebAuthn as the AN-10 second factor (threat model §7.2, §7.6 rule 1). The ceremony itself (CBOR, COSE,
// signature, origin, rpIdHash, flags) is the vetted library's (RT-15, go-webauthn); this file owns what the
// library leaves to the relying party: which challenge is live, that it is used once, the signature
// counter, and turning a pass into a session.
//
// Replay: a challenge is bound to one pending sign-in and is consumed by the FIRST assertion that names
// that sign-in, in its own committed transaction before the assertion is evaluated. A captured assertion
// therefore verifies at most once, and never against a later challenge (its signed challenge differs). The
// signature counter is a second line for authenticators that count.

// Reasons recorded for WebAuthn refusals (KindSecondFactorRefused).
const (
	RefusedNoChallenge       = "no_challenge"       // none issued, expired, or already consumed (a replay lands here)
	RefusedAssertionInvalid  = "assertion_invalid"  // the library refused the assertion
	RefusedCounterRegression = "counter_regression" // the signature counter did not advance: a clone or a replay
	RefusedNoWebAuthn        = "no_webauthn_credential"

	methodWebAuthn = "webauthn"
)

// WebAuthnConfig is the relying party. RPID is the registrable domain the console is served from;
// Origins are the exact https origins that may sign in (no wildcards).
type WebAuthnConfig struct {
	RPID          string
	RPDisplayName string
	Origins       []string
}

// WebAuthnCredential is a registered authenticator as AN-10 needs it. Public data only.
type WebAuthnCredential struct {
	CredentialID   []byte
	PublicKey      []byte // COSE_Key
	UserHandle     []byte // 16..64 opaque bytes, the same for every credential of an account
	BackupEligible bool
	AAGUID         []byte // 16 bytes or nil
	SignCount      uint32
	Label          string
}

// WebAuthnOptions is what the browser needs for navigator.credentials.get.
type WebAuthnOptions struct {
	Challenge        string // base64url
	RPID             string
	TimeoutMS        int64
	UserVerification string
	AllowCredentials []string // base64url credential IDs
}

// WebAuthnAssertion is the authenticator's answer, every field base64url without padding.
type WebAuthnAssertion struct {
	CredentialID, AuthenticatorData, ClientDataJSON, Signature, UserHandle string
}

// WebAuthnFactor is AN-10 for WebAuthn.
type WebAuthnFactor struct {
	DB       *store.DB
	Pending  *PendingStore
	Sessions *Store
	// Audit records refused attempts; it must be bound to DB (audit.NewChainer).
	Audit audit.Sink

	wa *webauthn.WebAuthn
	sf *SecondFactor // refusal auditing is shared with TOTP
}

// NewWebAuthnFactor validates the relying party and returns the factor.
func NewWebAuthnFactor(cfg WebAuthnConfig, db *store.DB, pending *PendingStore, sessions *Store, sink audit.Sink) (*WebAuthnFactor, error) {
	if db == nil || pending == nil || sessions == nil || sink == nil {
		return nil, errors.New("authn: WebAuthnFactor is not fully configured")
	}
	if len(cfg.Origins) == 0 {
		return nil, errors.New("authn: WebAuthn needs at least one origin")
	}
	wa, err := webauthn.New(&webauthn.Config{RPID: cfg.RPID, RPDisplayName: cfg.RPDisplayName, RPOrigins: cfg.Origins,
		Timeouts: webauthn.TimeoutsConfig{Login: webauthn.TimeoutConfig{Enforce: true, Timeout: PendingSignInTTL}}})
	if err != nil {
		return nil, fmt.Errorf("authn: WebAuthn relying party: %w", err)
	}
	return &WebAuthnFactor{DB: db, Pending: pending, Sessions: sessions, Audit: sink, wa: wa,
		sf: &SecondFactor{DB: db, Pending: pending, Sessions: sessions, Audit: sink}}, nil
}

// waUser adapts an account's credentials to the library.
type waUser struct {
	handle []byte
	creds  []webauthn.Credential
}

func (u waUser) WebAuthnID() []byte                         { return u.handle }
func (u waUser) WebAuthnName() string                       { return "console account" }
func (u waUser) WebAuthnDisplayName() string                { return "console account" }
func (u waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// AddCredential registers an already-verified credential for an active account. The registration
// ceremony (a later ticket) is the only intended caller; it exists so AN-10 has credentials to check and
// so tests do not write SQL.
func (f *WebAuthnFactor) AddCredential(ctx context.Context, t tenant.ID, account string, c WebAuthnCredential) (string, error) {
	if t.IsZero() || !validAccount(account) || len(c.CredentialID) == 0 || len(c.PublicKey) == 0 || len(c.UserHandle) == 0 {
		return "", ErrInvalid
	}
	var id string
	err := f.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		var err error
		id, err = insertCredential(ctx, tx, t, account, purposeSecondFactor, c)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("authn: add webauthn credential: %w", err)
	}
	return id, nil
}

// insertCredential stores a verified credential of the purpose for the account.
func insertCredential(ctx context.Context, tx store.Tx, t tenant.ID, account, purpose string, c WebAuthnCredential) (string, error) {
	if purpose == purposeSecondFactor {
		// Activating a second-factor credential changes what AN-10 accepts (the passkey lock). Take the
		// account row exclusively first: VerifyTOTP holds it FOR SHARE while it reads the credentials
		// and mints the session, so the two cannot interleave (FP-T8).
		var one int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM public.authn_accounts WHERE tenant_id = $1::uuid AND id = $2::uuid FOR UPDATE`, t.String(), account).Scan(&one); err != nil && !store.IsNoRows(err) {
			return "", err
		}
	}
	var id string
	err := tx.QueryRow(ctx, `INSERT INTO public.authn_webauthn_credentials
  (tenant_id, account_id, credential_id, public_key, user_handle, backup_eligible, aaguid, sign_count, label, purpose)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id::text`,
		t.String(), account, c.CredentialID, c.PublicKey, c.UserHandle, c.BackupEligible, c.AAGUID, int64(c.SignCount), c.Label, purpose).Scan(&id)
	return id, err
}

type storedCred struct {
	id string
	WebAuthnCredential
}

// Credential purposes (migration 0048). AN-10 reads only second_factor; the authority factor (TM-D19) only authority.
const (
	purposeSecondFactor = "second_factor"
	purposeAuthority    = "authority"
)

// credentials lists the active credentials of the purpose of an active account; nil when it has none or
// is not active.
func credentials(ctx context.Context, tx store.Tx, t tenant.ID, account, purpose string) ([]storedCred, error) {
	rows, err := tx.Query(ctx, `SELECT c.id::text, c.credential_id, c.public_key, c.user_handle, c.backup_eligible, c.aaguid, c.sign_count
FROM public.authn_webauthn_credentials c
JOIN public.authn_accounts a ON a.tenant_id = c.tenant_id AND a.id = c.account_id
WHERE c.tenant_id = $1::uuid AND c.account_id = $2::uuid AND c.state = 'active' AND a.state = 'active' AND c.purpose = $3
ORDER BY c.created_at, c.id`, t.String(), account, purpose)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storedCred
	for rows.Next() {
		var c storedCred
		var sc int64
		if err := rows.Scan(&c.id, &c.CredentialID, &c.PublicKey, &c.UserHandle, &c.BackupEligible, &c.AAGUID, &sc); err != nil {
			return nil, err
		}
		c.SignCount = uint32(sc)
		out = append(out, c)
	}
	return out, rows.Err()
}

func toUser(cs []storedCred) waUser {
	u := waUser{handle: cs[0].UserHandle}
	for _, c := range cs {
		u.creds = append(u.creds, webauthn.Credential{ID: c.CredentialID, PublicKey: c.PublicKey,
			Flags:         webauthn.CredentialFlags{BackupEligible: c.BackupEligible},
			Authenticator: webauthn.Authenticator{AAGUID: c.AAGUID, SignCount: c.SignCount}})
	}
	return u
}

// peek reads the live pending sign-in h names without charging an attempt: AN-10 challenge issuance is
// rate-limited by the auth class and writes one row per pending sign-in, so it cannot be used to guess.
func (p *PendingStore) peek(ctx context.Context, h PendingHandle) (pendingRef, error) {
	t, err := h.tok.Tenant()
	if err != nil {
		return pendingRef{}, ErrPendingInvalid
	}
	var ref pendingRef
	err = p.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := p.now(ctx, tx)
		if err != nil {
			return err
		}
		var attempts int
		err = tx.QueryRow(ctx, `SELECT id::text, account_id::text, first_factor, attempts, account_epoch
FROM public.authn_pending_signins
WHERE tenant_id = $1::uuid AND handle_hash = $2 AND state = 'active' AND expires_at > $3`, t.String(), h.hash(), now).
			Scan(&ref.ID, &ref.Account, &ref.First, &attempts, &ref.Epoch.n)
		if store.IsNoRows(err) || (err == nil && attempts >= MaxSignInAttempts) {
			return ErrPendingInvalid
		}
		ref.Tenant = t
		return err
	})
	return ref, err
}

// Begin issues the challenge for the pending sign-in h names, replacing any earlier one. It answers
// ErrPendingInvalid when there is no live pending sign-in and ErrSecondFactorRefused when the account has
// no credential.
func (f *WebAuthnFactor) Begin(ctx context.Context, h PendingHandle) (WebAuthnOptions, error) {
	ref, err := f.Pending.peek(ctx, h)
	if err != nil {
		if errors.Is(err, ErrPendingInvalid) {
			return WebAuthnOptions{}, err
		}
		return WebAuthnOptions{}, fmt.Errorf("authn: webauthn begin: %w", err)
	}
	var out WebAuthnOptions
	err = f.DB.WithTenant(ctx, ref.Tenant, func(ctx context.Context, tx store.Tx) error {
		cs, err := credentials(ctx, tx, ref.Tenant, ref.Account, purposeSecondFactor)
		if err != nil {
			return err
		}
		if len(cs) == 0 {
			return ErrSecondFactorRefused
		}
		assertion, session, err := f.wa.BeginLogin(toUser(cs), webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			return err
		}
		challenge, err := base64.RawURLEncoding.DecodeString(session.Challenge)
		if err != nil {
			return err
		}
		now, err := f.Pending.now(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.authn_webauthn_challenges (tenant_id, pending_id, challenge, allowed_credential_ids, created_at, expires_at)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)
ON CONFLICT (tenant_id, pending_id) DO UPDATE SET challenge = EXCLUDED.challenge, allowed_credential_ids = EXCLUDED.allowed_credential_ids,
  created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at, consumed_at = NULL`,
			ref.Tenant.String(), ref.ID, challenge, session.AllowedCredentialIDs, now, now.Add(PendingSignInTTL)); err != nil {
			return err
		}
		out = WebAuthnOptions{Challenge: session.Challenge, RPID: f.wa.Config.RPID, TimeoutMS: int64(PendingSignInTTL / time.Millisecond),
			UserVerification: string(protocol.VerificationRequired)}
		for _, id := range session.AllowedCredentialIDs {
			out.AllowCredentials = append(out.AllowCredentials, base64.RawURLEncoding.EncodeToString(id))
		}
		_ = assertion
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrSecondFactorRefused) {
			return WebAuthnOptions{}, err
		}
		return WebAuthnOptions{}, fmt.Errorf("authn: webauthn begin: %w", err)
	}
	return out, nil
}

// takeChallenge consumes the live challenge of the pending sign-in in its own committed transaction and
// returns it. ok is false when there is none (never issued, expired, or already consumed).
func (f *WebAuthnFactor) takeChallenge(ctx context.Context, ref pendingRef) (challenge []byte, allowed [][]byte, ok bool, err error) {
	err = f.DB.WithTenant(ctx, ref.Tenant, func(ctx context.Context, tx store.Tx) error {
		now, err := f.Pending.now(ctx, tx)
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `UPDATE public.authn_webauthn_challenges SET consumed_at = $3
WHERE tenant_id = $1::uuid AND pending_id = $2::uuid AND consumed_at IS NULL AND expires_at > $3
RETURNING challenge, allowed_credential_ids`, ref.Tenant.String(), ref.ID, now).Scan(&challenge, &allowed)
		if store.IsNoRows(err) {
			return nil
		}
		ok = err == nil
		return err
	})
	return
}

// Verify checks a WebAuthn assertion for the pending sign-in h names. One attempt is charged and the
// challenge is consumed before the assertion is looked at. On success, in one transaction, the signature
// counter advances, the pending sign-in is consumed and a session with a new ID is created (methods: the
// first factor and "webauthn"). Every refusal is ErrPendingInvalid or ErrSecondFactorRefused.
func (f *WebAuthnFactor) Verify(ctx context.Context, h PendingHandle, in WebAuthnAssertion, from netip.Addr) (CreateResult, error) {
	ref, err := f.Pending.charge(ctx, h, func(ctx context.Context, tx store.Tx, ref pendingRef, now time.Time, reason string) error {
		return f.sf.refuse(ctx, tx, ref, now, reason, from)
	})
	if err != nil {
		return CreateResult{}, err
	}
	challenge, allowed, ok, err := f.takeChallenge(ctx, ref)
	if err != nil {
		return CreateResult{}, fmt.Errorf("authn: webauthn challenge: %w", err)
	}
	if !ok {
		return CreateResult{}, f.deny(ctx, ref, RefusedNoChallenge, from)
	}
	parsed, err := parseAssertion(in)
	if err != nil {
		return CreateResult{}, f.deny(ctx, ref, RefusedAssertionInvalid, from)
	}
	var res CreateResult
	err = f.DB.WithTenant(ctx, ref.Tenant, func(ctx context.Context, tx store.Tx) error {
		cs, err := credentials(ctx, tx, ref.Tenant, ref.Account, purposeSecondFactor)
		if err != nil {
			return err
		}
		if len(cs) == 0 {
			reason := RefusedAccountDisabled
			if active, err := accountActive(ctx, tx, ref.Tenant, ref.Account); err != nil {
				return err
			} else if active {
				reason = RefusedNoWebAuthn
			}
			return &refusal{reason: reason}
		}
		user := toUser(cs)
		session := webauthn.SessionData{Challenge: base64.RawURLEncoding.EncodeToString(challenge), RelyingPartyID: f.wa.Config.RPID,
			UserID: user.handle, AllowedCredentialIDs: allowed, UserVerification: protocol.VerificationRequired}
		cred, err := f.wa.ValidateLogin(user, session, parsed)
		if err != nil {
			return &refusal{reason: RefusedAssertionInvalid}
		}
		now, err := f.Pending.now(ctx, tx)
		if err != nil {
			return err
		}
		if reason, err := useCredential(ctx, tx, ref.Tenant, cs, cred.ID, parsed, now); err != nil {
			return err
		} else if reason != "" {
			return &refusal{reason: reason}
		}
		won, err := f.Pending.consume(ctx, tx, ref)
		if err != nil {
			return err
		}
		if !won {
			return ErrPendingInvalid
		}
		res, err = f.Sessions.CreateTx(ctx, tx, CreateInput{Tenant: ref.Tenant, Account: ref.Account,
			Methods: []string{string(ref.First), methodWebAuthn}, MFAAt: &now, ClientIP: ref.ClientIP, Epoch: ref.Epoch})
		return err
	})
	if err != nil {
		var r *refusal
		switch {
		case errors.As(err, &r):
			return CreateResult{}, f.deny(ctx, ref, r.reason, from)
		case errors.Is(err, ErrPendingInvalid):
			return CreateResult{}, err
		case errors.Is(err, ErrCredentialsChanged):
			if aerr := f.sf.refuseOwn(ctx, ref, RefusedCredentialsChanged, from); aerr != nil {
				return CreateResult{}, aerr
			}
			return CreateResult{}, ErrPendingInvalid
		}
		return CreateResult{}, fmt.Errorf("authn: webauthn second factor: %w", err)
	}
	return res, nil
}

// useCredential finds the credential an assertion validated against among cs and advances its signature
// counter (WebAuthn §6.1.1). Authenticators that do not count report 0 throughout; one that counts must
// advance. A counter that stands still or goes back is a clone or a replay. It returns the refusal reason
// ("" on success); an error is infrastructure.
func useCredential(ctx context.Context, tx store.Tx, t tenant.ID, cs []storedCred, credID []byte, parsed *protocol.ParsedCredentialAssertionData, now time.Time) (string, error) {
	var matched *storedCred
	for i := range cs {
		if string(cs[i].CredentialID) == string(credID) {
			matched = &cs[i]
		}
	}
	if matched == nil {
		return RefusedAssertionInvalid, nil
	}
	newCount := parsed.Response.AuthenticatorData.Counter
	if (newCount != 0 || matched.SignCount != 0) && newCount <= matched.SignCount {
		return RefusedCounterRegression, nil
	}
	tag, err := tx.Exec(ctx, `UPDATE public.authn_webauthn_credentials SET sign_count = $4, last_used = $5
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state = 'active' AND sign_count = $3`,
		t.String(), matched.id, int64(matched.SignCount), int64(newCount), now)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() != 1 {
		return RefusedCounterRegression, nil // a concurrent use of the same credential won
	}
	return "", nil
}

// deny audits a refusal in its own transaction and returns ErrSecondFactorRefused (or the audit failure).
func (f *WebAuthnFactor) deny(ctx context.Context, ref pendingRef, reason string, from netip.Addr) error {
	if err := f.sf.refuseOwn(ctx, ref, reason, from); err != nil {
		return err
	}
	return ErrSecondFactorRefused
}

// parseAssertion hands the library the PublicKeyCredential JSON its parser expects, built from the
// contract's four base64url fields. Malformed input is an error and nothing more.
func parseAssertion(in WebAuthnAssertion) (*protocol.ParsedCredentialAssertionData, error) {
	resp := map[string]string{"clientDataJSON": in.ClientDataJSON, "authenticatorData": in.AuthenticatorData, "signature": in.Signature}
	if in.UserHandle != "" {
		resp["userHandle"] = in.UserHandle
	}
	raw, err := json.Marshal(map[string]any{"id": in.CredentialID, "rawId": in.CredentialID, "type": "public-key", "response": resp})
	if err != nil {
		return nil, err
	}
	return protocol.ParseCredentialRequestResponseBytes(raw)
}
