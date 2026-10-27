package connections

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// TakeoverAttestPermission starts a hybrid-trust attestation (TM-D17 rule 2, DM-10.I7(a)). It must be
// held over the Entra connection's entra_tenant scope, with a fresh step-up (TM §7.4).
const TakeoverAttestPermission authz.Permission = "connections.takeover.attest"

// AttestScope is the one delegated permission the flow requests. No offline_access, no openid, no
// other scope: the token is for one read and is discarded (TM-D17 rule 2). The Graph docs name Global
// Administrator as the only supported role for this call.
// https://learn.microsoft.com/en-us/graph/api/onpremisesdirectorysynchronization-get?view=graph-rest-1.0
const AttestScope = "OnPremDirectorySynchronization.Read.All"

// Audit kinds of the flow.
const (
	AuditAttestStarted  = "connection.takeover.attest_started"
	AuditAttestRecorded = "connection.takeover.attested"
	AuditAttestFailed   = "connection.takeover.attest_failed"
	AuditMaxAgeSet      = "connection.takeover.max_age_set"
)

// Machine reasons recorded with a refusal or failure. None carries a value from the IdP or Graph.
const (
	ReasonNotPermitted   = "not_permitted"
	ReasonStepUpRequired = "step_up_required"
	ReasonBadConnection  = "connection_not_attestable"
	ReasonAttemptInvalid = "attempt_invalid"
	ReasonTokenExchange  = "token_exchange_failed"
	ReasonTenantMismatch = "tid_mismatch"
	ReasonScopeMismatch  = "scope_mismatch"
	ReasonBadIdentity    = "attester_identity_invalid"
	ReasonGraphRead      = "graph_read_failed"
	ReasonRecordFailed   = "record_failed"
)

// Errors a caller can match. Detail never leaks a directory value.
var (
	ErrNotPermitted    = errors.New("connections: attestation not permitted")
	ErrStepUpRequired  = errors.New("connections: attestation needs a fresh step-up")
	ErrNotAttestable   = errors.New("connections: connection cannot be attested")
	ErrTenantMismatch  = errors.New("connections: token tenant is not the connection's tenant")
	ErrScopeMismatch   = errors.New("connections: token scope is not exactly the attestation scope")
	ErrAttesterInvalid = errors.New("connections: attester identity is not usable")
)

// Bearer is a delegated access token held only for the duration of the callback. It cannot be
// printed, logged or marshalled, and Zero overwrites the bytes. It is never stored.
type Bearer struct{ b []byte }

// NewBearer wraps token bytes (the IdP adapter's job); the slice is owned by the Bearer afterwards.
func NewBearer(b []byte) Bearer { return Bearer{b: b} }

// Use calls fn with the token bytes. fn must not retain them.
func (t Bearer) Use(fn func([]byte) error) error { return fn(t.b) }

// Zero overwrites the token.
func (t Bearer) Zero() {
	for i := range t.b {
		t.b[i] = 0
	}
}

// String implements fmt.Stringer; it never reveals the token.
func (Bearer) String() string { return "[redacted token]" }

// GoString implements fmt.GoStringer.
func (Bearer) GoString() string { return "[redacted token]" }

// MarshalJSON refuses to serialise the token.
func (Bearer) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

// MarshalText refuses to serialise the token.
func (Bearer) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }

// Grant is what the IdP adapter returns after the code exchange, from tokens it has validated
// (signature, issuer, audience, expiry). Only the claims the flow needs and the bearer for the one read.
type Grant struct {
	TenantID string   // tid claim
	ObjectID string   // oid claim: the signed-in Global Administrator
	Scopes   []string // scopes the IdP granted
	Token    Bearer
}

// ExchangeRequest is the authorization-code redemption.
type ExchangeRequest struct {
	TenantID     string // the connection's tenant; the token endpoint is tenant-specific
	Code         string
	CodeVerifier string
	RedirectURI  string
	Scopes       []string
}

// IdP redeems an authorization code. The adapter must not request or keep a refresh token or ID token
// beyond validating the claims it returns.
type IdP interface {
	Exchange(ctx context.Context, req ExchangeRequest) (Grant, error)
}

// SyncFeatures are the two values DM-20.I4(f) needs.
type SyncFeatures struct {
	BlockCloudObjectTakeoverThroughHardMatch bool
	BlockSoftMatch                           bool
}

// Graph makes the one delegated read, GET /directory/onPremisesSynchronization.
type Graph interface {
	ReadSyncFeatures(ctx context.Context, token Bearer) (SyncFeatures, error)
}

// Authorizer decides a permission over a target for the initiator chain.
type Authorizer interface {
	Authorize(ctx context.Context, chain authority.Chain, perm authz.Permission, t authority.TargetRef) error
}

// StepUp reports whether the session passed MFA inside the tenant's window (TM §7.4). authn.StepUp
// implements the same question for apihost.
type StepUp interface {
	Fresh(ctx context.Context, tid tenant.ID, sessionID string) (bool, error)
}

// TxRunner opens a tenant-scoped transaction. *store.DB implements it.
type TxRunner interface {
	WithTenant(ctx context.Context, id tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error
}

// AttestConfig wires an Attester. Every field except Now, Rand and AttemptTTL is required.
type AttestConfig struct {
	DB          TxRunner
	Audit       audit.Sink
	Authz       Authorizer
	StepUp      StepUp
	IdP         IdP
	Graph       Graph
	ClientID    string // the app registration that carries the delegated permission
	RedirectURI string
	// Authority is the login base, for example https://login.microsoftonline.com. The tenant ID is appended.
	Authority  string
	Component  string
	NewID      func() string
	Now        func() time.Time
	Rand       io.Reader     // nil: crypto/rand
	AttemptTTL time.Duration // zero: 10 minutes
}

// Attester runs the TM-D17 attestation flow. It owns no table (F1): it writes through
// directory/connection.
type Attester struct {
	cfg   AttestConfig
	store connection.Store
}

// NewAttester validates the wiring.
func NewAttester(cfg AttestConfig) (*Attester, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Authz == nil || cfg.StepUp == nil || cfg.IdP == nil || cfg.Graph == nil ||
		cfg.ClientID == "" || cfg.RedirectURI == "" || cfg.Authority == "" || cfg.Component == "" || cfg.NewID == nil {
		return nil, errors.New("connections: attester is not fully configured")
	}
	u, err := url.Parse(cfg.Authority)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("connections: attester authority must be https")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.AttemptTTL <= 0 {
		cfg.AttemptTTL = 10 * time.Minute
	}
	return &Attester{cfg: cfg}, nil
}

// StartRequest is who starts an attestation, for which Entra connection.
type StartRequest struct {
	Tenant       tenant.ID
	ConnectionID connection.ID
	Chain        authority.Chain // the initiator chain; the requester must be a human
	SessionID    string          // the console session, for the step-up check
}

// Start checks the permission over the connection's entra_tenant scope and a fresh step-up, stores the
// attempt and returns the URL the Global Administrator signs in at. A refusal is audited with its
// reason (unless the chain itself fails validation, which has no valid actor to audit). The state and PKCE verifier are random; only the hash of the state is stored.
func (a *Attester) Start(ctx context.Context, req StartRequest) (string, error) {
	target := authority.TargetRef{Connection: string(req.ConnectionID), GUID: string(req.ConnectionID), Class: classEntraTenant}
	deny := func(reason string, err error) (string, error) {
		a.auditOnly(ctx, req.Tenant, req.Chain, target, AuditAttestStarted, audit.Denied, reason, nil)
		return "", err
	}
	if req.Chain.Validate() != nil || req.Chain.Requester.Kind != authority.Human || len(req.Chain.Via) != 0 {
		return deny(ReasonNotPermitted, ErrNotPermitted)
	}
	if err := a.cfg.Authz.Authorize(ctx, req.Chain, TakeoverAttestPermission, target); err != nil {
		return deny(ReasonNotPermitted, ErrNotPermitted)
	}
	fresh, err := a.cfg.StepUp.Fresh(ctx, req.Tenant, req.SessionID)
	if err != nil {
		return "", fmt.Errorf("connections: step-up check: %w", err)
	}
	if !fresh {
		return deny(ReasonStepUpRequired, ErrStepUpRequired)
	}
	state, err := a.random(32)
	if err != nil {
		return "", err
	}
	verifier, err := a.random(32) // 43 base64url characters, RFC 7636 §4.1
	if err != nil {
		return "", err
	}
	var tenantID string
	err = a.cfg.DB.WithTenant(ctx, req.Tenant, func(ctx context.Context, tx store.Tx) error {
		c, err := a.store.Get(ctx, tx, req.ConnectionID)
		if err != nil {
			return err
		}
		if !attestable(c) {
			return ErrNotAttestable
		}
		tenantID = string(c.DirectoryIdentity)
		now := a.cfg.Now()
		if err := a.store.CreateAttempt(ctx, tx, connection.Attempt{ConnectionID: req.ConnectionID, CodeVerifier: verifier,
			StartedBy: string(req.Chain.Requester.ID)}, connection.HashState(state), now, a.cfg.AttemptTTL); err != nil {
			return err
		}
		return a.appendEvent(ctx, tx, req.Chain, target, AuditAttestStarted, audit.Success, "", nil)
	})
	if errors.Is(err, ErrNotAttestable) || errors.Is(err, connection.ErrNotFound) {
		return deny(ReasonBadConnection, ErrNotAttestable)
	}
	if err != nil {
		return "", err
	}
	return a.authorizeURL(tenantID, state, verifier), nil
}

func attestable(c connection.Connection) bool {
	return c.Kind == connection.KindEntraTenant && c.DirectoryIdentity != "" && c.State == connection.StateActive
}

func (a *Attester) authorizeURL(tenantID, state, verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{}
	q.Set("client_id", a.cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", a.cfg.RedirectURI)
	q.Set("response_mode", "query")
	q.Set("scope", AttestScope)
	q.Set("state", state)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	q.Set("prompt", "login") // a fresh interactive sign-in of the administrator, never a silent one
	return strings.TrimRight(a.cfg.Authority, "/") + "/" + url.PathEscape(tenantID) + "/oauth2/v2.0/authorize?" + q.Encode()
}

// CallbackRequest is the redirect back from the IdP.
type CallbackRequest struct {
	Tenant tenant.ID
	State  string
	Code   string
}

// Result is what a completed attestation recorded. It holds no token.
type Result struct {
	State          connection.TakeoverProtection
	BlockHardMatch bool
	BlockSoftMatch bool
	AttesterOID    string
	At             time.Time
}

// Callback redeems the code, checks the token, makes the one read, records the result and audits it.
// The attempt is consumed first, so a replay finds nothing. The token is zeroed before return on every
// path. Every refusal is audited with a machine reason and records no attestation.
func (a *Attester) Callback(ctx context.Context, req CallbackRequest) (res Result, err error) {
	var att connection.Attempt
	var conn connection.Connection
	err = a.cfg.DB.WithTenant(ctx, req.Tenant, func(ctx context.Context, tx store.Tx) error {
		var e error
		att, e = a.store.ConsumeAttempt(ctx, tx, connection.HashState(req.State), a.cfg.Now())
		if e != nil {
			return e
		}
		conn, e = a.store.Get(ctx, tx, att.ConnectionID)
		return e
	})
	starter := authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(att.StartedBy), Kind: authority.Human}}
	target := authority.TargetRef{Connection: string(att.ConnectionID), GUID: string(att.ConnectionID), Class: classEntraTenant}
	fail := func(reason string, e error) (Result, error) {
		a.auditOnly(ctx, req.Tenant, starter, target, AuditAttestFailed, audit.Failure, reason, nil)
		return Result{}, e
	}
	if err != nil {
		if errors.Is(err, connection.ErrAttemptInvalid) || errors.Is(err, connection.ErrNotFound) {
			// No attempt, so no starter to attribute: record the refusal under a system actor.
			sys := authority.Chain{Requester: authority.Principal{ID: "system:attestation-callback", Kind: authority.System}}
			a.auditOnly(ctx, req.Tenant, sys, authority.TargetRef{Class: classEntraTenant}, AuditAttestFailed, audit.Denied, ReasonAttemptInvalid, nil)
			return Result{}, connection.ErrAttemptInvalid
		}
		return Result{}, err
	}
	if !attestable(conn) {
		return fail(ReasonBadConnection, ErrNotAttestable)
	}

	grant, err := a.cfg.IdP.Exchange(ctx, ExchangeRequest{TenantID: string(conn.DirectoryIdentity), Code: req.Code,
		CodeVerifier: att.CodeVerifier, RedirectURI: a.cfg.RedirectURI, Scopes: []string{AttestScope}})
	defer grant.Token.Zero() // on every path below; a zero Bearer is a no-op
	if err != nil {
		return fail(ReasonTokenExchange, fmt.Errorf("connections: token exchange failed"))
	}
	if !sameTenant(grant.TenantID, string(conn.DirectoryIdentity)) {
		return fail(ReasonTenantMismatch, ErrTenantMismatch)
	}
	if !exactScope(grant.Scopes) {
		return fail(ReasonScopeMismatch, ErrScopeMismatch)
	}
	oidID, perr := connection.ParseID(strings.ToLower(grant.ObjectID))
	if perr != nil {
		return fail(ReasonBadIdentity, ErrAttesterInvalid)
	}
	oid := string(oidID)
	feat, err := a.cfg.Graph.ReadSyncFeatures(ctx, grant.Token)
	grant.Token.Zero()
	if err != nil {
		return fail(ReasonGraphRead, fmt.Errorf("connections: graph read failed"))
	}

	err = a.cfg.DB.WithTenant(ctx, req.Tenant, func(ctx context.Context, tx store.Tx) error {
		now := a.cfg.Now()
		tk, e := a.store.RecordAttestation(ctx, tx, att.ConnectionID, connection.Attestation{By: oid,
			BlockHardMatch: feat.BlockCloudObjectTakeoverThroughHardMatch, BlockSoftMatch: feat.BlockSoftMatch}, now)
		if e != nil {
			return e
		}
		res = Result{State: tk.State, BlockHardMatch: feat.BlockCloudObjectTakeoverThroughHardMatch,
			BlockSoftMatch: feat.BlockSoftMatch, AttesterOID: oid, At: now}
		return a.appendEvent(ctx, tx, starter, target, AuditAttestRecorded, audit.Success, "", []chain.Detail{
			{Key: "attester_object_id", Value: oid},
			{Key: "block_cloud_object_takeover_through_hard_match", Value: boolText(res.BlockHardMatch)},
			{Key: "block_soft_match", Value: boolText(res.BlockSoftMatch)},
			{Key: "takeover_protection", Value: string(tk.State)},
		})
	})
	if err != nil {
		return fail(ReasonRecordFailed, fmt.Errorf("connections: record attestation: %w", err))
	}
	return res, nil
}

// SetMaxAge shortens attestation_max_age. A value above the 90-day cap is refused and the refusal is
// audited (acceptance: attest_max_age_cap).
func (a *Attester) SetMaxAge(ctx context.Context, tid tenant.ID, id connection.ID, c authority.Chain, d time.Duration) error {
	target := authority.TargetRef{Connection: string(id), GUID: string(id), Class: classEntraTenant}
	if c.Validate() != nil || c.Requester.Kind != authority.Human || len(c.Via) != 0 {
		a.auditOnly(ctx, tid, c, target, AuditMaxAgeSet, audit.Denied, ReasonNotPermitted, nil)
		return ErrNotPermitted
	}
	if err := a.cfg.Authz.Authorize(ctx, c, TakeoverAttestPermission, target); err != nil {
		a.auditOnly(ctx, tid, c, target, AuditMaxAgeSet, audit.Denied, ReasonNotPermitted, nil)
		return ErrNotPermitted
	}
	if err := connection.ValidateAttestationMaxAge(d); err != nil {
		a.auditOnly(ctx, tid, c, target, AuditMaxAgeSet, audit.Denied, "max_age_above_cap", nil)
		return err
	}
	return a.cfg.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		if err := a.store.SetAttestationMaxAge(ctx, tx, id, d); err != nil {
			return err
		}
		return a.appendEvent(ctx, tx, c, target, AuditMaxAgeSet, audit.Success, "",
			[]chain.Detail{{Key: "max_age_seconds", Value: fmt.Sprint(int64(d / time.Second))}})
	})
}

func (a *Attester) appendEvent(ctx context.Context, tx store.Tx, c authority.Chain, t authority.TargetRef, kind string, o audit.Outcome, reason string, d []chain.Detail) error {
	return a.cfg.Audit.Append(ctx, tx, audit.Event{ID: a.cfg.NewID(), Kind: audit.Kind(kind), At: a.cfg.Now(), Actor: c, Target: t,
		Component: a.cfg.Component, Outcome: o, Reason: reason, Details: d})
}

// auditOnly writes a refusal or failure in its own transaction. A refusal must be recorded even
// though no change is, and an audit fault must not turn a refusal into an approval.
func (a *Attester) auditOnly(ctx context.Context, tid tenant.ID, c authority.Chain, t authority.TargetRef, kind string, o audit.Outcome, reason string, d []chain.Detail) {
	if c.Validate() != nil {
		return
	}
	_ = a.cfg.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		return a.appendEvent(ctx, tx, c, t, kind, o, reason, d)
	})
}

func (a *Attester) random(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(a.cfg.Rand, b); err != nil {
		return "", fmt.Errorf("connections: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func sameTenant(a, b string) bool {
	x, y := strings.ToLower(a), strings.ToLower(b)
	return x != "" && x == y
}

// exactScope: the IdP granted the attestation scope and nothing else (no offline_access).
func exactScope(got []string) bool {
	return len(got) == 1 && strings.EqualFold(got[0], AttestScope)
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
