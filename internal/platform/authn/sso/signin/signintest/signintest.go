// Package signintest holds the fakes of signin's ports for tests of the service and of its HTTP binding.
// Fixtures live only in tests: nothing outside a _test.go file imports this package.
package signintest

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso/signin"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Tenant is the tenant every fake serves.
var Tenant = func() tenant.ID {
	id, err := tenant.Parse("33333333-3333-4333-8333-333333333333")
	if err != nil {
		panic(err)
	}
	return id
}()

// AccountID is the one account the fakes know.
const AccountID = "44444444-4444-4444-8444-444444444444"

// Rig is a Service wired to fakes; the fields are the fakes, for the test to set and inspect.
type Rig struct {
	Service  *signin.Service
	IdPs     *IdPs
	Verifier *Verifier
	Txs      *MemTxs
	Accounts *Accounts
	Anchors  *Anchors
	Sessions *Sessions
	Pending  *Pending
	Priv     *Priv
	Rec      *Recorder
	Now      time.Time
}

// NewRig returns a Rig with one enabled OIDC IdP "idp1" (MFA off), one active unbound SSO account for
// issuer "https://idp.example" and subject "sub-1", and a verifier that accepts every callback as that
// subject.
func NewRig() *Rig {
	r := &Rig{Now: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	r.IdPs = &IdPs{M: map[string]sso.IdP{"idp1": {ID: "idp1", Protocol: sso.ProtocolOIDC, Enabled: true, OIDC: &sso.OIDCConfig{Issuer: "https://idp.example"}}}}
	r.Verifier = &Verifier{Out: sso.Verified{Issuer: "https://idp.example", Subject: "sub-1"}}
	r.Txs = &MemTxs{Now: func() time.Time { return r.Now }, M: map[string]sso.Transaction{}}
	r.Accounts = &Accounts{A: authn.Account{Tenant: Tenant, ID: AccountID, Kind: authn.KindSSO, State: authn.AccountActive,
		SSOIssuer: "https://idp.example", SSOSubject: "sub-1"}}
	r.Anchors = &Anchors{}
	r.Sessions = &Sessions{}
	r.Pending = &Pending{}
	r.Priv = &Priv{}
	r.Rec = &Recorder{}
	r.Service = &signin.Service{
		IdPs: r.IdPs, Verifiers: map[sso.Protocol]sso.Verifier{sso.ProtocolOIDC: r.Verifier, sso.ProtocolSAML: r.Verifier},
		Txs: r.Txs, Accounts: r.Accounts, Anchors: r.Anchors, Epochs: Epochs{}, Sessions: r.Sessions,
		Pending: r.Pending, Privileges: r.Priv, Recorder: r.Rec, Clock: func() time.Time { return r.Now },
	}
	return r
}

// SetMFA marks the IdP MFA-asserting (claim mode).
func (r *Rig) SetMFA() {
	i := r.IdPs.M["idp1"]
	i.OIDC.MFAMode = sso.MFAClaim
	r.IdPs.M["idp1"] = i
}

// StartCookie runs Start and returns the cookie value.
func (r *Rig) StartCookie(ctx context.Context, ret string) (string, error) {
	res, err := r.Service.Start(ctx, signin.StartRequest{Tenant: Tenant, IdPID: "idp1", ReturnPath: ret})
	if err != nil {
		return "", err
	}
	return res.Handle.Reveal(), nil
}

// Callback runs a callback for idp1 with the cookie.
func (r *Rig) Callback(ctx context.Context, cookie string) (signin.Result, error) {
	return r.Service.Callback(ctx, signin.CallbackRequest{Tenant: Tenant, IdPID: "idp1", Cookie: cookie,
		Callback: sso.Callback{IdPID: "idp1", Query: url.Values{"code": {"c"}, "state": {"s"}}}})
}

// IdPs is signin.IdPs over a map.
type IdPs struct{ M map[string]sso.IdP }

// IdP implements signin.IdPs.
func (f *IdPs) IdP(_ context.Context, _ tenant.ID, id string) (sso.IdP, error) {
	i, ok := f.M[id]
	if !ok {
		return sso.IdP{}, signin.ErrIdPNotFound
	}
	return i, nil
}

// Verifier is an sso.Verifier with a canned answer.
type Verifier struct {
	Out       sso.Verified
	Err       error
	Completed []sso.Transaction
}

// Start implements sso.Verifier.
func (v *Verifier) Start(_ context.Context, _ tenant.ID, idp sso.IdP, intent sso.Intent) (*url.URL, sso.Transaction, error) {
	return &url.URL{Scheme: "https", Host: "idp.example", Path: "/authorize"}, sso.Transaction{State: "st", Nonce: "no", Verifier: "ve", Intent: intent}, nil
}

// Complete implements sso.Verifier and records the Transaction it was given.
func (v *Verifier) Complete(_ context.Context, _ tenant.ID, _ sso.IdP, tx sso.Transaction, _ sso.Callback) (sso.Verified, error) {
	v.Completed = append(v.Completed, tx)
	if v.Err != nil {
		return sso.Verified{}, v.Err
	}
	return v.Out, nil
}

// MemTxs is an in-memory signin.Transactions with the same consume-once and age rules as TxStore.
type MemTxs struct {
	Now func() time.Time
	mu  sync.Mutex
	M   map[string]sso.Transaction
	n   int
}

// Put implements signin.Transactions.
func (m *MemTxs) Put(_ context.Context, _ tenant.ID, tx sso.Transaction) (signin.Handle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	raw := make([]byte, 32)
	copy(raw, []byte(strings.Repeat("h", 8)))
	raw[31] = byte(m.n)
	text := base64.RawURLEncoding.EncodeToString(raw)
	tx.CreatedAt = m.Now()
	m.M[text] = tx
	h, _ := signin.ParseHandle(text)
	return h, nil
}

// Consume implements signin.Transactions.
func (m *MemTxs) Consume(_ context.Context, _ tenant.ID, h signin.Handle) (sso.Transaction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tx, ok := m.M[h.Reveal()]
	if !ok {
		return sso.Transaction{}, signin.ErrNoTransaction
	}
	delete(m.M, h.Reveal())
	if m.Now().Sub(tx.CreatedAt) >= signin.TransactionTTL {
		return sso.Transaction{}, signin.ErrTransactionExpired
	}
	return tx, nil
}

// Accounts is signin.Accounts over one account.
type Accounts struct {
	A     authn.Account
	Found bool // when false the lookup is ErrAccountNotFound; NewRig leaves it true via Present
	Binds []authn.Anchor
	// BindErr is returned by Bind.
	BindErr error
	Absent  bool
}

// LookupSSO implements signin.Accounts.
func (f *Accounts) LookupSSO(_ context.Context, _ tenant.ID, issuer, subject string) (authn.Account, error) {
	if f.Absent || issuer != f.A.SSOIssuer || subject != f.A.SSOSubject {
		return authn.Account{}, authn.ErrAccountNotFound
	}
	return f.A, nil
}

// Bind implements signin.Accounts.
func (f *Accounts) Bind(_ context.Context, _ tenant.ID, _ string, an authn.Anchor, ref authn.DirectoryRef, _ authority.Chain) (authn.Account, error) {
	if f.BindErr != nil {
		return authn.Account{}, f.BindErr
	}
	f.Binds = append(f.Binds, an)
	f.A.Anchor, f.A.Ref = &an, &ref
	return f.A, nil
}

// Anchors is authn.DirectoryAnchors with one canned answer.
type Anchors struct {
	Ref      authn.DirectoryRef
	Err      error
	Resolved []authn.Anchor
}

// Resolve implements authn.DirectoryAnchors.
func (f *Anchors) Resolve(_ context.Context, _ tenant.ID, a authn.Anchor) (authn.DirectoryRef, error) {
	f.Resolved = append(f.Resolved, a)
	return f.Ref, f.Err
}

// Matched implements authn.DirectoryAnchors.
func (f *Anchors) Matched(context.Context, tenant.ID, authn.DirectoryRef, authn.DirectoryRef) (bool, error) {
	return false, nil
}

// Epochs is signin.Epochs; the epoch is the zero value because the fakes ignore it.
type Epochs struct{}

// Epoch implements signin.Epochs.
func (Epochs) Epoch(context.Context, tenant.ID, string) (authn.Epoch, error) {
	return authn.Epoch{}, nil
}

// Sessions records Create calls.
type Sessions struct{ Created []authn.CreateInput }

// Create implements signin.Sessions.
func (f *Sessions) Create(_ context.Context, in authn.CreateInput) (authn.CreateResult, error) {
	f.Created = append(f.Created, in)
	tok, err := authn.ParseToken(Tenant.String() + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		return authn.CreateResult{}, err
	}
	return authn.CreateResult{Token: tok, Session: authn.Session{ID: "sess-1", Tenant: in.Tenant, Account: in.Account,
		AbsoluteExpiry: time.Now().Add(time.Hour)}}, nil
}

// Pending records Begin calls.
type Pending struct{ Begun []authn.BeginInput }

// Begin implements signin.Pending.
func (f *Pending) Begin(_ context.Context, in authn.BeginInput) (authn.PendingHandle, error) {
	f.Begun = append(f.Begun, in)
	return authn.ParsePendingHandle(Tenant.String() + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
}

// Priv is signin.Privileges with a canned answer.
type Priv struct {
	Holds bool
	Err   error
}

// HoldsControlPlane implements signin.Privileges.
func (f *Priv) HoldsControlPlane(context.Context, tenant.ID, string) (bool, error) {
	return f.Holds, f.Err
}

// Recorder keeps every Outcome.
type Recorder struct {
	mu sync.Mutex
	O  []signin.Outcome
}

// Record implements signin.Recorder.
func (f *Recorder) Record(_ context.Context, o signin.Outcome) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.O = append(f.O, o)
	return nil
}

// Last returns the latest Outcome.
func (f *Recorder) Last() signin.Outcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.O) == 0 {
		return signin.Outcome{}
	}
	return f.O[len(f.O)-1]
}
