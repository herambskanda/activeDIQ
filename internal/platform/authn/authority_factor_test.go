package authn

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	afConn      = "00000000-0000-4000-8000-0000000000c1"
	afGUID      = "11111111-2222-4333-8444-555555555555" // the AD object the oid-bound account correlates to
	afEntraConn = "00000000-0000-4000-8000-0000000000e1"
	afEntraGUID = "22222222-3333-4444-8555-666666666666" // the Entra object the account is bound to
	afOID       = "99999999-aaaa-4bbb-8ccc-dddddddddddd"
	afTID       = "88888888-aaaa-4bbb-8ccc-dddddddddddd"
)

// register answers BeginEnrol's challenge the way an authenticator with attestation "none" does
// (WebAuthn §6.5): attestedCredentialData in authenticatorData, UP|UV|AT set.
func (k *softKey) register(t *testing.T, challenge, origin string) (in FinishEnrolInput) {
	t.Helper()
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": challenge, "origin": origin, "crossOrigin": false})
	rp := sha256.Sum256([]byte(waRPID))
	ad := append([]byte{}, rp[:]...)
	ad = append(ad, 0x45) // UP | UV | AT
	ad = binary.BigEndian.AppendUint32(ad, 0)
	ad = append(ad, make([]byte, 16)...) // aaguid
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(k.credID)))
	ad = append(ad, k.credID...)
	ad = append(ad, k.cose()...)
	// {"fmt":"none","attStmt":{},"authData":h'…'}
	obj := []byte{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e', 0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0,
		0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a', 0x59}
	obj = binary.BigEndian.AppendUint16(obj, uint16(len(ad)))
	obj = append(obj, ad...)
	e := base64.RawURLEncoding.EncodeToString
	return FinishEnrolInput{Label: "authority key", CredentialID: e(k.credID), AttestationObject: e(obj), ClientDataJSON: e(cd)}
}

type fakeOwners struct{ ids []string }

func (f *fakeOwners) TenantOwners(context.Context, store.Tx, tenant.ID) ([]string, error) {
	return append([]string(nil), f.ids...), nil
}

type fakeAnchors struct {
	ad  DirectoryRef
	err error
}

func (f *fakeAnchors) Resolve(context.Context, tenant.ID, Anchor) (DirectoryRef, error) {
	return DirectoryRef{}, ErrAnchorNoMatch
}
func (f *fakeAnchors) Matched(context.Context, tenant.ID, DirectoryRef, DirectoryRef) (bool, error) {
	return true, nil
}
func (f *fakeAnchors) MatchedAD(_ context.Context, _ tenant.ID, entra DirectoryRef) (DirectoryRef, error) {
	if f.err != nil || entra.ConnectionID != afEntraConn {
		return DirectoryRef{}, ErrAnchorNoMatch
	}
	return f.ad, nil
}

type fakeAD struct {
	err   error
	calls int
	got   []byte
	refs  []DirectoryRef
}

func (f *fakeAD) VerifyUser(_ context.Context, _ tenant.ID, ref DirectoryRef, cred []byte) error {
	f.refs = append(f.refs, ref)
	f.calls++
	f.got = append([]byte(nil), cred...)
	return f.err
}

type afEnv struct {
	*pendEnv
	af          *AuthorityFactors
	ad          *fakeAD
	anchors     *fakeAnchors
	owners      *fakeOwners
	user, owner Actor
	owner2      string
	userRes     CreateResult
	ownerRes    CreateResult
	key         *softKey
	userSeed    []byte
	stepUp      *StepUp
}

func (e *afEnv) mkAccount(t *testing.T, n NewAccount) string {
	t.Helper()
	n.Tenant, n.CreatedBy = e.ten, "system"
	a, err := e.accts.Create(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.accts.SetState(context.Background(), e.ten, a.ID, AccountActive, authority.Chain{Requester: authority.Principal{ID: "system", Kind: authority.System}}); err != nil {
		t.Fatal(err)
	}
	return a.ID
}

// enrolTOTP enrols and activates a TOTP factor for the account and returns its seed.
func (e *afEnv) enrolTOTP(t *testing.T, account string) []byte {
	t.Helper()
	keep, keepSeed := e.pendEnv.account, e.seed
	e.pendEnv.account = account
	e.enrolFor(t)
	seed := e.seed
	e.pendEnv.account, e.seed = keep, keepSeed
	return seed
}

func (e *afEnv) signIn(t *testing.T, account string) CreateResult {
	t.Helper()
	now := e.now
	res, err := e.sess.Create(context.Background(), CreateInput{Tenant: e.ten, Account: account, Methods: []string{"password", "totp"},
		MFAAt: &now, ClientIP: netip.MustParseAddr("192.0.2.7"), Epoch: epochOf(t, e.sess, e.ten, account)})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func eachAuthority(t *testing.T, fn func(t *testing.T, e *afEnv)) {
	eachPending(t, func(t *testing.T, p *pendEnv) {
		ctx := context.Background()
		if err := fixtureAs(p.db, p.ten, `INSERT INTO public.connections (tenant_id, id, kind, display_name, credential_id, transport_security)
			VALUES ($1::uuid, $2::uuid, 'ad_forest', 'c', $3::uuid, 'ldaps')`, p.ten.String(), afConn, afConn); err != nil {
			t.Fatal(err)
		}
		if err := fixtureAs(p.db, p.ten, `INSERT INTO public.connections (tenant_id, id, kind, display_name, credential_id, transport_security)
			VALUES ($1::uuid, $2::uuid, 'entra_tenant', 'e', $3::uuid, NULL)`, p.ten.String(), afEntraConn, afEntraConn); err != nil {
			t.Fatal(err)
		}
		e := &afEnv{pendEnv: p, ad: &fakeAD{}, key: newSoftKey(t),
			anchors: &fakeAnchors{ad: DirectoryRef{ConnectionID: afConn, ObjectGUID: afGUID}}}
		user := e.mkAccount(t, NewAccount{Kind: KindSSO, DisplayName: "sso user", SSOIssuer: "https://idp.example.test", SSOSubject: "u1"})
		if _, err := p.accts.Bind(ctx, p.ten, user, Anchor{Kind: AnchorOID, Value: afOID, TenantID: afTID},
			DirectoryRef{ConnectionID: afEntraConn, ObjectGUID: afEntraGUID}, authority.Chain{Requester: authority.Principal{ID: "system", Kind: authority.System}}); err != nil {
			t.Fatal(err)
		}
		e.userSeed = e.enrolTOTP(t, user)
		e.owner2 = e.mkAccount(t, NewAccount{Kind: KindLocal, DisplayName: "owner two"})
		e.owners = &fakeOwners{ids: []string{p.account, e.owner2}}
		e.stepUp = &StepUp{Sessions: p.sess, TOTP: p.svc}
		af, err := NewAuthorityFactors(WebAuthnConfig{RPID: waRPID, RPDisplayName: "activeDIQ", Origins: []string{waOrigin}},
			p.db, p.sess, p.accts, e.owners, e.stepUp, e.ad, e.anchors)
		if err != nil {
			t.Fatal(err)
		}
		e.af = af
		e.userRes, e.ownerRes = e.signIn(t, user), e.signIn(t, p.account)
		e.user = Actor{Account: user, SessionID: e.userRes.Session.ID}
		e.owner = Actor{Account: p.account, SessionID: e.ownerRes.Session.ID}
		fn(t, e)
	})
}

func wantRefusal(t *testing.T, err error, reason string) {
	t.Helper()
	var r *AuthorityRefusal
	if !errors.As(err, &r) || r.Reason != reason || !errors.Is(err, ErrAuthorityRefused) {
		t.Fatalf("want refusal %q, got %v", reason, err)
	}
}

// enrolViaAD runs the whole ceremony through the AD proof.
func (e *afEnv) enrolViaAD(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	c, err := e.af.BeginEnrol(ctx, e.ten, EnrolInput{Actor: e.user, ADCredential: []byte("correct horse")})
	if err != nil {
		t.Fatalf("begin enrol: %v", err)
	}
	if _, err := e.af.FinishEnrol(ctx, e.ten, withActor(e.key.register(t, c.Response.Challenge.String(), waOrigin), e.user)); err != nil {
		t.Fatalf("finish enrol: %v", err)
	}
}

func withActor(in FinishEnrolInput, a Actor) FinishEnrolInput { in.Actor = a; return in }

func (e *afEnv) count(t *testing.T, sql string) int {
	t.Helper()
	return mustInt(e.query(t, sql)[0])
}

// verify runs a successful per-session verification.
func (e *afEnv) verify(t *testing.T, counter uint32) error {
	t.Helper()
	o, err := e.af.BeginVerify(context.Background(), e.ten, e.user)
	if err != nil {
		return err
	}
	return e.af.Verify(context.Background(), e.ten, e.user, e.assertion(t, o.Challenge, counter))
}

// assertion signs as the authenticator; the credential is not discoverable, so no userHandle is returned.
func (e *afEnv) assertion(t *testing.T, challenge string, counter uint32) WebAuthnAssertion {
	a := e.key.assert(t, challenge, waOrigin, counter)
	a.UserHandle = ""
	return a
}

func (e *afEnv) current(t *testing.T) bool {
	t.Helper()
	ss, err := e.sess.ListActive(context.Background(), e.ten, e.user.Account)
	if err != nil || len(ss) != 1 {
		t.Fatalf("sessions: %v %v", ss, err)
	}
	return ss[0].AuthorityCurrent()
}

// TM-D19 rule 2: the factor is enrolled only on an AD-plane proof or a tenant-owner's approval.
func Test_enrol_requires_ad_proof_or_owner(t *testing.T) {
	eachAuthority(t, func(t *testing.T, e *afEnv) {
		ctx := context.Background()
		// Neither proof, or both: refused, and the refusal is audited.
		_, err := e.af.BeginEnrol(ctx, e.ten, EnrolInput{Actor: e.user})
		wantRefusal(t, err, AuthorityNoProof)
		_, err = e.af.BeginEnrol(ctx, e.ten, EnrolInput{Actor: e.user, ADCredential: []byte("x"), ApprovalID: afGUID})
		wantRefusal(t, err, AuthorityTwoProofs)
		if n := len(e.sink.of(KindAuthorityEnrolRefused)); n != 2 {
			t.Fatalf("%d refusal events", n)
		}
		// The connector says no: refused; it is asked once with the credential, which is zeroed afterwards.
		e.ad.err = ErrADProofRefused
		cred := []byte("wrong")
		_, err = e.af.BeginEnrol(ctx, e.ten, EnrolInput{Actor: e.user, ADCredential: cred})
		wantRefusal(t, err, AuthorityADProofRefused)
		if e.ad.calls != 1 || string(e.ad.got) != "wrong" || string(cred) == "wrong" {
			t.Fatalf("connector calls=%d got=%q caller buffer=%q", e.ad.calls, e.ad.got, cred)
		}
		// An outage is not a refusal, and nothing is enrolled.
		e.ad.err = errors.New("dc unreachable")
		if _, err = e.af.BeginEnrol(ctx, e.ten, EnrolInput{Actor: e.user, ADCredential: []byte("x")}); err == nil || errors.Is(err, ErrAuthorityRefused) {
			t.Fatalf("outage: %v", err)
		}
		// The proof is about the correlated AD object, never the Entra one the account is bound to.
		if len(e.ad.refs) == 0 {
			t.Fatal("connector not asked")
		}
		for _, r := range e.ad.refs {
			if r.ConnectionID != afConn || r.ObjectGUID != afGUID {
				t.Fatalf("VerifyUser got %+v, want the AD object", r)
			}
		}
		// No matched correlation: refused on the AD-proof path and the connector is never called.
		before := e.ad.calls
		e.anchors.err = ErrAnchorNoMatch
		_, err = e.af.BeginEnrol(ctx, e.ten, EnrolInput{Actor: e.user, ADCredential: []byte("x")})
		wantRefusal(t, err, AuthorityNoCorrelation)
		// A correlation that lands on a non-AD-forest connection is refused too.
		e.anchors.err = nil
		e.anchors.ad = DirectoryRef{ConnectionID: afEntraConn, ObjectGUID: afGUID}
		_, err = e.af.BeginEnrol(ctx, e.ten, EnrolInput{Actor: e.user, ADCredential: []byte("x")})
		wantRefusal(t, err, AuthorityNoCorrelation)
		e.anchors.ad = DirectoryRef{ConnectionID: afConn, ObjectGUID: afGUID}
		if e.ad.calls != before {
			t.Fatalf("VerifyUser called %d more times without a correlation", e.ad.calls-before)
		}
		// No connector configured: fail closed.
		noAD, _ := NewAuthorityFactors(WebAuthnConfig{RPID: waRPID, RPDisplayName: "a", Origins: []string{waOrigin}}, e.db, e.sess, e.accts, e.owners, e.stepUp, nil, e.anchors)
		_, err = noAD.BeginEnrol(ctx, e.ten, EnrolInput{Actor: e.user, ADCredential: []byte("x")})
		wantRefusal(t, err, AuthorityADProofMissing)
		if e.count(t, `SELECT count(*)::text FROM public.authn_webauthn_credentials WHERE purpose = 'authority'`) != 0 {
			t.Fatal("a credential exists without a proof")
		}

		// Path 1: the AD proof.
		e.ad.err = nil
		e.enrolViaAD(t)
		if e.count(t, `SELECT count(*)::text FROM public.authn_webauthn_credentials WHERE purpose = 'authority' AND state = 'active'`) != 1 {
			t.Fatal("no authority credential after the AD proof")
		}
		// It never signs anyone in: AN-10 reads second_factor credentials only.
		_ = e.tx(t, e.ten, func(ctx context.Context, tx store.Tx) error {
			cs, err := credentials(ctx, tx, e.ten, e.user.Account, purposeSecondFactor)
			if err != nil || len(cs) != 0 {
				t.Fatalf("second-factor credentials: %v %v", cs, err)
			}
			return nil
		})
		// One active authority credential per account.
		_, err = e.af.BeginEnrol(ctx, e.ten, EnrolInput{Actor: e.user, ADCredential: []byte("x")})
		wantRefusal(t, err, AuthorityAlreadyEnrolled)
	})
}

func Test_enrol_owner_approval(t *testing.T) {
	eachAuthority(t, func(t *testing.T, e *afEnv) {
		ctx := context.Background()
		// A non-owner cannot approve (even for themselves or with a fresh step-up).
		_, err := e.af.Approve(ctx, e.ten, e.user, e.user.Account)
		wantRefusal(t, err, AuthorityNotOwner)
		// An owner cannot approve their own enrolment, nor a step-up-less owner anyone's.
		_, err = e.af.Approve(ctx, e.ten, e.owner, e.owner.Account)
		wantRefusal(t, err, AuthorityApprovalInvalid) // never for oneself
		ap, err := e.af.Approve(ctx, e.ten, e.owner, e.user.Account)
		if err != nil {
			t.Fatalf("owner approval: %v", err)
		}
		if !ap.ExpiresAt.Equal(e.now.Add(15 * time.Minute)) {
			t.Fatalf("expires %v", ap.ExpiresAt)
		}
		// Somebody else's approval is not valid for me.
		_, err = e.af.BeginEnrol(ctx, e.ten, EnrolInput{Actor: e.user, ApprovalID: "00000000-0000-4000-8000-00000000ffff"})
		wantRefusal(t, err, AuthorityApprovalInvalid)
		// After 15 minutes it is dead.
		e.now = e.now.Add(16 * time.Minute)
		_, err = e.af.BeginEnrol(ctx, e.ten, EnrolInput{Actor: e.user, ApprovalID: ap.ID})
		wantRefusal(t, err, AuthorityApprovalInvalid)
		// A fresh approval whose approver then loses tenant-owner is dead too.
		e.ownerStepUp(t)
		ap, err = e.af.Approve(ctx, e.ten, e.owner, e.user.Account)
		if err != nil {
			t.Fatal(err)
		}
		e.owners.ids = []string{e.owner2}
		_, err = e.af.BeginEnrol(ctx, e.ten, EnrolInput{Actor: e.user, ApprovalID: ap.ID})
		wantRefusal(t, err, AuthorityApprovalInvalid)
		e.owners.ids = []string{e.owner.Account, e.owner2}
		// A valid approval enrols once; the same approval cannot start a second ceremony.
		ap, err = e.af.Approve(ctx, e.ten, e.owner, e.user.Account)
		if err != nil {
			t.Fatal(err)
		}
		c, err := e.af.BeginEnrol(ctx, e.ten, EnrolInput{Actor: e.user, ApprovalID: ap.ID})
		if err != nil {
			t.Fatalf("approved enrolment: %v", err)
		}
		if _, err := e.af.BeginEnrol(ctx, e.ten, EnrolInput{Actor: e.user, ApprovalID: ap.ID}); !errors.Is(err, ErrAuthorityRefused) {
			t.Fatalf("approval reused: %v", err)
		}
		if _, err := e.af.FinishEnrol(ctx, e.ten, withActor(e.key.register(t, c.Response.Challenge.String(), waOrigin), e.user)); err != nil {
			t.Fatalf("finish: %v", err)
		}
		if e.ad.calls != 0 {
			t.Fatal("the connector was asked on the approval path")
		}
		// A step-up-less owner cannot approve.
		e.now = e.now.Add(10 * time.Minute)
		_, err = e.af.Approve(ctx, e.ten, e.owner, e.user.Account)
		wantRefusal(t, err, AuthorityStepUpRequired)
	})
}

// A bad registration response (wrong origin) stores nothing and spends the challenge.
func Test_enrol_bad_attestation(t *testing.T) {
	eachAuthority(t, func(t *testing.T, e *afEnv) {
		ctx := context.Background()
		c, err := e.af.BeginEnrol(ctx, e.ten, EnrolInput{Actor: e.user, ADCredential: []byte("pw")})
		if err != nil {
			t.Fatal(err)
		}
		in := withActor(e.key.register(t, c.Response.Challenge.String(), "https://evil.example.test"), e.user)
		_, err = e.af.FinishEnrol(ctx, e.ten, in)
		wantRefusal(t, err, AuthorityAttestationBad)
		in = withActor(e.key.register(t, c.Response.Challenge.String(), waOrigin), e.user)
		_, err = e.af.FinishEnrol(ctx, e.ten, in)
		wantRefusal(t, err, AuthorityNoChallenge) // spent by the first attempt, right or wrong
		if e.count(t, `SELECT count(*)::text FROM public.authn_webauthn_credentials WHERE purpose = 'authority'`) != 0 {
			t.Fatal("credential stored")
		}
	})
}

// TM-D19 rule 2: enrolment is audited and notified; only a tenant-owner with step-up resets or removes.
func Test_enrol_audit_notify_reset_owner_only(t *testing.T) {
	eachAuthority(t, func(t *testing.T, e *afEnv) {
		ctx := context.Background()
		e.enrolViaAD(t)
		ev := e.sink.of(KindAuthorityEnrolled)
		if len(ev) != 1 || ev[0].Target.GUID != e.user.Account || ev[0].Reason != "ad_proof" {
			t.Fatalf("enrolled events: %+v", ev)
		}
		// The account and every tenant-owner are told, once each.
		recips := e.query(t, `SELECT recipient_id::text FROM public.authn_authority_notices WHERE event = 'enrolled' ORDER BY 1`)
		if len(recips) != 3 {
			t.Fatalf("notice recipients: %v", recips)
		}
		for _, id := range []string{e.user.Account, e.owner.Account, e.owner2} {
			if e.count(t, `SELECT count(*)::text FROM public.authn_authority_notices WHERE event = 'enrolled' AND recipient_id = '`+id+`'`) != 1 {
				t.Fatalf("%s was not notified exactly once", id)
			}
		}
		// The account itself, and a non-owner, cannot reset or remove.
		for _, f := range []func() error{
			func() error { return e.af.Reset(ctx, e.ten, e.user, e.user.Account) },
			func() error { return e.af.Remove(ctx, e.ten, e.user, e.user.Account) },
		} {
			wantRefusal(t, f(), AuthorityNotOwner)
		}
		// An owner without a fresh step-up cannot either.
		e.now = e.now.Add(10 * time.Minute)
		wantRefusal(t, e.af.Reset(ctx, e.ten, e.owner, e.user.Account), AuthorityStepUpRequired)
		wantRefusal(t, e.af.Remove(ctx, e.ten, e.owner, e.user.Account), AuthorityStepUpRequired)
		if e.count(t, `SELECT count(*)::text FROM public.authn_webauthn_credentials WHERE purpose = 'authority' AND state = 'active'`) != 1 {
			t.Fatal("a refused change removed the factor")
		}
		if n := len(e.sink.of(KindAuthorityChangeRefused)); n != 4 {
			t.Fatalf("%d refusal events", n)
		}
		// An owner with a fresh step-up can; the user's sessions lose AD-side authority at once.
		e.ownerStepUp(t)
		if err := e.verify(t, 1); err != nil {
			t.Fatal(err)
		}
		if !e.current(t) {
			t.Fatal("factor not current after verification")
		}
		if err := e.af.Reset(ctx, e.ten, e.owner, e.user.Account); err != nil {
			t.Fatalf("owner reset: %v", err)
		}
		if e.count(t, `SELECT count(*)::text FROM public.authn_webauthn_credentials WHERE purpose = 'authority' AND state = 'active'`) != 0 {
			t.Fatal("factor survived the reset")
		}
		if e.current(t) {
			t.Fatal("the user's session kept AD-side authority after the reset")
		}
		if len(e.sink.of(KindAuthorityReset)) != 1 || e.count(t, `SELECT count(*)::text FROM public.authn_authority_notices WHERE event = 'reset'`) != 3 {
			t.Fatal("reset not audited and notified")
		}
		// Nothing left to reset or remove.
		wantRefusal(t, e.af.Remove(ctx, e.ten, e.owner, e.user.Account), AuthorityNoCredential)
		// Re-enrol, then remove.
		e.key = newSoftKey(t)
		e.enrolViaAD(t)
		if err := e.af.Remove(ctx, e.ten, e.owner, e.user.Account); err != nil {
			t.Fatalf("owner remove: %v", err)
		}
		if len(e.sink.of(KindAuthorityRemoved)) != 1 {
			t.Fatal("removal not audited")
		}
	})
}

// TM-D19 rule 1 / DM-31.I3 at the session level: the factor counts only while authority_factor_at is not
// older than mfa_at, so a TOTP step-up (which moves mfa_at) ends it until the credential is used again.
func Test_authority_factor_gates_correlation_grants(t *testing.T) {
	eachAuthority(t, func(t *testing.T, e *afEnv) {
		ctx := context.Background()
		e.enrolViaAD(t)
		// Signed in through Entra only: no authority.
		if e.current(t) {
			t.Fatal("a session that only signed in holds the factor")
		}
		// No credential, no verification.
		if err := e.verify(t, 1); err != nil {
			t.Fatal(err)
		}
		if !e.current(t) {
			t.Fatal("verified session does not hold the factor")
		}
		// A TOTP step-up refreshes mfa_at but must not keep the factor current.
		e.now = e.now.Add(time.Minute)
		if _, err := e.userStepUp(t); err != nil {
			t.Fatalf("totp step-up: %v", err)
		}
		if e.current(t) {
			t.Fatal("TOTP step-up left authority_factor_at current")
		}
		// Re-verifying restores it, and the user-verified assertion also counts as a step-up.
		e.now = e.now.Add(time.Minute)
		if err := e.verify(t, 2); err != nil {
			t.Fatal(err)
		}
		if !e.current(t) {
			t.Fatal("re-verification did not restore the factor")
		}
		// A failed verification clears it (replayed counter), and is audited.
		o, err := e.af.BeginVerify(ctx, e.ten, e.user)
		if err != nil {
			t.Fatal(err)
		}
		err = e.af.Verify(ctx, e.ten, e.user, e.assertion(t, o.Challenge, 2))
		wantRefusal(t, err, AuthorityCounter)
		if e.current(t) {
			t.Fatal("a failed verification left the factor current")
		}
		if len(e.sink.of(KindAuthorityVerifyRefused)) != 1 {
			t.Fatal("refusal not audited")
		}
		// A challenge works once; another account's session cannot use it.
		wantRefusal(t, e.af.Verify(ctx, e.ten, e.user, e.assertion(t, o.Challenge, 3)), AuthorityNoChallenge)
		_, err = e.af.BeginVerify(ctx, e.ten, Actor{Account: e.user.Account, SessionID: e.ownerRes.Session.ID})
		wantRefusal(t, err, AuthorityNoSession)
	})
}

func (e *afEnv) userStepUp(t *testing.T) (Session, error) {
	t.Helper()
	return e.stepUp.Reverify(context.Background(), e.userRes.Token, hotp(e.userSeed, stepAt(e.now)))
}

// ownerStepUp is the owner's TOTP step-up: it is what makes an owner "fresh" after the window closed.
func (e *afEnv) ownerStepUp(t *testing.T) {
	t.Helper()
	if _, err := e.stepUp.Reverify(context.Background(), e.ownerRes.Token, e.good()); err != nil {
		t.Fatalf("owner step-up: %v", err)
	}
}

// TM-D19 rule 1 / TM-R12: whatever happens in Entra (a TAP, a methods reset, a new sign-in) changes none
// of the state the factor lives in.
func Test_entra_reset_leaves_factor(t *testing.T) {
	eachAuthority(t, func(t *testing.T, e *afEnv) {
		e.enrolViaAD(t)
		snapshot := func() string {
			return e.query(t, `SELECT string_agg(id::text || state || sign_count::text, ',' ORDER BY id) FROM public.authn_webauthn_credentials WHERE purpose = 'authority'`)[0]
		}
		before := snapshot()
		// A fresh Entra sign-in after the user's methods were reset and a TAP issued: a new session.
		ent := e.signIn(t, e.user.Account)
		if ent.Session.AuthorityCurrent() {
			t.Fatal("an Entra sign-in carries the authority factor")
		}
		// Re-binding by the Entra anchor is refused, so the account cannot be re-pointed either.
		if _, err := e.accts.Bind(context.Background(), e.ten, e.user.Account, Anchor{Kind: AnchorOID, Value: afOID, TenantID: afTID},
			DirectoryRef{ConnectionID: afConn, ObjectGUID: afGUID}, authority.Chain{Requester: authority.Principal{ID: "system", Kind: authority.System}}); !errors.Is(err, ErrAlreadyBound) {
			t.Fatalf("rebind: %v", err)
		}
		if snapshot() != before {
			t.Fatal("the factor changed without an owner")
		}
		// Only the credential holder's own assertion makes a session current.
		if e.count(t, `SELECT count(*)::text FROM public.authn_sessions WHERE account_id = '`+e.user.Account+`' AND authority_factor_at IS NOT NULL`) != 0 {
			t.Fatal("a session holds the factor without verification")
		}
	})
}
