package negotiate

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	conn    = "11111111-1111-4111-8111-111111111111"
	objA    = "aaaaaaaa-0000-4000-8000-0000000000a1"
	acctOK  = "bbbbbbbb-0000-4000-8000-0000000000b1"
	acctOff = "bbbbbbbb-0000-4000-8000-0000000000b2"
	acctDup = "bbbbbbbb-0000-4000-8000-0000000000b3"
)

var tid = func() tenant.ID {
	id, err := tenant.Parse("22222222-2222-4222-8222-222222222222")
	if err != nil {
		panic(err)
	}
	return id
}()

func mustSID(t *testing.T, s string) sid.SID {
	t.Helper()
	v, err := sid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// rig records the call order so the tests can compare paths.
type rig struct {
	mu        sync.Mutex
	calls     []string
	objs      map[string][]inventory.Ref
	backed    map[string][]string
	states    map[string]authn.AccountState
	principal Principal
	acceptErr error
	begun     []authn.BeginInput
	refused   []string
}

func (r *rig) note(s string) { r.mu.Lock(); r.calls = append(r.calls, s); r.mu.Unlock() }

func (r *rig) Accept(context.Context, []byte) (Principal, error) {
	r.note("accept")
	return r.principal, r.acceptErr
}
func (r *rig) ObjectsBySID(_ context.Context, _ tenant.ID, s sid.SID) ([]inventory.Ref, error) {
	r.note("sid")
	return r.objs[s.String()], nil
}
func (r *rig) BackedBy(_ context.Context, _ tenant.ID, ref authn.DirectoryRef) ([]string, error) {
	r.note("backed")
	return r.backed[ref.ObjectGUID], nil
}
func (r *rig) Get(_ context.Context, _ tenant.ID, id string) (authn.Account, error) {
	r.note("get")
	st, ok := r.states[id]
	if !ok {
		return authn.Account{}, authn.ErrAccountNotFound
	}
	return authn.Account{ID: id, State: st}, nil
}
func (r *rig) Epoch(_ context.Context, _ tenant.ID, id string) (authn.Epoch, error) {
	r.note("epoch")
	if _, ok := r.states[id]; !ok {
		return authn.Epoch{}, authn.ErrAccountInactive
	}
	return authn.Epoch{}, nil // zero value: Begin is faked below
}
func (r *rig) Begin(_ context.Context, in authn.BeginInput) (authn.PendingHandle, error) {
	r.note("begin")
	r.begun = append(r.begun, in)
	return authn.ParsePendingHandle(tid.String() + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
}
func (r *rig) Refused(_ context.Context, _ tenant.ID, reason string, _ netip.Addr) error {
	r.note("audit")
	r.refused = append(r.refused, reason)
	return nil
}

func newRig(t *testing.T) (*rig, *Service) {
	r := &rig{
		objs: map[string][]inventory.Ref{
			"S-1-5-21-1-2-3-1001": {{Connection: conn, Object: objA}},
			"S-1-5-21-1-2-3-1002": {{Connection: conn, Object: objA}},
			"S-1-5-21-1-2-3-1003": {{Connection: conn, Object: objA}, {Connection: conn, Object: "aaaaaaaa-0000-4000-8000-0000000000a2"}},
		},
		backed: map[string][]string{objA: {acctOK}},
		states: map[string]authn.AccountState{acctOK: authn.AccountActive, acctOff: authn.AccountDisabled},
	}
	return r, &Service{Acceptor: r, Directory: r, Accounts: r, Epochs: r, Pending: r, Recorder: r}
}

var krbReq = func() []byte { return negInit([][]byte{oidKerberos}, krbToken()) }

// Unmapped, ambiguous, disabled, replayed and NTLM requests get the same error value and none of them
// produce a pending sign-in: the response cannot tell the caller which one it was.
func Test_an9_uniform(t *testing.T) {
	cases := map[string]func(r *rig){
		"unmapped sid":      func(r *rig) { r.principal = Principal{SID: mustSID(t, "S-1-5-21-9-9-9-500")} },
		"ambiguous objects": func(r *rig) { r.principal = Principal{SID: mustSID(t, "S-1-5-21-1-2-3-1003")} },
		"ambiguous accounts": func(r *rig) {
			r.principal = Principal{SID: mustSID(t, "S-1-5-21-1-2-3-1001")}
			r.backed[objA] = []string{acctOK, acctDup}
		},
		"disabled account": func(r *rig) {
			r.principal = Principal{SID: mustSID(t, "S-1-5-21-1-2-3-1001")}
			r.backed[objA] = []string{acctOff}
		},
		"no console account": func(r *rig) { r.principal = Principal{SID: mustSID(t, "S-1-5-21-1-2-3-1002")}; r.backed[objA] = nil },
		"ticket rejected":    func(r *rig) { r.acceptErr = errors.New("replay") },
	}
	var wantReasons = map[string]string{"unmapped sid": ReasonUnmapped, "ambiguous objects": ReasonAmbiguous,
		"ambiguous accounts": ReasonAmbiguous, "disabled account": ReasonInactive, "no console account": ReasonUnmapped, "ticket rejected": ReasonRejected}
	for name, setup := range cases {
		r, svc := newRig(t)
		setup(r)
		h, err := svc.SignIn(context.Background(), Request{Tenant: tid, Token: krbReq()})
		if err != ErrSignInFailed {
			t.Errorf("%s: got %v, want exactly ErrSignInFailed", name, err)
		}
		if h != (authn.PendingHandle{}) || len(r.begun) != 0 {
			t.Errorf("%s: a pending sign-in was created", name)
		}
		if len(r.refused) != 1 || r.refused[0] != wantReasons[name] {
			t.Errorf("%s: audit reason %v, want %s", name, r.refused, wantReasons[name])
		}
	}
	// NTLM never reaches the acceptor.
	r, svc := newRig(t)
	_, err := svc.SignIn(context.Background(), Request{Tenant: tid, Token: negInit([][]byte{oidNTLM}, []byte("NTLMSSP\x00"))})
	if err != ErrSignInFailed || contains(r.calls, "accept") || r.refused[0] != ReasonNotKerberos {
		t.Errorf("ntlm: err=%v calls=%v refused=%v", err, r.calls, r.refused)
	}
}

// The unmapped and the disabled path make the same kinds of calls, so a caller cannot time them apart by
// a missing round trip.
func Test_an9_unmapped_and_disabled_do_the_same_work(t *testing.T) {
	shape := func(setup func(*rig)) []string {
		r, svc := newRig(t)
		setup(r)
		_, _ = svc.SignIn(context.Background(), Request{Tenant: tid, Token: krbReq()})
		return r.calls
	}
	unmapped := shape(func(r *rig) { r.principal = Principal{SID: mustSID(t, "S-1-5-21-9-9-9-500")} })
	disabled := shape(func(r *rig) {
		r.principal = Principal{SID: mustSID(t, "S-1-5-21-1-2-3-1001")}
		r.backed[objA] = []string{acctOff}
	})
	if len(unmapped) != len(disabled) {
		t.Fatalf("unmapped %v vs disabled %v", unmapped, disabled)
	}
	for i := range unmapped {
		if unmapped[i] != disabled[i] {
			t.Fatalf("unmapped %v vs disabled %v", unmapped, disabled)
		}
	}
}

func Test_an9_success_begins_a_kerberos_pending_sign_in_after_reading_the_epoch(t *testing.T) {
	r, svc := newRig(t)
	r.principal = Principal{SID: mustSID(t, "S-1-5-21-1-2-3-1001")}
	h, err := svc.SignIn(context.Background(), Request{Tenant: tid, Token: krbReq(), ClientIP: netip.MustParseAddr("192.0.2.7")})
	if err != nil {
		t.Fatal(err)
	}
	if h == (authn.PendingHandle{}) || len(r.begun) != 1 {
		t.Fatal("no pending sign-in")
	}
	b := r.begun[0]
	if b.FirstFactor != authn.FirstKerberos || b.Account != acctOK || b.Tenant != tid {
		t.Errorf("begin input %+v", b)
	}
	ie, ib := index(r.calls, "epoch"), index(r.calls, "begin")
	if ie < 0 || ib < 0 || ie > ib {
		t.Errorf("epoch must be read before Begin: %v", r.calls)
	}
}

func Test_an9_infrastructure_failure_is_not_a_sign_in_refusal(t *testing.T) {
	_, svc := newRig(t)
	svc.Directory = failingDir{}
	svc.Acceptor = acceptAll{mustSID(t, "S-1-5-21-1-2-3-1001")}
	if _, err := svc.SignIn(context.Background(), Request{Tenant: tid, Token: krbReq()}); err == nil || errors.Is(err, ErrSignInFailed) {
		t.Fatalf("got %v", err)
	}
}

type failingDir struct{}

func (failingDir) ObjectsBySID(context.Context, tenant.ID, sid.SID) ([]inventory.Ref, error) {
	return nil, errors.New("db down")
}

type acceptAll struct{ s sid.SID }

func (a acceptAll) Accept(context.Context, []byte) (Principal, error) {
	return Principal{SID: a.s}, nil
}

func contains(s []string, v string) bool { return index(s, v) >= 0 }
func index(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

// FF-SP5 at the service: arbitrary bytes never panic and never yield a pending sign-in unless the
// acceptor (here: reject-all) said yes.
func Fuzz_sign_in_token(f *testing.F) {
	f.Add(krbReq())
	f.Add([]byte("NTLMSSP\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, svc := newRig(t)
		r.acceptErr = errors.New("no")
		if _, err := svc.SignIn(context.Background(), Request{Tenant: tid, Token: b}); err != ErrSignInFailed {
			t.Fatalf("got %v", err)
		}
		if len(r.begun) != 0 {
			t.Fatal("pending sign-in without an accepted ticket")
		}
	})
}
