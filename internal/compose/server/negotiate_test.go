package server

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authn/negotiate"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	negConn = "11111111-1111-4111-8111-111111111111"
	negObjA = "aaaaaaaa-0000-4000-8000-0000000000a1"
	negObjB = "aaaaaaaa-0000-4000-8000-0000000000a2"
	negObjC = "aaaaaaaa-0000-4000-8000-0000000000a3"
	negAcct = "bbbbbbbb-0000-4000-8000-0000000000b1"
	negSID  = "S-1-5-21-1-2-3-1001"
)

func negTenant(t *testing.T) tenant.ID {
	t.Helper()
	id, err := tenant.Parse("22222222-2222-4222-8222-222222222222")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// fakeSIDs answers every lookup with refs/err and counts the calls.
type fakeSIDs struct {
	refs  []inventory.Ref
	err   error
	calls int
	got   string
}

func (f *fakeSIDs) ObjectsBySID(_ context.Context, _ tenant.ID, s sid.SID) ([]inventory.Ref, error) {
	f.calls++
	f.got = s.String()
	return f.refs, f.err
}

func ref(o string) inventory.Ref {
	return inventory.Ref{Connection: negConn, Object: inventory.GUID(o)}
}

func TestNegotiateDirectoryMapsRefs(t *testing.T) {
	src := &fakeSIDs{refs: []inventory.Ref{ref(negObjA)}}
	got, err := negotiateDirectory{src}.ObjectsBySID(context.Background(), negTenant(t), negSID)
	if err != nil {
		t.Fatal(err)
	}
	if want := []authn.DirectoryRef{{ConnectionID: negConn, ObjectGUID: negObjA}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if src.got != negSID {
		t.Fatalf("inventory asked for %q", src.got)
	}
}

func TestNegotiateDirectoryMalformedSIDIsEmptyAndNeverQueried(t *testing.T) {
	for _, text := range []string{"", "not-a-sid", "S-1", "S-1-5-21-x", "S-1-5-21-1-2-3-1001' OR '1'='1"} {
		src := &fakeSIDs{refs: []inventory.Ref{ref(negObjA)}}
		got, err := negotiateDirectory{src}.ObjectsBySID(context.Background(), negTenant(t), text)
		if err != nil || len(got) != 0 {
			t.Fatalf("%q: got %v, %v", text, got, err)
		}
		if src.calls != 0 {
			t.Fatalf("%q: inventory was queried", text)
		}
	}
}

func TestNegotiateDirectoryInvalidIsEmptyOtherErrorsPropagate(t *testing.T) {
	got, err := negotiateDirectory{&fakeSIDs{err: inventory.ErrInvalid}}.ObjectsBySID(context.Background(), negTenant(t), negSID)
	if err != nil || len(got) != 0 {
		t.Fatalf("invalid: got %v, %v", got, err)
	}
	boom := errors.New("db down")
	if _, err := (negotiateDirectory{&fakeSIDs{err: boom}}).ObjectsBySID(context.Background(), negTenant(t), negSID); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}

func TestNegotiateDirectoryCapsAtMaxSIDMatches(t *testing.T) {
	src := &fakeSIDs{refs: []inventory.Ref{ref(negObjA), ref(negObjB), ref(negObjC)}}
	got, err := negotiateDirectory{src}.ObjectsBySID(context.Background(), negTenant(t), negSID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != inventory.MaxSIDMatches {
		t.Fatalf("got %d refs, want %d", len(got), inventory.MaxSIDMatches)
	}
}

// negFakes are the rest of the negotiate service, enough to run SignIn through the adapter.
type negFakes struct {
	principal string
	refused   []string
}

func (f *negFakes) Accept(context.Context, []byte) (negotiate.Principal, error) {
	return negotiate.Principal{SID: f.principal}, nil
}
func (*negFakes) BackedBy(context.Context, tenant.ID, authn.DirectoryRef) ([]string, error) {
	return []string{negAcct}, nil
}
func (*negFakes) Get(_ context.Context, _ tenant.ID, id string) (authn.Account, error) {
	return authn.Account{ID: id, State: authn.AccountActive}, nil
}
func (*negFakes) Epoch(context.Context, tenant.ID, string) (authn.Epoch, error) {
	return authn.Epoch{}, nil
}
func (*negFakes) Begin(context.Context, authn.BeginInput) (authn.PendingHandle, error) {
	return authn.PendingHandle{}, nil
}
func (f *negFakes) Refused(_ context.Context, _ tenant.ID, reason string, _ netip.Addr) error {
	f.refused = append(f.refused, reason)
	return nil
}

// negDER is a short-form DER element (every length here is under 128).
func negDER(tag byte, content ...[]byte) []byte {
	var c []byte
	for _, p := range content {
		c = append(c, p...)
	}
	return append([]byte{tag, byte(len(c))}, c...)
}

// negKerberosToken is a Kerberos-first SPNEGO NegTokenInit with an AP-REQ-shaped optimistic token, the
// shape RequireKerberos admits. The acceptor here is a fake, so the AP-REQ body is not real.
func negKerberosToken() []byte {
	oidKrb := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
	oidSPNEGO := []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	krb := negDER(0x60, negDER(0x06, oidKrb), []byte{0x01, 0x00}, negDER(0x6e, []byte("ap-req-body")))
	init := negDER(0xa0, negDER(0x30,
		negDER(0xa0, negDER(0x30, negDER(0x06, oidKrb))),
		negDER(0xa2, negDER(0x04, krb))))
	return negDER(0x60, negDER(0x06, oidSPNEGO), init)
}

// The sign-in through the adapter: malformed text and more than MaxSIDMatches matches both end as the
// one ErrSignInFailed, with unmapped and ambiguous recorded; one match signs in.
func TestNegotiateSignInThroughAdapter(t *testing.T) {
	cases := map[string]struct {
		sid    string
		refs   []inventory.Ref
		reason string
	}{
		"one match signs in": {sid: negSID, refs: []inventory.Ref{ref(negObjA)}},
		"malformed sid":      {sid: "S-garbage", refs: []inventory.Ref{ref(negObjA)}, reason: negotiate.ReasonUnmapped},
		"no match":           {sid: negSID, reason: negotiate.ReasonUnmapped},
		"two matches":        {sid: negSID, refs: []inventory.Ref{ref(negObjA), ref(negObjB)}, reason: negotiate.ReasonAmbiguous},
		"more than max":      {sid: negSID, refs: []inventory.Ref{ref(negObjA), ref(negObjB), ref(negObjC)}, reason: negotiate.ReasonAmbiguous},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := &negFakes{principal: c.sid}
			svc := &negotiate.Service{Acceptor: f, Directory: negotiateDirectory{&fakeSIDs{refs: c.refs}},
				Accounts: f, Epochs: f, Pending: f, Recorder: f}
			_, err := svc.SignIn(context.Background(), negotiate.Request{Tenant: negTenant(t), Token: negKerberosToken()})
			if c.reason == "" {
				if err != nil {
					t.Fatalf("got %v", err)
				}
				return
			}
			if !errors.Is(err, negotiate.ErrSignInFailed) {
				t.Fatalf("got %v, want ErrSignInFailed", err)
			}
			if !reflect.DeepEqual(f.refused, []string{c.reason}) {
				t.Fatalf("recorded %v, want [%s]", f.refused, c.reason)
			}
		})
	}
}
