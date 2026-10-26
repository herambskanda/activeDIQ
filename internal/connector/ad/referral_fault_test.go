package ad

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// LF-32 / CC-SRCH-10 by fault injection (T-0309): a continuation reference ends ScopedSearch with
// UNEXPECTED_REFERRAL, is never followed, and never leaves a partial stream looking complete.
// FAILURE INJECTION: the directory is an in-process stand-in behind the test-only fault proxy;
// Samba cannot produce referrals (the same proxy fronts the real lab in ldapfault_lab_test.go).

func faultSession(t *testing.T, up func() (net.Conn, error), plan injectPlan) (*Session, *faultProxy) {
	t.Helper()
	p, pool := startFaultProxy(t, up, plan)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := Open(ctx, Config{
		Servers: []string{p.Addr()}, RootCAs: pool, Timeout: 5 * time.Second,
		Credential: Credential{BindName: "svc@lab.test", Password: secret.FromBytes([]byte("pw"))},
	})
	if err != nil {
		t.Fatalf("open through the proxy: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, p
}

func scopedReq(t *testing.T, s *Session, roots ...guid.GUID) ScopedRequest {
	t.Helper()
	cls, err := ldapfilter.ParseAttrName("objectClass", s.schema)
	if err != nil {
		t.Fatal(err)
	}
	refs := make([]dn.ObjectRef, len(roots))
	for i, g := range roots {
		refs[i] = dn.GUIDRef(g)
	}
	return ScopedRequest{Roots: refs, Depth: ScopeSubtree, Filter: ldapfilter.Present(cls), Attributes: []string{"distinguishedName"}}
}

// Control: the harness alone does not cause the error, so the failures below are the reference.
func TestReferralFaultControlNoInjection(t *testing.T) {
	up := startFakeUpstream(t, 3)
	s, p := faultSession(t, up.dial, injectPlan{skip: 1 << 30})
	var got int
	res, err := s.ScopedSearch(context.Background(), scopedReq(t, s, guid.GUID{1}), func(*Entry) error { got++; return nil })
	if err != nil || got != 3 || res.Returned != 3 || res.RootsCompleted != 1 || p.Injected() != 0 {
		t.Fatalf("control: err=%v got=%d res=%+v injected=%d", err, got, res, p.Injected())
	}
}

// AC1: a reference alone ends the search with UNEXPECTED_REFERRAL; nothing is followed, no URL leaks.
func TestReferralEndsScopedSearch(t *testing.T) {
	trap := startHoneypot(t)
	url := "ldaps://" + trap.ln.Addr().String() + "/DC=other,DC=test"
	up := startFakeUpstream(t, 0)
	s, p := faultSession(t, up.dial, injectPlan{urls: []string{url}})
	called := 0
	res, err := s.ScopedSearch(context.Background(), scopedReq(t, s, guid.GUID{1}), func(*Entry) error { called++; return nil })
	if CodeOf(err) != CodeUnexpectedReferral {
		t.Fatalf("want UNEXPECTED_REFERRAL, got %v", err)
	}
	if p.Injected() != 1 {
		t.Fatalf("the proxy injected %d references; the test proved nothing", p.Injected())
	}
	if called != 0 || res.Returned != 0 || res.RootsCompleted != 0 {
		t.Errorf("result presented after a referral: called=%d %+v", called, res)
	}
	if trap.Hits() != 0 {
		t.Errorf("the connector followed the referral: %d connections to the referred server", trap.Hits())
	}
	if strings.Contains(err.Error(), trap.ln.Addr().String()) || strings.Contains(err.Error(), "ldaps://") {
		t.Errorf("error leaks the referral URL: %v", err)
	}
}

// AC2: the reference arrives mid-stream, after entries. The call fails and is never complete:
// RootsCompleted stays 0 and the error, not a nil, is what the caller sees.
func TestReferralMidStreamIsNotComplete(t *testing.T) {
	for _, after := range []int{1, 2, 3} { // 3 = after the last entry, just before the done message
		trap := startHoneypot(t)
		up := startFakeUpstream(t, 3)
		s, p := faultSession(t, up.dial, injectPlan{afterEntries: after, urls: []string{"ldaps://" + trap.ln.Addr().String() + "/DC=x"}})
		res, err := s.ScopedSearch(context.Background(), scopedReq(t, s, guid.GUID{1}), func(*Entry) error { return nil })
		if CodeOf(err) != CodeUnexpectedReferral || p.Injected() != 1 {
			t.Errorf("after %d entries: err=%v injected=%d", after, err, p.Injected())
		}
		if res.RootsCompleted != 0 {
			t.Errorf("after %d entries: a root was reported complete: %+v", after, res)
		}
		if trap.Hits() != 0 {
			t.Errorf("after %d entries: referral followed", after)
		}
	}
}

// AC2, several roots: root 1 completes, root 2 gets the reference. The call returns the error and
// counts exactly one completed root, so a caller can tell the stream is partial.
func TestReferralOnSecondRootKeepsEarlierCountHonest(t *testing.T) {
	up := startFakeUpstream(t, 2)
	s, p := faultSession(t, up.dial, injectPlan{skip: 1, afterEntries: 1, urls: []string{"ldaps://127.0.0.1:1/DC=x"}})
	// The fake returns the same two GUIDs for both roots; de-duplication is not under test here.
	res, err := s.ScopedSearch(context.Background(), scopedReq(t, s, guid.GUID{1}, guid.GUID{2}), func(*Entry) error { return nil })
	if CodeOf(err) != CodeUnexpectedReferral || p.Injected() != 1 {
		t.Fatalf("err=%v injected=%d", err, p.Injected())
	}
	if res.RootsCompleted != 1 {
		t.Errorf("RootsCompleted = %d, want 1 (the second root failed)", res.RootsCompleted)
	}
}

// A multi-URL reference (a DFS-style continuation) is the same single failure.
func TestReferralWithSeveralURLs(t *testing.T) {
	up := startFakeUpstream(t, 1)
	s, _ := faultSession(t, up.dial, injectPlan{urls: []string{"ldaps://127.0.0.1:1/DC=a", "ldap://127.0.0.1:2/DC=b"}})
	if _, err := s.ScopedSearch(context.Background(), scopedReq(t, s, guid.GUID{1}), func(*Entry) error { return nil }); CodeOf(err) != CodeUnexpectedReferral {
		t.Errorf("err=%v", err)
	}
}

// AC4: the real Windows DC case needs the Windows lab (a DC with a subordinate cross-ref/referral
// object). It is recorded as PENDING in the run output; it is never reported as a pass.
func TestReferralWindowsRealDCPending(t *testing.T) {
	t.Skip("PENDING(windows-lab): LF-32 on a real Windows DC is unproven until `make windows-lab-up` can host a referral; fault-injection proof above stands in")
}
