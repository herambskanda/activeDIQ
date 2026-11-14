package write

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write/ops"
	"github.com/skenzeriq/activediq/internal/directory/accountkind"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func computerState(id guidT) ad.AccountState {
	return ad.AccountState{GUID: id, Classes: []string{"top", "person", "organizationalPerson", "user", "computer"},
		HasUAC: true, UAC: 4096, USN: 100, PwdLastSet: 5, SID: []byte{1, 2, 3}, OperatingSystem: "Windows Server 2022", LastLogonTimestamp: 1234}
}

func resetSpec() accountkind.Spec {
	sp, _ := accountkind.ByKey(accountkind.KeyComputerReset)
	return sp
}

// Kind 13 on a computer: Plan reads and returns the precondition and the display attributes, never a
// no-op (a reset is never already done).
func TestComputerResetPlan(t *testing.T) {
	id := mk(60)
	r, fs := acctRig(t, nil, computerState(id))
	p, _ := kindReqs(resetSpec(), id, false)
	resp, err := r.h.Plan(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetNoOp() || len(resp.GetPrecondition().GetStateDigest()) == 0 {
		t.Fatalf("no-op=%v digest=%d", resp.GetNoOp(), len(resp.GetPrecondition().GetStateDigest()))
	}
	got := map[string]bool{}
	for _, a := range resp.GetBefore().GetAttributes() {
		got[a.GetName()] = true
	}
	for _, n := range []string{"pwdLastSet", "userAccountControl", "lastLogonTimestamp", "operatingSystem"} {
		if !got[n] {
			t.Errorf("Plan before lacks %s", n)
		}
	}
	if len(fs.sent) != 0 {
		t.Fatal("Plan sent a modify")
	}
}

// A user, a managed service account and a cluster object are refused with their own rule ids, before
// anything is sent.
func TestComputerResetClassRefusals(t *testing.T) {
	id := mk(61)
	cluster := computerState(id)
	cluster.SPNs = []string{"MSClusterVirtualServer/vcluster1", "HOST/x"}
	clusterCNO := computerState(id)
	clusterCNO.SPNs = []string{"msserverclustermgmtapi/cno1"}
	gmsa := computerState(id)
	gmsa.Classes = append(gmsa.Classes, "msDS-GroupManagedServiceAccount")
	cases := map[string]struct {
		st   ad.AccountState
		rule string
	}{
		"user":   {userState(id, 512, 0), "ClassNotAllowed"},
		"gmsa":   {gmsa, "ClassNotAllowed"},
		"vco":    {cluster, "ClusterObject"},
		"cno":    {clusterCNO, "ClusterObject"},
		"no uac": {func() ad.AccountState { s := computerState(id); s.HasUAC = false; return s }(), "UnreadableAttribute"},
	}
	for name, c := range cases {
		r, fs := acctRig(t, nil, c.st)
		fs.secure = true
		p, a := kindReqs(resetSpec(), id, false)
		_, err := r.h.Plan(context.Background(), p)
		expectRule(t, err, c.rule)
		_, err = r.h.Apply(context.Background(), a)
		expectRule(t, err, c.rule)
		if len(fs.sent) != 0 {
			t.Errorf("%s: a modify was sent", name)
		}
	}
}

// Kind 13 carries no secret input: one in the request is SecretInputMismatch, before any call.
func TestComputerResetRefusesSecretInput(t *testing.T) {
	id := mk(62)
	r, fs := acctRig(t, nil, computerState(id))
	_, a := kindReqs(resetSpec(), id, false)
	a.SecretInput = &connectorv1.SecretValue{Material: []byte("Passw0rd!")}
	_, err := r.h.Apply(context.Background(), a)
	expectRule(t, err, "SecretInputMismatch")
	if fs.calls != 0 {
		t.Fatalf("session touched %d times", fs.calls)
	}
}

// Over a connection that is not verified TLS, Apply is TRANSPORT_SECURITY and nothing is generated or sent.
func TestComputerResetNeedsSecureTransport(t *testing.T) {
	id := mk(63)
	r, fs := acctRig(t, nil, computerState(id))
	fs.secure = false
	_, a := kindReqs(resetSpec(), id, false)
	_, err := r.h.Apply(context.Background(), a)
	if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_TRANSPORT_SECURITY {
		t.Fatalf("insecure: %s", c)
	}
	if len(fs.sent) != 0 {
		t.Fatal("sent over an unverified connection")
	}
}

// A changed target (uSNChanged, pwdLastSet or UAC moved since Plan) is TARGET_CHANGED and sends nothing.
func TestComputerResetTargetChanged(t *testing.T) {
	id := mk(64)
	r, fs := acctRig(t, nil, computerState(id))
	fs.secure = true
	p, a := kindReqs(resetSpec(), id, false)
	resp, err := r.h.Plan(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	a.Precondition = resp.GetPrecondition()
	fs.state.PwdLastSet = 99
	fs.state.USN = 101
	_, err = r.h.Apply(context.Background(), a)
	if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_TARGET_CHANGED {
		t.Fatalf("changed: %s", c)
	}
	if len(fs.sent) != 0 {
		t.Fatal("sent after the target changed")
	}
}

func TestGenerateMachinePassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		b, err := ops.GenerateMachinePassword()
		if err != nil {
			t.Fatal(err)
		}
		if len(b) < 120 {
			t.Fatalf("length %d", len(b))
		}
		for _, c := range b {
			if c < 0x21 || c > 0x7e {
				t.Fatalf("byte %#x outside the printable set", c)
			}
		}
		if seen[string(b)] {
			t.Fatal("repeated value")
		}
		seen[string(b)] = true
		if bytes.Count(b, b[:1]) > len(b)/2 {
			t.Fatal("degenerate value")
		}
	}
	// every class of character shows up over many draws: no truncated alphabet
	var all strings.Builder
	for i := 0; i < 40; i++ {
		b, _ := ops.GenerateMachinePassword()
		all.Write(b)
	}
	for _, set := range []string{"abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"} {
		if !strings.ContainsAny(all.String(), set) {
			t.Errorf("no character of %q drawn", set[:4])
		}
	}
}
