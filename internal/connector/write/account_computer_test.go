package write

import (
	"context"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/accountkind"
	"github.com/skenzeriq/activediq/internal/directory/attr/unicodepwd"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Kind 13, COMPUTER_ACCOUNT_RESET (contract §8.10.3, T-1913). The LDAP Modify itself needs a verified
// TLS proof the unit fakes cannot mint, so its success path is the lab test (CC-WK-57, S/W).

func computerState(id guidT, spns ...string) ad.AccountState {
	return ad.AccountState{GUID: id, Classes: []string{"top", "person", "organizationalPerson", "user", "computer"}, HasUAC: true,
		UAC: 4096, USN: 100, PwdLastSet: 7, LastLogonTS: 9, OperatingSystem: "Windows 11", SPNs: spns, SID: []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}}
}

func TestMachinePasswordIsRandomLongAndPrintable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		pw, err := newMachinePassword()
		if err != nil {
			t.Fatal(err)
		}
		pw.Expose(func(b []byte) {
			if len(b) < 120 {
				t.Errorf("password is %d characters, want at least 120", len(b))
			}
			for _, c := range b {
				if !strings.ContainsRune(machinePasswordAlphabet, rune(c)) {
					t.Errorf("character %q outside the alphabet", c)
				}
			}
			if seen[string(b)] {
				t.Error("two resets drew the same password")
			}
			seen[string(b)] = true
		})
		pw.Destroy()
	}
}

func TestResetComputerSendsNothingWithoutAVerifiedChannel(t *testing.T) {
	fs := &fakeSession{}
	err := resetComputer()(recMod{fs}, "<GUID=x>", unicodepwd.SecureConn{})
	if ad.CodeOf(err) != ad.CodeInsecure || len(fs.sent) != 0 {
		t.Fatalf("got %v, %d sent", err, len(fs.sent))
	}
}

func TestComputerResetPlanClassAndClusterRules(t *testing.T) {
	id := mk(50)
	sp, _ := accountkind.ByKey(accountkind.KeyComputerReset)
	ruleOf := func(err error) string { return connErr(t, err).GetRejectedInput().GetRuleId() }
	cases := []struct {
		name string
		st   ad.AccountState
		rule string // "" = planned
	}{
		{"plain computer", computerState(id, "HOST/pc01", "TERMSRV/pc01"), ""},
		{"lookalike name", computerState(id, "HOST/MSClusterVirtualServer-lookalike"), ""},
		{"cluster name object", computerState(id, "MSServerClusterMgmtAPI/clus1"), "ClusterObject"},
		{"virtual computer object", computerState(id, "host/x", "msclustervirtualserver/vco"), "ClusterObject"},
		{"user", userState(id, 512, 0), "ClassNotAllowed"},
		{"gMSA", ad.AccountState{GUID: id, HasUAC: true, Classes: []string{"top", "person", "organizationalPerson", "user", "computer", "msDS-GroupManagedServiceAccount"}}, "ClassNotAllowed"},
	}
	for _, c := range cases {
		r, fs := acctRig(t, nil, c.st)
		p, _ := kindReqs(sp, id, false)
		pr, err := r.h.Plan(context.Background(), p)
		if c.rule != "" {
			if ruleOf(err) != c.rule || len(fs.sent) != 0 {
				t.Errorf("%s: got rule %q (%v)", c.name, ruleOf(err), err)
			}
			continue
		}
		if err != nil || pr.GetNoOp() || len(pr.GetPrecondition().GetStateDigest()) != 32 {
			t.Errorf("%s: plan %v", c.name, err)
			continue
		}
		names := map[string]bool{}
		for _, a := range pr.GetBefore().GetAttributes() {
			names[a.GetName()] = true
		}
		for _, n := range []string{"pwdLastSet", "lastLogonTimestamp", "userAccountControl", "operatingSystem"} {
			if !names[n] {
				t.Errorf("%s: preview lacks %s", c.name, n)
			}
		}
	}
}

func TestComputerResetApplyRefusals(t *testing.T) {
	id := mk(51)
	sp, _ := accountkind.ByKey(accountkind.KeyComputerReset)
	plan := func(t *testing.T, r *rig) (*connectorv1.PlanResponse, *connectorv1.ApplyRequest) {
		p, a := kindReqs(sp, id, false)
		pr, err := r.h.Plan(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		a.Precondition = pr.Precondition
		return pr, a
	}
	t.Run("plain channel is TRANSPORT_SECURITY", func(t *testing.T) {
		r, fs := acctRig(t, nil, computerState(id))
		_, a := plan(t, r)
		_, err := r.h.Apply(context.Background(), a)
		if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_TRANSPORT_SECURITY || len(fs.sent) != 0 {
			t.Fatalf("got %s, %d sent", c, len(fs.sent))
		}
	})
	t.Run("secret input is a mismatch", func(t *testing.T) {
		r, fs := acctRig(t, nil, computerState(id))
		_, a := plan(t, r)
		a.SecretInput = &connectorv1.SecretValue{Material: []byte("x")}
		_, err := r.h.Apply(context.Background(), a)
		if rule := connErr(t, err).GetRejectedInput().GetRuleId(); rule != "SecretInputMismatch" || len(fs.sent) != 0 {
			t.Fatalf("got %q, %d sent", rule, len(fs.sent))
		}
	})
	t.Run("a retry after the reset landed is TARGET_CHANGED, never ALREADY_APPLIED", func(t *testing.T) {
		r, fs := acctRig(t, nil, computerState(id))
		fs.secure = true
		_, a := plan(t, r)
		fs.state.USN++ // the first reply was lost; the reset moved uSNChanged and pwdLastSet
		fs.state.PwdLastSet += 100
		_, err := r.h.Apply(context.Background(), a)
		if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_TARGET_CHANGED || len(fs.sent) != 0 {
			t.Fatalf("got %s, %d sent", c, len(fs.sent))
		}
	})
}

func TestComputerResetDeclaresOnlyUnicodePwd(t *testing.T) {
	sp, _ := accountkind.ByKey(accountkind.KeyComputerReset)
	if got := accountDecl(sp, 0).Keys; len(got) != 1 || got[0] != "unicodePwd" {
		t.Fatalf("keys %v", got)
	}
	if operations[adKey(connectorv1.WriteKind_WRITE_KIND_COMPUTER_ACCOUNT_RESET)].WantsSecret {
		t.Fatal("kind 13 must not take secret_input")
	}
}
