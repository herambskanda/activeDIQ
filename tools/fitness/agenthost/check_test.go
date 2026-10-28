package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hostProto = `syntax = "proto3";
package skenzeriq.agent.v1;
message Empty {}
message SignedPolicy { bytes payload = 1; bytes signature = 2; }
message SignedKeyset { bytes payload = 1; bytes signature = 2; }
message StageRequest { bytes tuf_metadata = 1; bytes artefact_digest = 2; }
message AckRequest { uint64 through_agent_seq = 1; }
message Status { uint64 policy_seq = 1; }
service Host {
  rpc GetStatus(Empty) returns (Status);
  rpc ApplyPolicy(SignedPolicy) returns (Status);
  rpc ApplyKeyset(SignedKeyset) returns (Status);
  rpc StageUpdate(StageRequest) returns (Status);
  rpc AckEvents(AckRequest) returns (Status);
}
`

const addcProto = `syntax = "proto3";
package activediq.addc.v1;
message Empty {}
message CollectionState { uint64 last_event_record_id = 1; }
message PasswordPolicy { uint32 min_length = 1; repeated string banned_terms = 2; }
message AddcPolicy { PasswordPolicy password = 1; bool collection_enabled = 2; }
service Addc { rpc GetCollectionState(Empty) returns (CollectionState); }
`

const goodWxs = `<?xml version="1.0"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="activeDIQ Agent">
    <ServiceInstall Name="activediq-agent" Account="NT SERVICE\activeDIQAgent" Start="auto" Type="ownProcess" ErrorControl="normal">
      <ServiceConfig ServiceSid="restricted" RequiredPrivileges="SeChangeNotifyPrivilege" />
    </ServiceInstall>
  </Package>
</Wix>
`

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func protoTree(t *testing.T, host, addc string) string {
	root := t.TempDir()
	// The proto tool also requires the fleet contract to exist (F11), so the fixtures carry the real one.
	fleet, err := os.ReadFile("../../../proto/activediq/fleet/v1/fleet.proto")
	if err != nil {
		t.Fatal(err)
	}
	write(t, root, "proto/activediq/fleet/v1/fleet.proto", string(fleet))
	write(t, root, "proto/skenzeriq/agent/v1/agent.proto", host)
	write(t, root, "proto/activediq/addc/v1/addc.proto", addc)
	return root
}

func wantViolation(t *testing.T, r Result, sub string) {
	t.Helper()
	if r.Inactive != "" {
		t.Fatalf("%s inactive (%s), want a violation containing %q", r.ID, r.Inactive, sub)
	}
	for _, v := range r.Violations {
		if strings.Contains(v, sub) {
			return
		}
	}
	t.Fatalf("%s: want a violation containing %q, got %v", r.ID, sub, r.Violations)
}

func wantClean(t *testing.T, r Result) {
	t.Helper()
	if r.Inactive != "" || len(r.Violations) != 0 {
		t.Fatalf("%s: want clean, got inactive=%q violations=%v", r.ID, r.Inactive, r.Violations)
	}
}

func TestProtoRulesInactiveWithoutProto(t *testing.T) {
	r := checkProto(t.TempDir(), "R1", "x", []string{"AG1"})
	if r.Inactive == "" {
		t.Fatal("R1 must say inactive when the agent proto does not exist, never pass")
	}
}

func TestProtoRulesR1R2R5(t *testing.T) {
	clean := protoTree(t, hostProto, addcProto)
	wantClean(t, checkProto(clean, "R1", "x", []string{"AG1", "AG2", "AG3", "AG8"}))
	wantClean(t, checkProto(clean, "R2", "x", []string{"AG4", "AG5"}))
	wantClean(t, checkProto(clean, "R5", "x", []string{"AG6", "AG7"}))

	// A denied verb (TM-D13: exec) added to the host.
	denied := protoTree(t, strings.Replace(hostProto, "service Host {", "service Host { rpc RunCommand(Empty) returns (Status);", 1), addcProto)
	wantViolation(t, checkProto(denied, "R1", "x", []string{"AG1", "AG2", "AG3", "AG8"}), "AG2")
	// An RPC outside the golden list, even with a harmless name.
	extra := protoTree(t, hostProto, strings.Replace(addcProto, "service Addc {", "service Addc { rpc Ping(Empty) returns (Empty);", 1))
	wantViolation(t, checkProto(extra, "R1", "x", []string{"AG1", "AG2", "AG3", "AG8"}), "AG1")
	// A path in the policy.
	path := protoTree(t, hostProto, strings.Replace(addcProto, "bool collection_enabled = 2;", "bool collection_enabled = 2; string log_path = 3;", 1))
	wantViolation(t, checkProto(path, "R2", "x", []string{"AG4", "AG5"}), "AG4")
	// A password in the surface.
	pw := protoTree(t, hostProto, strings.Replace(addcProto, "bool collection_enabled = 2;", "bool collection_enabled = 2; uint32 password_hash = 3;", 1))
	wantViolation(t, checkProto(pw, "R5", "x", []string{"AG6", "AG7"}), "AG6")
	// A rule's violation is reported only under its own check.
	if r := checkProto(pw, "R2", "x", []string{"AG4", "AG5"}); len(r.Violations) != 0 {
		t.Fatalf("R2 reported an R5 violation: %v", r.Violations)
	}
}

func TestR3ModuleCapabilities(t *testing.T) {
	root := t.TempDir()
	write(t, root, "internal/agentmodules/addc/ok.go", "package addc\n\nimport \"strings\"\n\nvar _ = strings.ToLower\n")
	wantClean(t, checkModuleCapabilities(root))
	for name, src := range map[string]string{
		"os/exec":      "package addc\n\nimport \"os/exec\"\n\nvar _ = exec.Command\n",
		"registry":     "package addc\n\nimport \"golang.org/x/sys/windows/registry\"\n\nvar _ = registry.LOCAL_MACHINE\n",
		"service mgr":  "package addc\n\nimport \"golang.org/x/sys/windows/svc/mgr\"\n\nvar _ = mgr.Connect\n",
		"os.WriteFile": "package addc\n\nimport \"os\"\n\nfunc f() { _ = os.WriteFile(\"x\", nil, 0) }\n",
		"os.RemoveAll": "package addc\n\nimport \"os\"\n\nfunc f() { _ = os.RemoveAll(\"x\") }\n",
	} {
		bad := t.TempDir()
		write(t, bad, "internal/agentmodules/addc/bad.go", src)
		r := checkModuleCapabilities(bad)
		if len(r.Violations) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestR4NoListener(t *testing.T) {
	root := t.TempDir()
	write(t, root, "cmd/agent/main.go", "package main\n\nfunc main() {}\n")
	wantClean(t, checkNoListener(root))
	for name, src := range map[string]string{
		"net.Listen":            "package main\n\nimport \"net\"\n\nfunc main() { _, _ = net.Listen(\"tcp\", \":1\") }\n",
		"ListenAndServe":        "package main\n\nimport \"net/http\"\n\nfunc main() { _ = http.ListenAndServe(\":1\", nil) }\n",
		"server ListenAndServe": "package main\n\nimport \"net/http\"\n\nfunc main() { s := &http.Server{}; _ = s.ListenAndServe() }\n",
		"httptest":              "package main\n\nimport \"net/http/httptest\"\n\nvar _ = httptest.NewServer\n\nfunc main() {}\n",
	} {
		bad := t.TempDir()
		write(t, bad, "cmd/agent/main.go", src)
		if r := checkNoListener(bad); len(r.Violations) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestA1Installer(t *testing.T) {
	if r := checkInstaller(t.TempDir()); r.Inactive == "" {
		t.Fatal("A1 must be inactive, not passing, without installer source")
	}
	mk := func(body string) Result {
		root := t.TempDir()
		write(t, root, "packaging/windows/agent.wxs", body)
		return checkInstaller(root)
	}
	wantClean(t, mk(goodWxs))
	wantViolation(t, mk(strings.Replace(goodWxs, `NT SERVICE\activeDIQAgent`, `LocalSystem`, 1)), "LocalSystem")
	wantViolation(t, mk(strings.Replace(goodWxs, `Start="auto"`, `Start="auto"><!-- runs as LocalSystem --><X`, 1)+"</Wix>"), "LocalSystem")
	wantViolation(t, mk(strings.Replace(goodWxs, `NT SERVICE\activeDIQAgent`, `NT AUTHORITY\NetworkService`, 1)), "Account")
	wantViolation(t, mk(strings.Replace(goodWxs, `NT SERVICE\activeDIQAgent`, `NT SERVICE\SomethingElse`, 1)), "Account is")
	wantViolation(t, mk(strings.Replace(goodWxs, `ServiceSid="restricted"`, `ServiceSid="unrestricted"`, 1)), "service SID type")
	wantViolation(t, mk(strings.Replace(goodWxs, ` ServiceSid="restricted"`, ``, 1)), "service SID type")
	wantViolation(t, mk(strings.Replace(goodWxs, `SeChangeNotifyPrivilege"`, `SeChangeNotifyPrivilege SeBackupPrivilege"`, 1)), "RequiredPrivileges")
	wantViolation(t, mk(strings.Replace(goodWxs, ` RequiredPrivileges="SeChangeNotifyPrivilege"`, ``, 1)), "RequiredPrivileges")
	wantViolation(t, mk(strings.Replace(goodWxs, `Start="auto"`, `Start="auto" Password="x"`, 1)), "Password")
	wantViolation(t, mk(`<Wix><Package/></Wix>`), "no ServiceInstall")
	// The agent is found by its body when the file name does not say so.
	root := t.TempDir()
	write(t, root, "packaging/windows/product.wxs", strings.Replace(goodWxs, `NT SERVICE\activeDIQAgent`, `LocalSystem`, 1))
	wantViolation(t, checkInstaller(root), "LocalSystem")
}

func TestA4Judge(t *testing.T) {
	clean := []string{"fmt", "crypto/tls", "google.golang.org/grpc", "github.com/skenzeriq/activediq/internal/platform/agentpolicy"}
	if v := judgeDeps(clean); len(v) != 0 {
		t.Fatalf("clean closure rejected: %v", v)
	}
	for _, bad := range []string{
		"github.com/go-ldap/ldap/v3", "github.com/go-krb5/krb5/client", "github.com/alexbrainman/sspi/negotiate",
		"github.com/skenzeriq/activediq/internal/directory/client", "github.com/skenzeriq/activediq/internal/connector/ad",
		"golang.org/x/sys/windows/registry",
	} {
		if v := judgeDeps(append([]string{"fmt"}, bad)); len(v) == 0 {
			t.Errorf("%s accepted in the agent closure", bad)
		}
	}
}

func TestA4RealClosure(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", "module fx.test\n\ngo 1.22\n")
	write(t, root, "cmd/agent/main.go", "package main\n\nfunc main() {}\n")
	wantClean(t, checkAgentImports(root))
	write(t, root, "internal/directory/client/c.go", "package client\n")
	write(t, root, "cmd/agent/main.go", "package main\n\nimport _ \"fx.test/internal/directory/client\"\n\nfunc main() {}\n")
	wantViolation(t, checkAgentImports(root), "internal/directory/client")
}

func TestJudgeTests(t *testing.T) {
	const pa = "github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	const ps = pa + "/signer"
	ev := func(pkg, test, action string) string {
		return `{"Action":"` + action + `","Package":"` + pkg + `","Test":"` + test + `"}` + "\n"
	}
	all := func(skip map[string]string) string {
		var b strings.Builder
		for _, rt := range requiredTests {
			pkg := pa
			if rt.ID == "P8" {
				pkg = ps
			}
			act := "pass"
			if a, ok := skip[rt.Prefix]; ok {
				if a == "missing" {
					continue
				}
				act = a
			}
			b.WriteString(ev(pkg, rt.Prefix+"Something", act))
		}
		return b.String()
	}
	if v := judgeTests([]byte(all(nil))); len(v) != 0 {
		t.Fatalf("clean run rejected: %v", v)
	}
	for _, c := range []struct{ prefix, action, want string }{
		{"TestP1", "fail", "P1"},    // wrong-tenant policy accepted
		{"TestP2", "fail", "P2"},    // replay accepted
		{"TestP3", "skip", "P3"},    // skipped is not passed
		{"TestP8", "missing", "P8"}, // deleted test
		{"TestF1", "fail", "F1"},    // out-of-bounds policy accepted
		{"FuzzF1", "missing", "F1"}, // fuzz target removed
	} {
		v := judgeTests([]byte(all(map[string]string{c.prefix: c.action})))
		if len(v) == 0 || !strings.HasPrefix(v[0], c.want) {
			t.Errorf("%s %s: want %s violation, got %v", c.prefix, c.action, c.want, v)
		}
	}
	// A failing subtest fails its parent even when the parent line says pass.
	sub := all(nil) + ev(pa, "TestF1OutOfBoundsPolicyRejected/min_length_0", "fail")
	if v := judgeTests([]byte(sub)); len(v) == 0 {
		t.Fatal("failing subtest ignored")
	}
}

func TestRunOnRepositoryTreeIsConsistent(t *testing.T) {
	// The real tree: every check either runs clean or says why it is inactive.
	res := Run("../../..", Options{SkipTests: true, Only: "R3,R4,A1,A4"})
	for _, r := range res {
		if len(r.Violations) != 0 {
			t.Errorf("%s: %v", r.ID, r.Violations)
		}
	}
}
