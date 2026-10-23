package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// base is a clean contract: one RPC, its Operation value, APPLY and the two reserved names.
const base = `syntax = "proto3";
package t.v1;
enum Operation {
  OPERATION_UNSPECIFIED = 0;
  OPERATION_READ_PER_DC = 1;
  OPERATION_APPLY = 100;
  OPERATION_READ_SECRET = 101;
  OPERATION_VERIFY_USER = 102;
}
message Guid { bytes value = 1; }
message ReadPerDCRequest { Guid guid = 1; }
message ReadPerDCResponse { string note = 1; }
service S { rpc ReadPerDC(ReadPerDCRequest) returns (stream ReadPerDCResponse); }
`

func lint(t *testing.T, src string) ([]Violation, error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "t.proto"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := Compile(dir)
	if err != nil {
		return nil, err
	}
	return Lint(files), nil
}

func rules(vs []Violation) string {
	var r []string
	for _, v := range vs {
		r = append(r, v.Rule)
	}
	return strings.Join(r, ",")
}

func TestCleanContractPasses(t *testing.T) {
	vs, err := lint(t, base)
	if err != nil || len(vs) != 0 {
		t.Fatalf("want clean, got %v %v", vs, err)
	}
}

func TestRepositoryContractPasses(t *testing.T) {
	files, err := Compile("../../../proto")
	if err != nil {
		t.Fatal(err)
	}
	if vs := Lint(files); len(vs) != 0 {
		t.Fatalf("proto/ violates its own rules: %v", vs)
	}
}

func TestViolations(t *testing.T) {
	cases := []struct {
		name, rule string
		src        string
	}{
		{"P2 dn text in a request", "P2", strings.Replace(base, "message ReadPerDCRequest { Guid guid = 1; }", "message ReadPerDCRequest { Guid guid = 1; string dn = 2; }", 1)},
		{"P2 filter text nested in a request", "P2", strings.Replace(base, "message ReadPerDCRequest { Guid guid = 1; }", "message Inner { string ldap_filter = 1; }\nmessage ReadPerDCRequest { Inner inner = 1; }", 1)},
		{"P2 tenant in a request", "P2", strings.Replace(base, "message ReadPerDCRequest { Guid guid = 1; }", "message ReadPerDCRequest { string tenant_id = 1; }", 1)},
		{"P3 Any in a request", "P3", strings.Replace(strings.Replace(base, "package t.v1;", "package t.v1;\nimport \"google/protobuf/any.proto\";", 1), "message ReadPerDCRequest { Guid guid = 1; }", "message ReadPerDCRequest { google.protobuf.Any a = 1; }", 1)},
		{"P4 client streaming", "P4", strings.Replace(base, "rpc ReadPerDC(ReadPerDCRequest)", "rpc ReadPerDC(stream ReadPerDCRequest)", 1)},
		{"P5 rpc without an Operation value", "P5", strings.Replace(base, "service S {", "message XRequest {}\nservice S { rpc Extra(XRequest) returns (ReadPerDCResponse);", 1)},
		{"P6 reserved name missing", "P6", strings.Replace(base, "  OPERATION_VERIFY_USER = 102;\n", "", 1)},
		{"P6 reserved name has an rpc", "P6", strings.Replace(base, "service S {", "message ReadSecretRequest {}\nservice S { rpc ReadSecret(ReadSecretRequest) returns (ReadPerDCResponse);", 1)},
		{"P6 APPLY value removed", "P6", strings.Replace(base, "  OPERATION_APPLY = 100;\n", "", 1)},
		{"P8 Apply without Tier0Context", "P8", strings.Replace(base, "service S {", "message ApplyRequest { Guid target = 1; }\nservice S { rpc Apply(ApplyRequest) returns (ReadPerDCResponse);", 1)},
		{"P8 Plan with a repeated Tier0Context", "P8", strings.Replace(strings.Replace(base, "  OPERATION_APPLY = 100;", "  OPERATION_PLAN = 7;\n  OPERATION_APPLY = 100;", 1), "service S {", "message Tier0Context {}\nmessage PlanRequest { repeated Tier0Context t = 1; }\nservice S { rpc Plan(PlanRequest) returns (ReadPerDCResponse);", 1)},
		{"P8 Tier0Context with a single CorrelationStatement", "P8", strings.Replace(strings.Replace(base, "  OPERATION_APPLY = 100;", "  OPERATION_PLAN = 7;\n  OPERATION_APPLY = 100;", 1), "service S {", "message CorrelationStatement {}\nmessage Tier0Context { CorrelationStatement correlation = 1; }\nmessage PlanRequest { Tier0Context t = 1; }\nservice S { rpc Plan(PlanRequest) returns (ReadPerDCResponse);", 1)},
		{"P7 secret as plain text", "P7", strings.Replace(base, "message ReadPerDCResponse { string note = 1; }", "message ReadPerDCResponse { bytes unicode_pwd = 1; }", 1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vs, err := lint(t, c.src)
			if err != nil {
				t.Fatalf("fixture must compile: %v", err)
			}
			if !strings.Contains(rules(vs), c.rule) {
				t.Fatalf("want a %s violation, got %q", c.rule, rules(vs))
			}
		})
	}
}

func TestWriteGroupWithTier0ContextPasses(t *testing.T) {
	src := strings.Replace(strings.Replace(base, "  OPERATION_APPLY = 100;", "  OPERATION_PLAN = 7;\n  OPERATION_APPLY = 100;", 1), "service S {",
		"message CorrelationStatement {}\nmessage Tier0Context { repeated CorrelationStatement statements = 1; }\nmessage PlanRequest { Tier0Context tier0 = 1; }\nmessage ApplyRequest { Tier0Context tier0 = 1; }\n"+
			"service S { rpc Plan(PlanRequest) returns (ReadPerDCResponse); rpc Apply(ApplyRequest) returns (ReadPerDCResponse);", 1)
	vs, err := lint(t, src)
	if err != nil || len(vs) != 0 {
		t.Fatalf("want clean, got %v %v", vs, err)
	}
}

func TestSyntaxErrorFails(t *testing.T) {
	if _, err := lint(t, "syntax = \"proto3\";\nmessage {"); err == nil {
		t.Fatal("a file that does not compile must fail P1")
	}
}

func TestScreamingSnake(t *testing.T) {
	for in, want := range map[string]string{"Describe": "DESCRIBE", "ReadPerDC": "READ_PER_DC", "ScopedSearch": "SCOPED_SEARCH", "VerifyUser": "VERIFY_USER", "VerifyConnection": "VERIFY_CONNECTION", "Plan": "PLAN", "Apply": "APPLY", "ChangeFeed": "CHANGE_FEED"} {
		if got := screamingSnake(in); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

var r = strings.Replace

// fleetBase is a clean fleet contract.
const fleetBase = `syntax = "proto3";
package activediq.fleet.v1;
message EnrollRequest { string enrollment_token = 1; bytes csr_der = 2; }
message EnrollResponse { bytes leaf_certificate_der = 1; bytes ca_bundle_pem = 2; }
message TunnelFrame { uint64 call_id = 1; bytes payload = 2; }
service Fleet {
  rpc Enroll(EnrollRequest) returns (EnrollResponse);
  rpc Tunnel(stream TunnelFrame) returns (stream TunnelFrame);
}
`

func TestFleetCleanPasses(t *testing.T) {
	vs, err := lint(t, fleetBase)
	if err != nil || len(vs) != 0 {
		t.Fatalf("want clean, got %v %v", vs, err)
	}
}

func TestFleetViolations(t *testing.T) {
	cases := []struct{ name, rule, src string }{
		{"F1 extra rpc", "F1", r(fleetBase, "service Fleet {", "message PingRequest {}\nservice Fleet { rpc Ping(PingRequest) returns (EnrollResponse);", 1)},
		{"F1 tunnel not bidirectional", "F1", r(fleetBase, "rpc Tunnel(stream TunnelFrame) returns (stream TunnelFrame)", "rpc Tunnel(TunnelFrame) returns (stream TunnelFrame)", 1)},
		{"F1 tunnel missing", "F1", r(fleetBase, "  rpc Tunnel(stream TunnelFrame) returns (stream TunnelFrame);\n", "", 1)},
		{"F1 second service", "F1", fleetBase + "service Other { rpc X(EnrollRequest) returns (EnrollResponse); }\n"},
		{"F5 streaming enroll", "F5", r(fleetBase, "rpc Enroll(EnrollRequest)", "rpc Enroll(stream EnrollRequest)", 1)},
		{"F2 tenant in a request", "F2", r(fleetBase, "bytes csr_der = 2;", "bytes csr_der = 2; string tenant_id = 3;", 1)},
		{"F2 tenant in a response", "F2", r(fleetBase, "bytes ca_bundle_pem = 2;", "bytes ca_bundle_pem = 2; string tenant = 3;", 1)},
		{"F3 private key in the response", "F3", r(fleetBase, "bytes ca_bundle_pem = 2;", "bytes ca_bundle_pem = 2; bytes private_key_der = 3;", 1)},
		{"F3 password in a frame", "F3", r(fleetBase, "bytes payload = 2;", "bytes payload = 2; string password = 3;", 1)},
		{"F3 second token", "F3", r(fleetBase, "bytes payload = 2;", "bytes payload = 2; string session_token = 3;", 1)},
		{"F3 token moved to another message", "F3", r(fleetBase, "bytes payload = 2;", "bytes payload = 2; string enrollment_token = 3;", 1)},
		{"F9 secret-named message with innocuous fields", "F9", fleetBase + "message PasswordPush { bytes blob = 1; }\n"},
		{"F9 credential-named message used in a frame", "F9", r(fleetBase, "message TunnelFrame {", "message CredentialEnvelope { uint32 n = 1; }\nmessage TunnelFrame { CredentialEnvelope env = 3;", 1)},
		{"F3 nested message", "F3", r(fleetBase, "message TunnelFrame {", "message Inner { string api_key = 1; }\nmessage TunnelFrame { Inner inner = 3;", 1)},
		{"F4 no CA bundle", "F4", r(fleetBase, "bytes ca_bundle_pem = 2;", "bytes other = 2;", 1)},
		{"F4 no leaf", "F4", r(fleetBase, "bytes leaf_certificate_der = 1;", "bytes cert = 1;", 1)},
		{"F5 Any", "F5", r(r(fleetBase, "package activediq.fleet.v1;", "package activediq.fleet.v1;\nimport \"google/protobuf/any.proto\";", 1), "bytes payload = 2;", "google.protobuf.Any payload = 2;", 1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vs, err := lint(t, c.src)
			if err != nil {
				t.Fatalf("fixture must compile: %v", err)
			}
			if !strings.Contains(rules(vs), c.rule) {
				t.Fatalf("want a %s violation, got %q", c.rule, rules(vs))
			}
		})
	}
}

// lintMany compiles several files (name -> source) in one directory.
func lintMany(t *testing.T, srcs map[string]string) []Violation {
	t.Helper()
	dir := t.TempDir()
	for n, s := range srcs {
		p := filepath.Join(dir, n)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := Compile(dir)
	if err != nil {
		t.Fatalf("fixture must compile: %v", err)
	}
	return Lint(files)
}

const foreignCtx = `syntax = "proto3";
package x.common.v1;
message Ctx { string tenant_id = 1; string session_token = 2; bytes private_key_der = 3; }
message Plain { string note = 1; }
`

// TestFleetImportedTypes: a foreign message cannot smuggle a tenant or a secret into a fleet
// message (security-architect review of T-0152).
func TestFleetImportedTypes(t *testing.T) {
	imp := strings.Replace(fleetBase, "package activediq.fleet.v1;", "package activediq.fleet.v1;\nimport \"x/common.proto\";", 1)
	cases := []struct{ name, want, src string }{
		{"imported tenant, token and key in a response", "F2,F3,F6", r(imp, "bytes ca_bundle_pem = 2;", "bytes ca_bundle_pem = 2; x.common.v1.Ctx ctx = 3;", 1)},
		{"imported plain message", "F6", r(imp, "bytes ca_bundle_pem = 2;", "bytes ca_bundle_pem = 2; x.common.v1.Plain plain = 3;", 1)},
		{"imported type nested in a frame", "F6", r(imp, "bytes payload = 2;", "bytes payload = 2; x.common.v1.Plain plain = 3;", 1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vs := lintMany(t, map[string]string{"f.proto": c.src, "x/common.proto": foreignCtx})
			got := rules(vs)
			for _, w := range strings.Split(c.want, ",") {
				if !strings.Contains(got, w) {
					t.Fatalf("want %s, got %q", w, got)
				}
			}
		})
	}
}

func TestFleetEnrollResponseAllowlist(t *testing.T) {
	vs, err := lint(t, r(fleetBase, "bytes ca_bundle_pem = 2;", "bytes ca_bundle_pem = 2; bytes leaf_pkcs12 = 3;", 1))
	if err != nil || !strings.Contains(rules(vs), "F4") {
		t.Fatalf("want F4, got %q (%v)", rules(vs), err)
	}
}

// TestFleetExactPackage: only activediq.fleet.v1 gets the fleet rules; look-alikes are checked as
// operation contracts (P4 refuses their bidirectional stream).
func TestFleetExactPackage(t *testing.T) {
	src := strings.Replace(fleetBase, "package activediq.fleet.v1;", "package activediq.connector.fleet.v1;", 1)
	vs, err := lint(t, src)
	if err != nil || !strings.Contains(rules(vs), "P4") || strings.Contains(rules(vs), "F") {
		t.Fatalf("want P rules only, got %q (%v)", rules(vs), err)
	}
}

// TestFleetMapsAndResponseClosure: maps (F7) and messages under allowlisted response fields (F4)
// cannot smuggle data (second security-architect review of T-0152).
func TestFleetMapsAndResponseClosure(t *testing.T) {
	imp := strings.Replace(fleetBase, "package activediq.fleet.v1;", "package activediq.fleet.v1;\nimport \"x/common.proto\";", 1)
	withEndpoint := func(ep string) string {
		return r(r(fleetBase, "bytes ca_bundle_pem = 2;", "bytes ca_bundle_pem = 2; repeated Endpoint endpoints = 3;", 1), "service Fleet {", ep+"\nservice Fleet {", 1)
	}
	cases := []struct{ name, want, src string }{
		{"map of foreign messages on a frame", "F7", r(imp, "bytes payload = 2;", "bytes payload = 2; map<string, x.common.v1.Ctx> ext = 3;", 1)},
		{"map of strings on a frame", "F7", r(fleetBase, "bytes payload = 2;", "bytes payload = 2; map<string, string> headers = 3;", 1)},
		{"extra field on Endpoint", "F4", withEndpoint("message Endpoint { string host = 1; uint32 port = 2; bytes pkcs8 = 3; }")},
		{"Endpoint port retyped", "F4", withEndpoint("message Endpoint { string host = 1; bytes port = 2; }")},
		{"leaf redeclared as a message", "F4", r(fleetBase, "bytes leaf_certificate_der = 1;", "Leaf leaf_certificate_der = 1;", 1) + "message Leaf { bytes cert = 1; bytes pkcs8 = 2; }\n"},
		{"renamed Enroll output with a pkcs12 blob", "F4", r(r(fleetBase, "EnrollResponse", "Issued", -1), "bytes ca_bundle_pem = 2;", "bytes ca_bundle_pem = 2; bytes leaf_pkcs12 = 3;", 1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vs := lintMany(t, map[string]string{"f.proto": c.src, "x/common.proto": foreignCtx})
			if !strings.Contains(rules(vs), c.want) {
				t.Fatalf("want %s, got %q", c.want, rules(vs))
			}
		})
	}
	// The real shape of Endpoint passes.
	vs := lintMany(t, map[string]string{"f.proto": withEndpoint("message Endpoint { string host = 1; uint32 port = 2; }")})
	if len(vs) != 0 {
		t.Fatalf("want clean, got %v", vs)
	}
}

// TestFleetExtensionsRPCTypesNestedToken: third security-architect review of T-0152.
func TestFleetExtensionsRPCTypesNestedToken(t *testing.T) {
	ed := r(fleetBase, `syntax = "proto3";`, `edition = "2023";`, 1)
	imp := func(s string) string {
		return r(s, "package activediq.fleet.v1;", "package activediq.fleet.v1;\nimport \"x/common.proto\";", 1)
	}
	cases := []struct {
		name, want string
		files      map[string]string
	}{
		{"edition with extensions on the response", "F8", map[string]string{"f.proto": r(r(ed, "message EnrollResponse {", "message EnrollResponse { extensions 100 to 200;", 1), "service Fleet {", "extend EnrollResponse { bytes pkcs8 = 100; string tenant_id = 101; }\nservice Fleet {", 1)}},
		{"extension from another package", "F8", map[string]string{
			"f.proto":   r(ed, "message EnrollResponse {", "message EnrollResponse { extensions 100 to 200;", 1),
			"x/e.proto": "edition = \"2023\";\npackage x.ext.v1;\nimport \"f.proto\";\nextend activediq.fleet.v1.EnrollResponse { bytes pkcs8 = 100; }\n"}},
		{"foreign tunnel types", "F6", map[string]string{"f.proto": r(imp(fleetBase), "rpc Tunnel(stream TunnelFrame) returns (stream TunnelFrame)", "rpc Tunnel(stream x.common.v1.Plain) returns (stream x.common.v1.Plain)", 1), "x/common.proto": foreignCtx}},
		{"foreign enroll input", "F6", map[string]string{"f.proto": r(imp(fleetBase), "rpc Enroll(EnrollRequest)", "rpc Enroll(x.common.v1.Plain)", 1), "x/common.proto": foreignCtx}},
		{"nested EnrollRequest with a token", "F3", map[string]string{"f.proto": r(fleetBase, "message TunnelFrame {", "message TunnelFrame { message EnrollRequest { string enrollment_token = 1; }", 1)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rules(lintMany(t, c.files)); !strings.Contains(got, c.want) {
				t.Fatalf("want %s, got %q", c.want, got)
			}
		})
	}
}

// TestFleetViolationMessages: the failure names the message and field (TM-TB6-T6), and a new RPC
// points at the ADR it needs.
func TestFleetViolationMessages(t *testing.T) {
	vs, err := lint(t, r(fleetBase, "bytes payload = 2;", "bytes payload = 2; string password = 3;", 1))
	if err != nil || !strings.Contains(vs[0].String(), "activediq.fleet.v1.TunnelFrame.password") {
		t.Fatalf("want message and field named, got %v %v", vs, err)
	}
	vs, err = lint(t, r(fleetBase, "service Fleet {", "message PingRequest {}\nservice Fleet { rpc Ping(PingRequest) returns (EnrollResponse);", 1))
	if err != nil || !strings.Contains(vs[0].String(), "new ADR") {
		t.Fatalf("want an ADR pointer, got %v %v", vs, err)
	}
}
