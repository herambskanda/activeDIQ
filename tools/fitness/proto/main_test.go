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
