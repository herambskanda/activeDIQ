package apihost

import (
	"bytes"
	"os"
	"testing"
)

func TestEmbeddedPolicyIsTheContractsFile(t *testing.T) {
	src, err := os.ReadFile("../../../api/openapi/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(src, embeddedPolicy) {
		t.Fatal("spec/policy.gen.yaml is stale: run make gen-api")
	}
	p, err := LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.anonymous("getLiveness"); !ok {
		t.Error("getLiveness must be anonymous in the shipped policy")
	}
}

func TestParsePolicy(t *testing.T) {
	p, err := ParsePolicy([]byte(`
anonymous:
  - method: GET
    path: /healthz
  - operation: enrol
    host: totp-enrolment
    gate: handle
authenticated:
  - operation: whoami
stepUp:
  - permission: user.reset
nonApiRoutes:
  - method: GET
    path: /x
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Anonymous) != 1 || p.Anonymous[0] != (AnonymousRow{Operation: "enrol", Host: "totp-enrolment", Gate: "handle"}) {
		t.Errorf("anonymous = %+v", p.Anonymous)
	}
	if !p.authenticated("whoami") || !p.stepUp("user.reset") {
		t.Errorf("policy = %+v", p)
	}
	for name, in := range map[string]string{
		"unknown host":    "anonymous:\n  - operation: a\n    host: nope\n",
		"unknown section": "anonymus:\n  - operation: a\n",
		"no subject":      "anonymous:\n  - gate: none\n",
		"duplicate":       "anonymous:\n  - operation: a\n  - operation: a\n",
		"auth no op":      "authenticated:\n  - reason: x\n",
		"stepup no perm":  "stepUp:\n  - operation: a\n",
		"not yaml":        "anonymous: [",
	} {
		if _, err := ParsePolicy([]byte(in)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
