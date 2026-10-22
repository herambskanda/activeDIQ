package apihost

import "testing"

// That the embedded JSON is current with api/openapi/policy.yaml is `make gen-api-check`'s job.
func TestEmbeddedPolicyLoads(t *testing.T) {
	p, err := LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.anonymous("getLiveness"); !ok {
		t.Error("getLiveness must be anonymous in the shipped policy")
	}
}

func TestParsePolicy(t *testing.T) {
	p, err := ParsePolicy([]byte(`{
  "anonymous": [
    {"method": "GET", "path": "/healthz"},
    {"operation": "enrol", "host": "totp-enrolment", "gate": "handle"}
  ],
  "authenticated": [{"operation": "whoami"}],
  "stepUp": [{"permission": "user.reset"}],
  "nonApiRoutes": [{"method": "GET", "path": "/x"}]
}`))
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
		"unknown host":    `{"anonymous": [{"operation": "a", "host": "nope"}]}`,
		"unknown section": `{"anonymus": [{"operation": "a"}]}`,
		"no subject":      `{"anonymous": [{"gate": "none"}]}`,
		"duplicate":       `{"anonymous": [{"operation": "a"}, {"operation": "a"}]}`,
		"auth no op":      `{"authenticated": [{"reason": "x"}]}`,
		"stepup no perm":  `{"stepUp": [{"operation": "a"}]}`,
		"not json":        `{"anonymous": [`,
		"null host":       `{"anonymous": [{"operation": "a", "host": null}]}`,
		"empty host":      `{"anonymous": [{"operation": "a", "host": ""}]}`,
		"empty operation": `{"anonymous": [{"operation": ""}]}`,
		"null gate":       `{"anonymous": [{"operation": "a", "gate": null}]}`,
		"empty perm":      `{"stepUp": [{"permission": ""}]}`,
	} {
		if _, err := ParsePolicy([]byte(in)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
