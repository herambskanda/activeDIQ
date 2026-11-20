package ad_test

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/modules/ad"
	"github.com/skenzeriq/activediq/internal/platform/operation"
)

// The contract tests of the object-write HTTP surface (T-1595, ADR-0004 rule 14). They read the bundled
// OpenAPI document and judge it against the Actions the module registers, so an Action with no
// operation, a permission that drifts from its Descriptor, or a missing undo pair fails here.

type specOp struct {
	Description string `json:"description"`
	Permission  string `json:"x-permission"`
	Params      []struct {
		Ref string `json:"$ref"`
	} `json:"parameters"`
	Responses map[string]json.RawMessage `json:"responses"`
	Request   json.RawMessage            `json:"requestBody"`
}

type spec struct {
	Paths      map[string]map[string]specOp `json:"paths"`
	Components struct {
		Schemas map[string]json.RawMessage `json:"schemas"`
	} `json:"components"`
}

func loadSpec(t *testing.T) spec {
	t.Helper()
	b, err := os.ReadFile("../../platform/apihost/spec/openapi.gen.json")
	if err != nil {
		t.Fatal(err)
	}
	var s spec
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func actionDescriptors(t *testing.T) []operation.Descriptor {
	t.Helper()
	var all []operation.Action
	a, err := ad.Actions(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	all = append(all, a...)
	l, err := ad.LifecycleActions(ad.LifecyclePorts{})
	if err != nil {
		t.Fatal(err)
	}
	all = append(all, l...)
	m, err := ad.MemberActions(ad.LifecyclePorts{})
	if err != nil {
		t.Fatal(err)
	}
	all = append(all, m...)
	var out []operation.Descriptor
	for _, x := range all {
		out = append(out, x.Describe())
	}
	return out
}

// forward and twin find the write and its preview twin of an Action: the operation whose description names it.
func find(s spec, id operation.ActionID) (write, twin string) {
	for p, ms := range s.Paths {
		for _, o := range ms {
			if !strings.Contains(o.Description, "the Action "+string(id)+" (ADR-0004 rule 14)") {
				continue
			}
			if strings.Contains(p, "/previews/") {
				twin = p
			} else {
				write = p
			}
		}
	}
	return
}

// AC1: every registered Action has a write and a preview twin, each with exactly the Descriptor's one
// x-permission, the same parameters, and the write answers the operation reference and the undo handle.
func TestEveryActionHasWriteAndPreviewTwinWithItsPermission(t *testing.T) {
	s := loadSpec(t)
	ds := actionDescriptors(t)
	if len(ds) < 30 {
		t.Fatalf("only %d Actions registered", len(ds))
	}
	for _, d := range ds {
		w, p := find(s, d.ID)
		if w == "" || p == "" {
			t.Errorf("%s: write %q, preview twin %q: both must exist", d.ID, w, p)
			continue
		}
		wo, po := s.Paths[w]["post"], s.Paths[p]["post"]
		if wo.Permission != string(d.Permission) || po.Permission != string(d.Permission) {
			t.Errorf("%s: write binds %q, twin %q, Descriptor %q", d.ID, wo.Permission, po.Permission, d.Permission)
		}
		var wp, pp []string
		for _, x := range wo.Params {
			wp = append(wp, x.Ref)
		}
		for _, x := range po.Params {
			pp = append(pp, x.Ref)
		}
		wp = slices.DeleteFunc(wp, func(r string) bool { return strings.HasSuffix(r, "/ObjectWriteKey") })
		if !slices.Equal(wp, pp) {
			t.Errorf("%s: twin parameters %v differ from the write's %v", d.ID, pp, wp)
		}
		if !strings.Contains(string(wo.Responses["200"]), "ActiveDIQ-Operation-Id") || !strings.Contains(string(wo.Responses["202"]), "OperationRef") {
			t.Errorf("%s: the write must answer 200 with ActiveDIQ-Operation-Id and 202 OperationRef", d.ID)
		}
		if !strings.Contains(string(po.Responses["200"]), "OperationPreview") {
			t.Errorf("%s: the twin must answer the shared OperationPreview", d.ID)
		}
	}
}

// AC1: every Action family (class) has the undo pair, bound to the family's update permission.
func TestEveryFamilyHasAnUndoPair(t *testing.T) {
	s := loadSpec(t)
	for _, seg := range []string{"user", "group", "computer", "contact", "ou"} {
		plural := map[string]string{"user": "users", "group": "groups", "computer": "computers", "contact": "contacts", "ou": "ous"}[seg]
		for _, suffix := range []string{"/undo", "/previews/undo"} {
			p := "/objects/" + plural + "/operations/{operationId}" + suffix
			if suffix == "/undo" {
				p = "/objects/" + plural + "/operations/{operationId}/undo"
			}
			o, ok := s.Paths[p]["post"]
			if !ok {
				t.Errorf("missing %s", p)
				continue
			}
			if o.Permission != "objects."+seg+".update" {
				t.Errorf("%s binds %q", p, o.Permission)
			}
		}
	}
}

// AC2: a write on an existing object demands If-Match and answers 412 and 428 (ADR-0004 rule 14; a stale
// value is refused, an absent one is refused, as on the existing writes); every write demands Idempotency-Key.
func TestTargetWritesDemandIfMatchAndEveryWriteAnIdempotencyKey(t *testing.T) {
	s := loadSpec(t)
	n := 0
	for p, ms := range s.Paths {
		if !strings.HasPrefix(p, "/objects/") || strings.Contains(p, "/operations/") {
			continue
		}
		o := ms["post"]
		target := strings.Contains(p, "{objectGuid}")
		hasIfMatch, hasKey := false, false
		for _, x := range o.Params {
			hasIfMatch = hasIfMatch || strings.HasSuffix(x.Ref, "/ObjectIfMatch")
			hasKey = hasKey || strings.HasSuffix(x.Ref, "/ObjectWriteKey")
		}
		if target != hasIfMatch {
			t.Errorf("%s: target %v but If-Match %v", p, target, hasIfMatch)
		}
		if target && (o.Responses["412"] == nil || o.Responses["428"] == nil) {
			t.Errorf("%s: must declare 412 and 428", p)
		}
		if !strings.Contains(p, "/previews/") && !hasKey {
			t.Errorf("%s: a write needs Idempotency-Key", p)
		}
		n++
	}
	if n < 60 {
		t.Fatalf("only %d object operations", n)
	}
}

// AC3: resetPassword's password is write-only and no response schema (the operation reference, the preview, the
// diff values) has a place to carry a secret: values are text, list, integer, boolean, time, redacted or absent.
func TestResetPasswordNeverCarriesThePasswordBack(t *testing.T) {
	s := loadSpec(t)
	body := string(s.Components.Schemas["UserResetPasswordBody"])
	if !strings.Contains(body, `"#/components/schemas/SecretInput"`) || !strings.Contains(body, "newPassword") {
		t.Fatalf("newPassword must be a SecretInput: %s", body)
	}
	var si struct {
		WriteOnly bool `json:"writeOnly"`
	}
	if err := json.Unmarshal(s.Components.Schemas["SecretInput"], &si); err != nil || !si.WriteOnly {
		t.Fatalf("SecretInput must be write-only: %v %s", err, s.Components.Schemas["SecretInput"])
	}
	for _, name := range []string{"OperationPreview", "OperationRef", "OperationStepPreview", "OperationChange"} {
		raw := strings.ToLower(string(s.Components.Schemas[name]))
		if raw == "" || strings.Contains(raw, "password") || strings.Contains(raw, "secret") && !strings.Contains(raw, "redacted") {
			t.Errorf("%s may not name a password or secret member: %s", name, raw)
		}
	}
	var v struct {
		OneOf []struct {
			Ref string `json:"$ref"`
		} `json:"oneOf"`
	}
	if err := json.Unmarshal(s.Components.Schemas["OperationValue"], &v); err != nil || len(v.OneOf) != 7 {
		t.Fatalf("OperationValue must stay the seven redactable variants: %v %s", err, s.Components.Schemas["OperationValue"])
	}
	for _, p := range []string{"/objects/users/{objectGuid}/reset-password", "/objects/users/{objectGuid}/previews/reset-password"} {
		o := s.Paths[p]["post"]
		if !strings.Contains(o.Description, "rreversible") {
			t.Errorf("%s: description must state it is irreversible", p)
		}
	}
	// the Action itself is Irreversible and secret-input, so the preview's reversibility is irreversible.
	for _, d := range actionDescriptors(t) {
		if d.ID == ad.ResetPasswordID && (d.Reversibility != operation.Irreversible || !d.SecretInput || !d.StepUp) {
			t.Errorf("resetPassword Descriptor: %+v", d)
		}
	}
}
