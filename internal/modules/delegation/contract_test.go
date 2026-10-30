package delegation_test

import (
	"encoding/json"
	"strings"
	"testing"

	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"

	"github.com/skenzeriq/activediq/internal/modules/delegation"
	dapi "github.com/skenzeriq/activediq/internal/modules/delegation/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
)

const (
	id1 = "11111111-1111-4111-8111-111111111111"
	id2 = "22222222-2222-4222-8222-222222222222"
	id3 = "33333333-3333-4333-8333-333333333333"
)

// Every delegation.* Action is a control-plane Action: the flag is on, and it agrees with the rule that
// keeps the permission out of every group, token, automation policy and hybrid correlation.
func TestDelegationActionsAreFlaggedControlPlane(t *testing.T) {
	acts, err := delegation.Actions(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[operation.ActionID]string{
		delegation.RoleCreateID: "RoleCreate", delegation.RoleUpdateID: "RoleUpdate",
		delegation.GrantID: "AssignmentGrant", delegation.RevokeID: "AssignmentRevoke",
	}
	if len(acts) != len(want) {
		t.Fatalf("got %d Actions, want %d", len(acts), len(want))
	}
	for _, a := range acts {
		d := a.Describe()
		schema, ok := want[d.ID]
		if !ok {
			t.Errorf("unexpected Action %s", d.ID)
			continue
		}
		if !d.ControlPlane {
			t.Errorf("%s is not flagged control_plane", d.ID)
		}
		if !authz.NeverCrosses(d.Permission) {
			t.Errorf("%s: permission %s is not in a never-crosses family", d.ID, d.Permission)
		}
		if d.Input != operation.SchemaRef("#/components/schemas/"+schema) {
			t.Errorf("%s: Input = %s, want schema %s", d.ID, d.Input, schema)
		}
	}
}

// roundTrip decodes a sample through the generated contract type (strict: an unknown or missing member
// fails), then through the Action's own input type, and requires both to re-encode to the same JSON.
func roundTrip[C, A any, P interface {
	*C
	validator
}](t *testing.T, sample string) {
	t.Helper()
	if n, err := check[C, P](sample); err != nil || n != 0 {
		t.Fatalf("contract refuses a valid sample (decode error %v, %d violations)\n%s", err, n, sample)
	}
	var a A
	dec := json.NewDecoder(strings.NewReader(sample))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		t.Fatalf("Action input refuses a sample the contract accepts: %v\n%s", err, sample)
	}
	got, _ := json.Marshal(a)
	var x, y any
	_ = json.Unmarshal(got, &x)
	_ = json.Unmarshal([]byte(sample), &y)
	gx, _ := json.Marshal(x)
	gy, _ := json.Marshal(y)
	if string(gx) != string(gy) {
		t.Errorf("Action input re-encodes differently:\n got %s\nwant %s", gx, gy)
	}
}

type validator interface {
	Validate(at jsontext.Pointer, errs *apitypes.Errors)
}

// check decodes a sample strictly and runs the generated schema checks (required members, bounds,
// counts, patterns). It returns the decode error or the number of violations.
func check[C any, P interface {
	*C
	validator
}](sample string) (int, error) {
	var c C
	if err := jsonv2.Unmarshal([]byte(sample), &c); err != nil {
		return 0, err
	}
	var errs apitypes.Errors
	P(&c).Validate("", &errs)
	return errs.Len(), nil
}

func refuses[C any, P interface {
	*C
	validator
}](t *testing.T, why, sample string) {
	t.Helper()
	if n, err := check[C, P](sample); err == nil && n == 0 {
		t.Errorf("contract accepts %s: %s", why, sample)
	}
}

func TestSamplePayloadsMatchTheContract(t *testing.T) {
	roundTrip[dapi.RoleCreate, delegation.RoleCreateInput, *dapi.RoleCreate](t, `{"roleId":"`+id1+`","name":"Help desk lead","tier":2,"permissions":["objects.user.reset_password"]}`)
	roundTrip[dapi.RoleUpdate, delegation.RoleUpdateInput, *dapi.RoleUpdate](t, `{"roleId":"`+id1+`","permissions":["objects.user.reset_password","objects.user.delete"]}`)
	roundTrip[dapi.AssignmentRevoke, delegation.RevokeInput, *dapi.AssignmentRevoke](t, `{"assignmentId":"`+id2+`"}`)
	roundTrip[dapi.AssignmentGrant, delegation.GrantInput, *dapi.AssignmentGrant](t, `{"assignmentId":"`+id2+`","roleId":"`+id1+`","subject":{"kind":"account","accountId":"`+id3+`"},`+
		`"roots":[{"kind":"ou_subtree","connectionId":"`+id1+`","guid":"`+id2+`"},{"kind":"ou_subtree","connectionId":"`+id1+`","guid":"`+id3+`","exclude":true}],`+
		`"validFrom":"2026-11-01T00:00:00Z","validUntil":"2027-01-01T00:00:00Z"}`)
	roundTrip[dapi.AssignmentGrant, delegation.GrantInput, *dapi.AssignmentGrant](t, `{"assignmentId":"`+id2+`","roleId":"`+id1+`","subject":{"kind":"group","connectionId":"`+id1+`","groupGuid":"`+id3+`"},`+
		`"roots":[{"kind":"tenant","connectionId":"`+id1+`","guid":"`+id2+`"}]}`)
	roundTrip[dapi.AssignmentGrant, delegation.GrantInput, *dapi.AssignmentGrant](t, `{"assignmentId":"`+id2+`","roleId":"`+id1+`","subject":{"kind":"automation","policyId":"`+id3+`"},`+
		`"roots":[{"kind":"naming_context","connectionId":"`+id1+`","guid":"`+id2+`"}]}`)
}

func TestContractRefusesMalformedPayloads(t *testing.T) {
	refuses[dapi.RoleCreate, *dapi.RoleCreate](t, "a missing tier", `{"roleId":"`+id1+`","name":"x","permissions":["a.b"]}`)
	refuses[dapi.RoleCreate, *dapi.RoleCreate](t, "an empty permission list", `{"roleId":"`+id1+`","name":"x","tier":1,"permissions":[]}`)
	refuses[dapi.RoleCreate, *dapi.RoleCreate](t, "tier 3", `{"roleId":"`+id1+`","name":"x","tier":3,"permissions":["a.b"]}`)
	refuses[dapi.RoleCreate, *dapi.RoleCreate](t, "a non-UUID roleId", `{"roleId":"admins","name":"x","tier":1,"permissions":["a.b"]}`)
	refuses[dapi.RoleCreate, *dapi.RoleCreate](t, "an unknown member", `{"roleId":"`+id1+`","name":"x","tier":1,"permissions":["a.b"],"builtIn":true}`)
	refuses[dapi.RoleCreate, *dapi.RoleCreate](t, "a snake_case member", `{"role_id":"`+id1+`","name":"x","tier":1,"permissions":["a.b"]}`)
	refuses[dapi.RoleUpdate, *dapi.RoleUpdate](t, "a malformed permission name", `{"roleId":"`+id1+`","permissions":["not a permission"]}`)
	refuses[dapi.AssignmentRevoke, *dapi.AssignmentRevoke](t, "a missing assignmentId", `{}`)
	refuses[dapi.AssignmentGrant, *dapi.AssignmentGrant](t, "no roots", `{"assignmentId":"`+id2+`","roleId":"`+id1+`","subject":{"kind":"account","accountId":"`+id3+`"},"roots":[]}`)
	refuses[dapi.AssignmentGrant, *dapi.AssignmentGrant](t, "a subject mixing kinds", `{"assignmentId":"`+id2+`","roleId":"`+id1+`","subject":{"kind":"account","accountId":"`+id3+`","groupGuid":"`+id3+`"},"roots":[{"kind":"tenant","connectionId":"`+id1+`","guid":"`+id2+`"}]}`)
	refuses[dapi.AssignmentGrant, *dapi.AssignmentGrant](t, "an unknown subject kind", `{"assignmentId":"`+id2+`","roleId":"`+id1+`","subject":{"kind":"robot"},"roots":[{"kind":"tenant","connectionId":"`+id1+`","guid":"`+id2+`"}]}`)
}
