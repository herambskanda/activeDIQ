package fixture

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	widgets "github.com/skenzeriq/activediq/tools/gen/api/internal/fixture/internal/modules/widgets/api"
)

// decode runs the decode path apihost will run for a body (rule 6 steps 3 and 4): strict
// json.Unmarshal into the generated type, then the generated Validate. It returns every violation,
// or the one a decoder stopped at, and the raw error when the failure is not ours.
type validator interface {
	Validate(at jsontext.Pointer, errs *apitypes.Errors)
}

func decode[T any, PT interface {
	*T
	validator
}](t *testing.T, body string) (*T, []apitypes.Violation, error) {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(body), &v, json.RejectUnknownMembers(true)); err != nil {
		if viol, ok := apitypes.ViolationOf(err); ok {
			return nil, []apitypes.Violation{viol}, nil
		}
		return nil, nil, err
	}
	var errs apitypes.Errors
	PT(&v).Validate("", &errs)
	return &v, errs.All(), nil
}

func codes(vs []apitypes.Violation) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.Code + "@" + string(v.Pointer)
	}
	return out
}

func want(t *testing.T, got []apitypes.Violation, exp ...string) {
	t.Helper()
	g := codes(got)
	if !reflect.DeepEqual(g, exp) && !(len(g) == 0 && len(exp) == 0) {
		t.Fatalf("violations\n got %q\nwant %q", g, exp)
	}
}

const validCreate = `{"name":"gizmo","size":"large","owner":"3F2504E0-4F89-11D3-9A0C-0305E82C3301","notes":null,"quota":"9007199254740993"}`

func TestCreateWidgetValid(t *testing.T) {
	v, viol, err := decode[widgets.WidgetCreate](t, `{"name":"gizmo","size":"large","owner":"3F2504E0-4F89-11D3-9A0C-0305E82C3301","notes":null,"quota":"9007199254740993",`+
		`"contact":"a@example.com","count":3,"enabled":false,"expires":"2026-02-28","starts":"2026-10-02T12:00:00+05:30","labels":{"a":"b"},"tags":["x","y-1"],"parts":[{"name":"p"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	want(t, viol)
	if v.Name != "gizmo" || v.Size != widgets.WidgetSizeLarge || v.Notes != nil || *v.Count != 3 || *v.Enabled || v.Quota != 9007199254740993 {
		t.Fatalf("decoded wrongly: %+v", v)
	}
	if v.Owner.String() != "3f2504e0-4f89-11d3-9a0c-0305e82c3301" {
		t.Fatalf("uuid must be accepted in either case and held canonically: %s", v.Owner)
	}
	if got := v.Starts.Time().UTC().Format("2006-01-02T15:04:05Z"); *v.Starts == (apitypes.Timestamp{}) || got != "2026-10-02T06:30:00Z" {
		t.Fatalf("a date-time offset must decode to UTC: %v", got)
	}
	if len(v.Labels) != 1 || len(v.Tags) != 2 || len(v.Parts) != 1 {
		t.Fatalf("collections: %+v", v)
	}
}

func TestStrictDecode(t *testing.T) {
	cases := []struct {
		name, body string
		want       []string
	}{
		{"unknown member", `{"bogus":1}`, []string{"unknown-member@/bogus"}},
		{"wrong-case member", `{"Name":"x"}`, []string{"unknown-member@/Name"}},
		{"unknown member in nested object", strings.Replace(validCreate, `"quota"`, `"parts":[{"name":"p","extra":1}],"quota"`, 1), []string{"unknown-member@/parts/0/extra"}},
		{"missing required", `{}`, []string{"required@/name", "required@/notes", "required@/owner", "required@/quota", "required@/size"}},
		{"null on a required non-nullable member", strings.Replace(validCreate, `"name":"gizmo"`, `"name":null`, 1), []string{"null@/name"}},
		{"null on an optional member", strings.Replace(validCreate, `"quota"`, `"count":null,"quota"`, 1), []string{"null@/count"}},
		{"null on an optional array", strings.Replace(validCreate, `"quota"`, `"tags":null,"quota"`, 1), []string{"null@/tags"}},
		{"required nullable member absent", `{"name":"g","size":"small","owner":"3f2504e0-4f89-11d3-9a0c-0305e82c3301","quota":"1"}`, []string{"required@/notes"}},
		{"closed enum", strings.Replace(validCreate, `"large"`, `"huge"`, 1), []string{"enum@/size"}},
		{"wrong json type", strings.Replace(validCreate, `"quota"`, `"count":"3","quota"`, 1), []string{"type@/count"}},
		{"integer above its bound", strings.Replace(validCreate, `"quota"`, `"count":101,"quota"`, 1), []string{"maximum@/count"}},
		{"length counts code points", strings.Replace(validCreate, `"gizmo"`, `"`+strings.Repeat("é", 33)+`"`, 1), []string{"max-length@/name"}},
		{"32 code points are fine", strings.Replace(validCreate, `"gizmo"`, `"`+strings.Repeat("é", 32)+`"`, 1), nil},
		{"pattern", strings.Replace(validCreate, `"quota"`, `"tags":["Bad"],"quota"`, 1), []string{"pattern@/tags/0"}},
		{"e-mail", strings.Replace(validCreate, `"quota"`, `"contact":"Bob <b@example.com>","quota"`, 1), []string{"format@/contact"}},
		{"too many properties", strings.Replace(validCreate, `"quota"`, `"labels":{"a":"1","b":"1","c":"1","d":"1","e":"1"},"quota"`, 1), []string{"max-properties@/labels"}},
		{"map value bound", strings.Replace(validCreate, `"quota"`, `"labels":{"a":"`+strings.Repeat("x", 17)+`"},"quota"`, 1), []string{"max-length@/labels/a"}},
		{"too many items", strings.Replace(validCreate, `"quota"`, `"parts":[{"name":"a"},{"name":"b"},{"name":"c"},{"name":"d"}],"quota"`, 1), []string{"max-items@/parts"}},
		{"every violation is collected", `{"name":"","size":"huge","owner":"3f2504e0-4f89-11d3-9a0c-0305e82c3301","notes":null,"quota":"1","count":-1}`,
			[]string{"minimum@/count", "min-length@/name", "enum@/size"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, viol, err := decode[widgets.WidgetCreate](t, c.body)
			if err != nil {
				t.Fatalf("not a violation: %v", err)
			}
			want(t, viol, c.want...)
		})
	}
}

func TestNullItemsAreRefused(t *testing.T) {
	for name, body := range map[string]string{
		"array item":     strings.Replace(validCreate, `"quota"`, `"tags":[null],"quota"`, 1),
		"object item":    strings.Replace(validCreate, `"quota"`, `"parts":[null],"quota"`, 1),
		"map value":      strings.Replace(validCreate, `"quota"`, `"labels":{"a":null},"quota"`, 1),
		"in a nested []": `{"filter":{"op":"x"},"rule":{"kind":"and","rules":[null]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			var viol []apitypes.Violation
			if name == "in a nested []" {
				_, viol, err = decode[widgets.WidgetSearch](t, body)
			} else {
				_, viol, err = decode[widgets.WidgetCreate](t, body)
			}
			if err != nil || len(viol) != 1 || viol[0].Code != apitypes.CodeNull {
				t.Fatalf("a null item must be a null violation: %v %v", viol, err)
			}
		})
	}
}

func TestMalformedInputIsNotAViolation(t *testing.T) {
	for name, body := range map[string]string{
		"duplicate member": `{"name":"a","name":"b"}`,
		"trailing data":    validCreate + `{}`,
		"invalid utf-8":    "{\"name\":\"\xff\"}",
		"lone surrogate":   `{"name":"\ud800"}`,
		"not json":         `{`,
	} {
		t.Run(name, func(t *testing.T) {
			_, viol, err := decode[widgets.WidgetCreate](t, body)
			if err == nil || len(viol) != 0 {
				t.Fatalf("want a raw decode error for apihost to map to malformed-request; got %v %v", viol, err)
			}
			var ve *apitypes.ViolationError
			if errors.As(err, &ve) {
				t.Fatalf("a malformed body must not look like a schema violation: %v", err)
			}
		})
	}
}

func TestOpenEnumAcceptsUnknown(t *testing.T) {
	var w widgets.Widget
	body := `{"id":"3f2504e0-4f89-11d3-9a0c-0305e82c3301","name":"g","status":"from-the-future","quota":"1","notes":null,"createdAt":"2026-10-02T00:00:00Z"}`
	if err := json.Unmarshal([]byte(body), &w, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	var errs apitypes.Errors
	w.Validate("", &errs)
	want(t, errs.All())
	if w.Status.Valid() || w.Status != "from-the-future" {
		t.Fatalf("an unknown value is carried, and Valid reports that this build does not know it: %q", w.Status)
	}
	out, err := json.Marshal(w)
	if err != nil || !strings.Contains(string(out), `"status":"from-the-future"`) {
		t.Fatalf("an open enum is never checked on encode: %s %v", out, err)
	}
}

func TestPatchStates(t *testing.T) {
	// absent, null and a value are three states.
	v, viol, err := decode[widgets.WidgetPatch](t, `{"name":"n","notes":null}`)
	if err != nil {
		t.Fatal(err)
	}
	want(t, viol)
	if val, ok := v.Name.Value(); !ok || val != "n" {
		t.Fatalf("name: %v %v", val, ok)
	}
	if !v.Notes.Present() || !v.Notes.IsNull() {
		t.Fatalf("notes is a present null: %+v", v.Notes)
	}
	if v.Count.Present() || v.Labels.Present() {
		t.Fatal("an absent member stays absent")
	}
	out, err := json.Marshal(v)
	if err != nil || string(out) != `{"name":"n","notes":null}` {
		t.Fatalf("encode keeps the three states: %s %v", out, err)
	}

	_, viol, err = decode[widgets.WidgetPatch](t, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	want(t, viol)

	// A merge-patch member that does not declare null refuses it.
	_, viol, err = decode[widgets.WidgetPatch](t, `{"name":null,"count":null,"labels":null}`)
	if err != nil {
		t.Fatal(err)
	}
	want(t, viol, "null@/count", "null@/labels", "null@/name")

	_, viol, err = decode[widgets.WidgetPatch](t, `{"count":101,"name":""}`)
	if err != nil {
		t.Fatal(err)
	}
	want(t, viol, "maximum@/count", "min-length@/name")

	_, viol, err = decode[widgets.WidgetPatch](t, `{"nope":1}`)
	if err != nil {
		t.Fatal(err)
	}
	want(t, viol, "unknown-member@/nope")
}

func TestUnion(t *testing.T) {
	good := `{"filter":{"op":"x"},"rule":{"kind":"and","rules":[{"kind":"equals","field":"f","value":"v"},{"kind":"not","rule":{"kind":"or","rules":[{"kind":"equals","field":"g","value":"w"}]}}]}}`
	v, viol, err := decode[widgets.WidgetSearch](t, good)
	if err != nil {
		t.Fatal(err)
	}
	want(t, viol)
	if v.Filter.Op != "x" || v.Rule.Kind != "and" || v.Rule.And == nil || v.Rule.Or != nil || len(v.Rule.And.Rules) != 2 {
		t.Fatalf("union: %+v", v.Rule)
	}
	if n := v.Rule.And.Rules[1]; n.Kind != "not" || n.Not.Rule.Kind != "or" || n.Not.Rule.Or.Rules[0].Equals.Field != "g" {
		t.Fatalf("recursion: %+v", n)
	}
	out, err := json.Marshal(v)
	var gotAny, wantAny any
	if err != nil || json.Unmarshal(out, &gotAny) != nil || json.Unmarshal([]byte(good), &wantAny) != nil || !reflect.DeepEqual(gotAny, wantAny) {
		t.Fatalf("round trip\n got %s\nwant %s (%v)", out, good, err)
	}

	for name, c := range map[string]struct{ body, want string }{
		"kind missing":            {`{"filter":{"op":"x"},"rule":{"rules":[]}}`, "kind@/rule/kind"},
		"unknown kind":            {`{"filter":{"op":"x"},"rule":{"kind":"xor"}}`, "kind@/rule/kind"},
		"wrong-case kind member":  {`{"filter":{"op":"x"},"rule":{"Kind":"and","rules":[]}}`, "kind@/rule/kind"},
		"kind of the wrong type":  {`{"filter":{"op":"x"},"rule":{"kind":1}}`, "kind@/rule/kind"},
		"union not an object":     {`{"filter":{"op":"x"},"rule":"and"}`, "type@/rule"},
		"unknown member, variant": {`{"filter":{"op":"x"},"rule":{"kind":"equals","field":"f","value":"v","x":1}}`, "unknown-member@/rule/x"},
		"unknown member, nested":  {`{"filter":{"op":"x"},"rule":{"kind":"not","rule":{"kind":"equals","field":"f","value":"v","x":1}}}`, "unknown-member@/rule/rule/x"},
		"unknown member, array":   {`{"filter":{"op":"x"},"rule":{"kind":"and","rules":[{"kind":"equals","field":"f","value":"v"},{"kind":"not","rule":{"kind":"equals","field":"f","value":"v","y":1}}]}}`, "unknown-member@/rule/rules/1/rule/y"},
		"bound violation, nested": {`{"filter":{"op":"x"},"rule":{"kind":"and","rules":[]}}`, "min-items@/rule/rules"},
		"missing in variant":      {`{"filter":{"op":"x"},"rule":{"kind":"equals","field":"f"}}`, "required@/rule/value"},
		"unknown in bound type":   {`{"filter":{"op":"x","extra":1}}`, "unknown-member@/filter/extra"},
	} {
		t.Run(name, func(t *testing.T) {
			_, viol, err := decode[widgets.WidgetSearch](t, c.body)
			if err != nil {
				t.Fatalf("not a violation: %v", err)
			}
			want(t, viol, c.want)
		})
	}
}

func TestSecretsAreDestroyed(t *testing.T) {
	var c widgets.WidgetCredential
	body := `{"secret":"hunter2","backup":"b4ckup","extra":["one","two"],"hint":"h"}`
	if err := json.Unmarshal([]byte(body), &c, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	held := [][]byte{c.Secret.Bytes(), c.Backup.Bytes(), c.Extra[0].Bytes(), c.Extra[1].Bytes()}
	for i, h := range held {
		if len(h) == 0 {
			t.Fatalf("secret %d was not decoded", i)
		}
	}
	c.DestroySecrets()
	for i, h := range held {
		if strings.Trim(string(h), "\x00") != "" {
			t.Fatalf("secret %d still holds %q after DestroySecrets", i, h)
		}
	}
	if c.Secret.Len() != 0 || c.Backup.Len() != 0 || c.Extra[0].Len() != 0 {
		t.Fatal("a destroyed secret holds nothing")
	}

	// A secret never re-serialises.
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("a Secret must refuse to marshal")
	}
}

func TestInputDestroysOnlyWhenSecret(t *testing.T) {
	in := &widgets.SetWidgetCredentialInput{}
	if err := json.Unmarshal([]byte(`{"secret":"hunter2"}`), in.BodyTarget(), json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	held := in.Body.Secret.Bytes()
	in.DestroySecrets()
	if strings.Trim(string(held), "\x00") != "" {
		t.Fatal("Input.DestroySecrets must destroy the body's secrets")
	}
}
