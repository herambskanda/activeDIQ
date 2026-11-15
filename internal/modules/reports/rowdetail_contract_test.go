package reports_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	jsonv2 "encoding/json/v2"

	"github.com/skenzeriq/activediq/internal/modules/reports"
	"github.com/skenzeriq/activediq/internal/modules/reports/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

const (
	detRun = "0b0a1d2e-0000-4000-8000-0000000000d1"
	detRow = "0b0a1d2e-0000-4000-8000-0000000000d2"
	detOp  = "0b0a1d2e-0000-4000-8000-0000000000d3"
)

const detObject = `"object":{"objectGuid":"` + detRow + `","name":"Ana Kowalska","logonName":{"kind":"text","value":"ana.kowalska"},"domain":"corp.example","ouPath":{"kind":"text","value":"corp.example/Staff/Warsaw"},"dn":{"kind":"text","value":"CN=Ana Kowalska,OU=Warsaw,OU=Staff,DC=corp,DC=example"}}`
const detWhenOrigin = `"when":{"changedAt":{"kind":"time","value":"2026-11-14T09:30:00Z"},"basis":"origin","observedAt":{"kind":"time","value":"2026-11-14T09:45:00Z"},"gapMinutes":{"kind":"integer","value":"15"},"observationBased":true}`
const detWhenUnknown = `"when":{"changedAt":{"kind":"time","value":"2026-11-14T09:45:00Z"},"basis":"observed","observedAt":{"kind":"time","value":"2026-11-14T09:45:00Z"},"gapMinutes":{"kind":"unknown"},"observationBased":true}`
const detNative = `"actor":{"kind":"notRecorded"}`
const detHead = `"runId":"` + detRun + `","rowKey":"` + detRow + `",`

func readDetail(t *testing.T, doc string) (api.ReportRowDetail, *apitypes.Errors, error) {
	t.Helper()
	var v api.ReportRowDetail
	if err := jsonv2.Unmarshal([]byte(doc), &v); err != nil {
		return v, nil, err
	}
	var errs apitypes.Errors
	v.Validate("", &errs)
	return v, &errs, nil
}

// T-1717 acceptance 1: one row of each kind answers exactly the fields of design 2 for that kind.
func TestRowDetailEachKindCarriesExactlyItsFields(t *testing.T) {
	cases := map[string]struct {
		doc  string
		kind string
		has  []string
		not  []string
	}{
		"edited": {
			doc: `{"kind":"edited",` + detHead + detWhenOrigin + `,"valuesRecorded":false,"attributes":[
			  {"name":"title","originAt":{"kind":"time","value":"2026-11-14T09:30:00Z"},"version":{"kind":"integer","value":"7"}},
			  {"name":"department","originAt":{"kind":"unknown"},"version":{"kind":"unknown"}}],` + detObject + `,` + detNative + `}`,
			kind: "edited", has: []string{"attributes", "valuesRecorded", "when", "object", "actor"}, not: []string{"names", "restorableUntil", "descriptorRead"},
		},
		"membership": {
			doc: `{"kind":"membership",` + detHead + detWhenOrigin + `,"side":"added","addedCount":1204,"removedCount":8,"addedOutOfScope":37,"removedOutOfScope":0,
			  "names":{"items":[{"objectGuid":"` + detOp + `","name":"Beata Nowak"}],"page":{"nextCursor":null}},` + detObject + `,` + detNative + `}`,
			kind: "membership", has: []string{"names", "addedCount", "removedCount", "addedOutOfScope", "removedOutOfScope", "side"}, not: []string{"attributes", "restorableUntil"},
		},
		"credential": {
			doc:  `{"kind":"credential",` + detHead + detWhenUnknown + `,` + detObject + `,` + detNative + `}`,
			kind: "credential", has: []string{"when", "object", "actor"}, not: []string{"attributes", "names", "descriptorRead", "restorableUntil"},
		},
		"permissions": {
			doc:  `{"kind":"permissions",` + detHead + detWhenOrigin + `,"descriptorRead":false,` + detObject + `,` + detNative + `}`,
			kind: "permissions", has: []string{"descriptorRead"}, not: []string{"attributes", "names", "restorableUntil"},
		},
		"removed": {
			doc: `{"kind":"removed",` + detHead + `"when":{"changedAt":{"kind":"time","value":"2026-11-14T10:00:00Z"},"basis":"last_seen","observedAt":{"kind":"time","value":"2026-11-14T10:00:00Z"},"gapMinutes":{"kind":"unknown"},"observationBased":true},
			  "deletedAt":{"kind":"time","value":"2026-11-14T10:00:00Z"},"onOrBefore":true,"state":"removed_restore_unknown","restorableUntil":{"kind":"unknown"},"restoreUnknownReason":"deleted_objects_not_readable",` + detObject + `,` + detNative + `}`,
			kind: "removed", has: []string{"deletedAt", "onOrBefore", "state", "restorableUntil", "restoreUnknownReason"}, not: []string{"attributes", "names"},
		},
		"through activeDIQ": {
			doc: `{"kind":"edited",` + detHead + detWhenOrigin + `,"valuesRecorded":false,"attributes":[{"name":"title","originAt":{"kind":"unknown"},"version":{"kind":"unknown"}}],` + detObject + `,
			  "actor":{"kind":"activediq","principal":"ana.kowalska","operationId":"` + detOp + `"}}`,
			kind: "edited", has: []string{"actor"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			v, errs, err := readDetail(t, c.doc)
			if err != nil {
				t.Fatal(err)
			}
			if errs.Len() != 0 {
				t.Fatalf("a valid %s detail is refused: %v", name, errs.All())
			}
			if v.Kind != c.kind {
				t.Fatalf("kind = %q", v.Kind)
			}
			out, err := jsonv2.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := jsonv2.Unmarshal(out, &m); err != nil {
				t.Fatal(err)
			}
			for _, k := range c.has {
				if _, ok := m[k]; !ok {
					t.Errorf("%s detail lacks %s: %s", name, k, out)
				}
			}
			for _, k := range c.not {
				if _, ok := m[k]; ok {
					t.Errorf("%s detail carries another kind's field %s", name, k)
				}
			}
		})
	}
	// The one case with an actor names the principal and links the operation.
	v, _, _ := readDetail(t, cases["through activeDIQ"].doc)
	if a := v.Edited.Actor; a.Kind != "activediq" || a.Activediq == nil || a.Activediq.OperationID.String() != detOp {
		t.Errorf("actor = %+v", a)
	}
}

// Unknown is a typed value of its own: never a null, an empty string or a zero.
func TestRowDetailUnknownIsTypedAndNeverAGuess(t *testing.T) {
	v, errs, err := readDetail(t, `{"kind":"credential",`+detHead+detWhenUnknown+`,`+detObject+`,`+detNative+`}`)
	if err != nil || errs.Len() != 0 {
		t.Fatalf("err=%v errs=%v", err, errs)
	}
	if g := v.Credential.When.GapMinutes; g.Kind != "unknown" || g.Unknown == nil || g.Integer != nil {
		t.Errorf("gapMinutes = %+v", g)
	}
	for name, doc := range map[string]string{
		"a null time":         `{"kind":"credential",` + detHead + strings.Replace(detWhenUnknown, `"observedAt":{"kind":"time","value":"2026-11-14T09:45:00Z"}`, `"observedAt":null`, 1) + `,` + detObject + `,` + detNative + `}`,
		"an empty-string gap": `{"kind":"credential",` + detHead + strings.Replace(detWhenUnknown, `"gapMinutes":{"kind":"unknown"}`, `"gapMinutes":""`, 1) + `,` + detObject + `,` + detNative + `}`,
		"a removed row with a guessed restore time": `{"kind":"removed",` + detHead + detWhenUnknown + `,"deletedAt":{"kind":"unknown"},"onOrBefore":true,"state":"removed_restore_unknown","restorableUntil":{"kind":"time","value":"2027-01-01T00:00:00Z"},"restoreUnknownReason":"deleted_objects_not_readable",` + detObject + `,` + detNative + `}`,
		"a field of another kind":                   `{"kind":"credential",` + detHead + detWhenUnknown + `,"attributes":[],` + detObject + `,` + detNative + `}`,
		"an unknown kind":                           `{"kind":"restored",` + detHead + detWhenUnknown + `,` + detObject + `,` + detNative + `}`,
		"an old value":                              `{"kind":"edited",` + detHead + detWhenOrigin + `,"valuesRecorded":false,"attributes":[{"name":"title","originAt":{"kind":"unknown"},"version":{"kind":"unknown"},"oldValue":"x"}],` + detObject + `,` + detNative + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, errs, err := readDetail(t, doc)
			if err == nil && errs.Len() == 0 {
				t.Errorf("accepted: %s", doc)
			}
		})
	}
}

// The contract states what the read is: gate order, paging and scope, names only, no restore.
func TestRowDetailOperationIsDeclared(t *testing.T) {
	d := bundle(t)
	ops := at(t, d, "paths", "/reports/runs/{runId}/rows/{rowKey}/detail", "get")
	if ops["operationId"] != "getReportRunRowDetail" || ops["x-permission"] != string(reports.RunPermission) {
		t.Errorf("operation = %v / %v", ops["operationId"], ops["x-permission"])
	}
	desc, _ := ops["description"].(string)
	for _, want := range []string{"counted, never named", "scope_changed_rerun", "run_not_ready", "run_failed", "report-result-expired", "typed unknown", "no restore"} {
		if !strings.Contains(desc, want) {
			t.Errorf("getReportRunRowDetail does not say %q", want)
		}
	}
	var names []string
	for _, p := range ops["parameters"].([]any) {
		m := p.(map[string]any)
		ref, _ := m["$ref"].(string)
		names = append(names, ref[strings.LastIndex(ref, "/")+1:])
	}
	for _, want := range []string{"RunId", "RowKey", "MembershipSide", "PageCursor", "PageLimit"} {
		if !slices.Contains(names, want) {
			t.Errorf("lacks parameter %s (has %v)", want, names)
		}
	}
	mapping := at(t, d, "components", "schemas", "ReportRowDetail", "discriminator", "mapping")
	if len(mapping) != 5 {
		t.Errorf("kinds = %v", mapping)
	}
}

// Until T-2117 lands the read answers 501, never an empty detail.
func TestRowDetailAnswers501UntilTheReadLands(t *testing.T) {
	var h reports.Handlers
	out, err := h.GetReportRunRowDetail(context.Background(), api.GetReportRunRowDetailInput{})
	var p *apitypes.Problem
	if out != nil || !errors.As(err, &p) || p.Status != 501 {
		t.Fatalf("out=%v err=%v", out, err)
	}
}
