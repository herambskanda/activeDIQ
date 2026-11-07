package reports_test

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	jsonv2 "encoding/json/v2"

	"github.com/skenzeriq/activediq/internal/modules/reports"
	"github.com/skenzeriq/activediq/internal/modules/reports/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

const (
	domA   = "0b0a1d2e-0000-4000-8000-00000000000a"
	domB   = "0b0a1d2e-0000-4000-8000-00000000000b"
	rowKey = "0b0a1d2e-0000-4000-8000-0000000000c1"
)

func readPolicyReads(t *testing.T, doc string) (api.ReportPolicyReads, *apitypes.Errors, error) {
	t.Helper()
	var v api.ReportPolicyReads
	if err := jsonv2.Unmarshal([]byte(doc), &v); err != nil {
		return v, nil, err
	}
	var errs apitypes.Errors
	v.Validate("", &errs)
	return v, &errs, nil
}

// T-1718 acceptance 1: a domain's Password Settings Container read is exactly one of readable, none_exist or
// unreadable, and unreadable is a value of its own: it is never a none_exist and never carries a read that
// succeeded (spec 7.1 rule 3, AC-S19). Partial coverage (1 of 2 domains readable) is expressed per domain.
func TestPolicyReadsKeepUnreadableDistinctFromNoneExist(t *testing.T) {
	doc := `{"domainsInScope":2,"domainsReadable":1,"complete":false,"domains":[
	  {"kind":"none_exist","domainId":"` + domA + `","domainName":"corp.example","domainPolicyRowKey":"` + rowKey + `","readAt":"2026-11-07T14:02:00Z"},
	  {"kind":"unreadable","domainId":"` + domB + `","domainName":"emea.corp.example","domainPolicyRowKey":"` + rowKey + `","containerName":"Password Settings Container","reason":"permission_denied"}]}`
	v, errs, err := readPolicyReads(t, doc)
	if err != nil {
		t.Fatal(err)
	}
	if errs.Len() != 0 {
		t.Fatalf("a valid partial-coverage read is refused: %v", errs.All())
	}
	if v.Complete || v.DomainsReadable != 1 || v.DomainsInScope != 2 {
		t.Fatalf("coverage = %+v", v)
	}
	if got := v.Domains[0]; got.Kind != "none_exist" || got.NoneExist == nil || got.Unreadable != nil || got.Readable != nil {
		t.Errorf("domain 0 must be none_exist only: %+v", got)
	}
	if got := v.Domains[1]; got.Kind != "unreadable" || got.Unreadable == nil || got.NoneExist != nil || got.Readable != nil {
		t.Errorf("domain 1 must be unreadable only: %+v", got)
	}
	// It round-trips with its kind intact.
	out, err := jsonv2.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"kind":"unreadable"`) || !strings.Contains(string(out), `"containerName":"Password Settings Container"`) {
		t.Errorf("unreadable lost on the wire: %s", out)
	}
}

func TestPolicyReadsRefuseWhatWouldBlurTheThreeKinds(t *testing.T) {
	base := `"domainId":"` + domA + `","domainName":"corp.example","domainPolicyRowKey":"` + rowKey + `"`
	for name, domain := range map[string]string{
		"unreadable with no reason":           `{"kind":"unreadable",` + base + `,"containerName":"Password Settings Container"}`,
		"unreadable with no container":        `{"kind":"unreadable",` + base + `,"reason":"permission_denied"}`,
		"unreadable carrying a psoCount":      `{"kind":"unreadable",` + base + `,"containerName":"c","reason":"not_read","psoCount":0}`,
		"none_exist with a reason":            `{"kind":"none_exist",` + base + `,"readAt":"2026-11-07T14:02:00Z","reason":"permission_denied"}`,
		"none_exist without a read time":      `{"kind":"none_exist",` + base + `}`,
		"readable with zero policies":         `{"kind":"readable",` + base + `,"readAt":"2026-11-07T14:02:00Z","psoCount":0}`,
		"a kind that is not one of the three": `{"kind":"empty",` + base + `,"readAt":"2026-11-07T14:02:00Z"}`,
	} {
		t.Run(name, func(t *testing.T) {
			doc := `{"domainsInScope":1,"domainsReadable":0,"complete":false,"domains":[` + domain + `]}`
			_, errs, err := readPolicyReads(t, doc)
			if err == nil && errs.Len() == 0 {
				t.Errorf("accepted: %s", domain)
			}
		})
	}
}

// The SYS-01 columns are in the closed request enum, a never cell stays the policy's own no-limit setting and
// the contract says the units and the unknown rule where a client reads them.
func TestPolicyColumnsAndUnitsAreDeclared(t *testing.T) {
	raw, err := os.ReadFile("../../platform/apihost/spec/openapi.gen.json")
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := jsonv2.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	enum := func(name string) []string {
		var out []string
		for _, v := range at(t, d, "components", "schemas", name)["enum"].([]any) {
			out = append(out, v.(string))
		}
		return out
	}
	cols := enum("ReportColumnId")
	for _, c := range []string{"policy_name", "policy_kind", "precedence", "applies_to_count", "applies_to_first", "min_length", "history_length", "max_age", "min_age", "complexity", "reversible_encryption", "lockout_threshold", "lockout_duration", "lockout_window"} {
		if !slices.Contains(cols, c) {
			t.Errorf("ReportColumnId lacks %s", c)
		}
	}
	if u := enum("ReportColumnUnitValue"); !slices.Equal(u, []string{"count", "seconds"}) {
		t.Errorf("units = %v", u)
	}
	if k := enum("ReportPolicyKindValue"); !slices.Equal(k, []string{"domain", "pso"}) {
		t.Errorf("policy kinds = %v", k)
	}
	if r := enum("ReportPolicyUnreadableReasonValue"); !slices.Equal(r, []string{"permission_denied", "container_absent", "not_read"}) {
		t.Errorf("unreadable reasons = %v", r)
	}
	// The run carries the state; the three kinds map one to one onto their own schemas.
	if _, ok := at(t, d, "components", "schemas", "ReportRun")["properties"].(map[string]any)["policyReads"]; !ok {
		t.Error("ReportRun has no policyReads")
	}
	mapping := at(t, d, "components", "schemas", "ReportPolicyDomainRead", "discriminator", "mapping")
	if len(mapping) != 3 || mapping["unreadable"] != "#/components/schemas/ReportPolicyDomainUnreadable" || mapping["none_exist"] != "#/components/schemas/ReportPolicyDomainNoneExist" {
		t.Errorf("discriminator mapping = %v", mapping)
	}
	// The targets read: paged, on the run-read gate, and it says what it is not.
	ops := at(t, d, "paths", "/reports/runs/{runId}/policies/{policyId}/targets", "get")
	desc, _ := ops["description"].(string)
	for _, want := range []string{"direct targets, not the resultant set", "scope_changed_rerun", "run_not_ready", "run_failed", "report-result-expired"} {
		if !strings.Contains(desc, want) {
			t.Errorf("listReportRunPolicyTargets does not say %q", want)
		}
	}
	if ops["x-permission"] != string(reports.RunPermission) {
		t.Errorf("listReportRunPolicyTargets binds %v", ops["x-permission"])
	}
	params := ops["parameters"].([]any)
	names := []string{}
	for _, p := range params {
		m := p.(map[string]any)
		if ref, ok := m["$ref"].(string); ok {
			names = append(names, ref[strings.LastIndex(ref, "/")+1:])
		} else {
			names = append(names, m["name"].(string))
		}
	}
	for _, want := range []string{"RunId", "PolicyId", "PageCursor", "PageLimit"} {
		if !slices.Contains(names, want) {
			t.Errorf("listReportRunPolicyTargets lacks parameter %s (has %v)", want, names)
		}
	}
	if _, ok := at(t, d, "components", "schemas", "ReportPolicyTargetPage")["properties"].(map[string]any)["page"]; !ok {
		t.Error("the targets page carries no page info")
	}
}

// Until the policy dataset (T-1114) lands the targets read answers 501, never an empty page a client would read
// as "no direct targets".
func TestPolicyTargetsAnswer501UntilTheDatasetLands(t *testing.T) {
	var h reports.Handlers
	out, err := h.ListReportRunPolicyTargets(context.Background(), api.ListReportRunPolicyTargetsInput{})
	var p *apitypes.Problem
	if out != nil || !errors.As(err, &p) || p.Status != 501 {
		t.Fatalf("out=%v err=%v", out, err)
	}
}
