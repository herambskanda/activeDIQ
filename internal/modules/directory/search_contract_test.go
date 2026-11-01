package directory_test

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	jsonv2 "encoding/json/v2"

	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/modules/directory/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// Contract tests of searchDirectory (T-1094, ADR-0011). They read the bundled contract the server serves.

func loadBundle(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../platform/apihost/spec/openapi.gen.json")
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := jsonv2.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func sub(t *testing.T, m map[string]any, path ...string) map[string]any {
	t.Helper()
	cur := m
	for _, k := range path {
		next, ok := cur[k].(map[string]any)
		if !ok {
			t.Fatalf("bundle has no %v", path)
		}
		cur = next
	}
	return cur
}

func schema(t *testing.T, d map[string]any, name string) map[string]any {
	t.Helper()
	return sub(t, d, "components", "schemas", name)
}

func refName(v any) string {
	r, _ := v.(map[string]any)["$ref"].(string)
	return r[strings.LastIndex(r, "/")+1:]
}

func strs(v any) []string {
	var out []string
	for _, e := range v.([]any) {
		out = append(out, e.(string))
	}
	return out
}

// AC1: a POST (the text never sits in a URL, ADR-0011 rule 15), directory.read, a read-class limit, no
// parameter at all, and the old GET operation is still there.
func TestSearchDirectoryIsAPostReadUnderDirectoryRead(t *testing.T) {
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	var found, legacy bool
	for _, op := range doc.Operations() {
		switch op.ID {
		case "searchDirectory":
			found = true
			if op.Method != "POST" || op.Path != "/directory/search" || op.Permission != "directory.read" || op.Class != "read" || op.Tag != "directory" {
				t.Errorf("searchDirectory = %+v", op)
			}
		case "searchDirectoryUsers": // AC5: untouched here; T-1127 retires it
			legacy = true
			if op.Method != "GET" || op.Path != "/directory/users" || op.Permission != "directory.read" {
				t.Errorf("searchDirectoryUsers changed: %+v", op)
			}
		}
	}
	if !found || !legacy {
		t.Fatalf("searchDirectory present %v, searchDirectoryUsers present %v", found, legacy)
	}
	d := loadBundle(t)
	op := sub(t, d, "paths", "/directory/search", "post")
	if _, has := op["parameters"]; has {
		t.Error("searchDirectory takes no query-string or path parameter; the text is in the body")
	}
	if got := refName(sub(t, op, "requestBody", "content", "application/json")["schema"]); got != "DirectorySearchRequest" {
		t.Errorf("request body schema %q", got)
	}
}

// AC2: every field IA 5.3 names is on the hit, status is an enumerated list of chips (no string), and the
// request is closed.
func TestSearchHitCarriesTheMetadataOfIA53(t *testing.T) {
	d := loadBundle(t)
	hit := schema(t, d, "DirectorySearchHit")
	props := sub(t, hit, "properties")
	for _, f := range []string{"type", "objectId", "displayName", "matchClass", "highlights", "samAccountName", "userPrincipalName", "mail", "disambiguator", "distinguishedName", "domain", "status"} {
		if _, ok := props[f]; !ok {
			t.Errorf("hit has no %q", f)
		}
	}
	req := strs(hit["required"])
	for _, f := range []string{"type", "objectId", "displayName", "matchClass", "highlights", "distinguishedName", "domain", "status"} {
		if !slices.Contains(req, f) {
			t.Errorf("hit does not require %q", f)
		}
	}
	for _, f := range []string{"samAccountName", "userPrincipalName", "mail", "disambiguator"} {
		if slices.Contains(req, f) {
			t.Errorf("hit requires %q; a contact has no logon name and a title may be unsynced", f)
		}
	}
	if sub(t, props, "status")["type"] != "array" {
		t.Error("status is not an array of chips")
	}
	if got := refName(sub(t, props, "status")["items"]); got != "DirectorySearchChip" {
		t.Errorf("status items %q", got)
	}
	if got := strs(schema(t, d, "DirectorySearchChipKind")["enum"]); !slices.Equal(got, []string{"locked", "disabled", "passwordExpired", "passwordExpiresInDays", "accountExpires", "deleted", "tier0", "cloudOnly"}) {
		t.Errorf("chip kinds %v", got)
	}
	chip := sub(t, schema(t, d, "DirectorySearchChip"), "properties")
	for name, p := range chip {
		if sub(t, map[string]any{"p": p}, "p")["type"] == "string" && name != "kind" && name != "at" {
			t.Errorf("chip member %q is a free-form string", name)
		}
	}
	if got := strs(schema(t, d, "DirectorySearchMatchClass")["enum"]); !slices.Equal(got, []string{"exact", "prefix", "fuzzy"}) {
		t.Errorf("match classes %v", got)
	}
	if got := strs(schema(t, d, "DirectorySearchType")["enum"]); !slices.Equal(got, []string{"users", "groups", "computers", "contacts"}) {
		t.Errorf("type filter %v", got)
	}
	if schema(t, d, "DirectorySearchRequest")["additionalProperties"] != false {
		t.Error("the request accepts members it does not declare")
	}
	if _, ok := sub(t, schema(t, d, "DirectorySearchRequest"), "properties")["filter"]; ok {
		t.Error("the request declares a filter member; no client filter syntax is accepted")
	}
}

// AC3: counts are of the trimmed result only. No schema of the operation has a total, and count, more,
// nextCursor are optional so the refine state can omit them.
func TestSearchCountsAreTrimmedAndOptional(t *testing.T) {
	d := loadBundle(t)
	for _, name := range []string{"DirectorySearchResult", "DirectorySearchGroup", "DirectorySearchHit", "DirectorySearchRequest"} {
		for p := range sub(t, schema(t, d, name), "properties") {
			if strings.Contains(strings.ToLower(p), "total") || strings.Contains(strings.ToLower(p), "unscoped") {
				t.Errorf("%s has %q; there is no total over the directory", name, p)
			}
		}
	}
	grp := schema(t, d, "DirectorySearchGroup")
	req := strs(grp["required"])
	if !slices.Equal(req, []string{"type", "items"}) && !(len(req) == 2 && slices.Contains(req, "type") && slices.Contains(req, "items")) {
		t.Errorf("group requires %v; count, more, nextCursor and limitReached must be omittable", req)
	}
	gp := sub(t, grp, "properties")
	if gp["more"].(map[string]any)["type"] != "boolean" {
		t.Error("a truncated group says so with a boolean flag")
	}
	res := schema(t, d, "DirectorySearchResult")
	if !slices.Contains(strs(res["required"]), "refine") || !slices.Contains(strs(res["required"]), "asOf") {
		t.Errorf("result requires %v; refine and asOf are always present", res["required"])
	}
}

// AC4: 400, 403, 429 (and 503) are problem catalogue entries whose example carries a traceId and no real
// name, and the recovery-password refusal does not echo the text.
func TestSearchFailuresUseTheSharedProblemSchema(t *testing.T) {
	d := loadBundle(t)
	op := sub(t, d, "paths", "/directory/search", "post", "responses")
	want := map[string]string{"400": "SearchQueryInvalid", "403": "Forbidden", "429": "RateLimited", "503": "SearchUnavailable"}
	for status, name := range want {
		if got := refName(op[status]); got != name {
			t.Errorf("%s answers %q, want %q", status, got, name)
		}
		r := sub(t, d, "components", "responses", name, "content", "application/problem+json")
		if refName(r["schema"]) != "Problem" {
			t.Errorf("%s does not use the Problem schema", name)
		}
		ex := r["example"].(map[string]any)
		if _, ok := ex["traceId"].(string); !ok {
			t.Errorf("%s example has no traceId", name)
		}
	}
	desc := sub(t, d, "components", "responses", "SearchQueryInvalid")["description"].(string)
	for _, code := range []string{"query_too_short", "query_too_long", "query_invalid", "query_refused", "cursor_invalid"} {
		if !strings.Contains(desc, code) {
			t.Errorf("SearchQueryInvalid does not document %s", code)
		}
	}
	// The whole operation's examples carry the names of no real person or domain.
	raw, _ := jsonv2.Marshal(sub(t, d, "paths", "/directory/search"))
	for _, real := range []string{"contoso", "fabrikam", "microsoft", "skenzeriq"} {
		if strings.Contains(strings.ToLower(string(raw)), real) {
			t.Errorf("an example in searchDirectory mentions %q", real)
		}
	}
}

// Bounds the contract states: q 1..256, groupLimit 1..50, an unknown type is refused.
func TestSearchRequestBounds(t *testing.T) {
	in := func(b api.DirectorySearchRequest) []apitypes.Violation {
		var errs apitypes.Errors
		i := api.SearchDirectoryInput{Body: b}
		i.Validate(&errs)
		return errs.All()
	}
	if got := in(api.DirectorySearchRequest{Q: "pat"}); len(got) != 0 {
		t.Errorf("a plain query is refused: %v", got)
	}
	if got := in(api.DirectorySearchRequest{Q: ""}); len(got) == 0 {
		t.Error("an empty q is accepted")
	}
	if got := in(api.DirectorySearchRequest{Q: strings.Repeat("a", 257)}); len(got) == 0 {
		t.Error("a 257-character q is accepted")
	}
	if got := in(api.DirectorySearchRequest{Q: strings.Repeat("é", 256)}); len(got) != 0 {
		t.Errorf("256 characters is refused: %v", got)
	}
	zero, big := int64(0), int64(51)
	for _, n := range []*int64{&zero, &big} {
		if got := in(api.DirectorySearchRequest{Q: "pat", GroupLimit: n}); len(got) == 0 {
			t.Errorf("groupLimit %d is accepted", *n)
		}
	}
}

// Until T-1096 lands the handler answers 501 and never builds a made-up body or repeats the text.
func TestSearchDirectoryAnswersNotImplementedWithoutEchoingTheText(t *testing.T) {
	secret := "pat.secret.query"
	_, err := directory.Handlers{}.SearchDirectory(context.Background(), api.SearchDirectoryInput{Body: api.DirectorySearchRequest{Q: secret}})
	p, ok := err.(*apitypes.Problem)
	if !ok || p.Status != 501 {
		t.Fatalf("err = %#v", err)
	}
	b, _ := jsonv2.Marshal(p)
	if strings.Contains(string(b), secret) {
		t.Error("the problem repeats the query")
	}
}
