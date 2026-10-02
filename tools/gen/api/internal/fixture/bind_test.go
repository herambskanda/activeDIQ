package fixture

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	widgets "github.com/skenzeriq/activediq/tools/gen/api/internal/fixture/internal/modules/widgets/api"
)

// handlers is a Handlers that records what it was given.
type handlers struct {
	widgets.Handlers // nil: an operation the test does not expect panics
	gotList          widgets.ListWidgetsInput
	err              error
}

func (h *handlers) ListWidgets(_ context.Context, in widgets.ListWidgetsInput) (widgets.ListWidgetsOutput, error) {
	h.gotList = in
	if h.err != nil {
		return nil, h.err
	}
	return widgets.ListWidgets200{XTotalHint: "7"}, nil
}

func (h *handlers) DeleteWidget(context.Context, widgets.DeleteWidgetInput) (widgets.DeleteWidgetOutput, error) {
	return nil, nil // a handler that returns neither output nor error
}

func routes(t *testing.T, h widgets.Handlers) map[string]apihost.Route {
	t.Helper()
	th := widgets.Bind(h)
	if th.Tag() != "widgets" {
		t.Fatalf("tag = %q", th.Tag())
	}
	out := map[string]apihost.Route{}
	for _, r := range th.Routes() {
		out[r.Meta().OperationID] = r
	}
	return out
}

func TestBindRouteRows(t *testing.T) {
	rs := routes(t, &handlers{})
	if len(rs) != 9 {
		t.Fatalf("want one route per operation, got %d", len(rs))
	}
	type row struct {
		method, path, perm, stability string
		body                          apihost.BodyKind
		media                         string
		secret                        bool
		maxBody                       int64
		class                         string
	}
	for id, w := range map[string]row{
		"listWidgets":         {"GET", "/widgets", "widgets.read", "stable", apihost.BodyNone, "", false, 1 << 20, "read"},
		"createWidget":        {"POST", "/widgets", "widgets.write", "stable", apihost.BodyJSON, "application/json", false, 1 << 20, "write"},
		"getWidget":           {"GET", "/widgets/{widgetId}", "widgets.read", "stable", apihost.BodyNone, "", false, 1 << 20, "read"},
		"updateWidget":        {"PATCH", "/widgets/{widgetId}", "widgets.write", "stable", apihost.BodyMergePatch, "application/merge-patch+json", false, 1 << 20, "write"},
		"deleteWidget":        {"DELETE", "/widgets/{widgetId}", "widgets.write", "preview", apihost.BodyNone, "", false, 1 << 20, "write"},
		"setWidgetCredential": {"PUT", "/widgets/{widgetId}/credential", "widgets.credential", "stable", apihost.BodyJSON, "application/json", true, 4096, "write"},
		"searchWidgets":       {"POST", "/widgets/search", "widgets.read", "stable", apihost.BodyJSON, "application/json", false, 1 << 20, "read"},
		"importWidgets":       {"POST", "/widgets/import", "widgets.write", "stable", apihost.BodyBinary, "text/csv", false, 1 << 20, "write"},
		"exportWidgets":       {"GET", "/widgets/export", "widgets.read", "stable", apihost.BodyNone, "", false, 1 << 20, "read"},
	} {
		r, ok := rs[id]
		if !ok {
			t.Errorf("%s: no route", id)
			continue
		}
		m := r.Meta()
		got := row{m.Method, m.Path, m.Permission, m.Stability, m.Body, m.MediaType, m.Secret, m.MaxBody, m.Class}
		if got != w || m.Tag != "widgets" || m.Scope != "tenant" {
			t.Errorf("%s: route row\n got %+v\nwant %+v", id, got, w)
		}
	}
}

func TestRouteCallsTheHandler(t *testing.T) {
	h := &handlers{}
	r := routes(t, h)["listWidgets"]
	in := r.NewInput()
	req := &apihost.Request{Query: url.Values{"limit": {"25"}, "active": {"true"}, "id": {"3f2504e0-4f89-11d3-9a0c-0305e82c3301", "3F2504E0-4F89-11D3-9A0C-0305E82C3302"}}, Header: http.Header{}, PathValue: func(string) string { return "" }}
	var errs apitypes.Errors
	in.BindRequest(req, &errs)
	in.Validate(&errs)
	if errs.Len() != 0 {
		t.Fatalf("a valid request: %v", errs.All())
	}
	out, err := r.Call(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if out.StatusCode() != 200 || out.ResponseHeaders()["X-Total-Hint"] != "7" {
		t.Fatalf("response = %d %v", out.StatusCode(), out.ResponseHeaders())
	}
	if h.gotList.Limit == nil || *h.gotList.Limit != 25 || h.gotList.Active == nil || !*h.gotList.Active || len(h.gotList.ID) != 2 || h.gotList.Cursor != nil {
		t.Fatalf("the handler got %+v", h.gotList)
	}

	// An error from the handler is returned as is.
	h.err = errors.New("boom")
	if _, err := r.Call(context.Background(), r.NewInput()); err == nil {
		t.Fatal("an error must pass through")
	}
	// A handler with neither is a bug that is reported, not a nil Response.
	if out, err := routes(t, h)["deleteWidget"].Call(context.Background(), routes(t, h)["deleteWidget"].NewInput()); err == nil || out != nil {
		t.Fatalf("no output and no error must be an error: %v %v", out, err)
	}
}

func TestParameterViolations(t *testing.T) {
	r := routes(t, &handlers{})["listWidgets"]
	req := &apihost.Request{
		Query: url.Values{
			"limit":         {"2000"},
			"sort":          {"colour"},
			"owner":         {"not-a-uuid"},
			"modifiedSince": {"yesterday"},
			"createdOn":     {"2026-02-30"},
			"active":        {"yes"},
			"cursor":        {"a", "b"},
			"id":            {"3f2504e0-4f89-11d3-9a0c-0305e82c3301", "x"},
		},
		Header:    http.Header{"X-Request-Source": {"ab"}},
		PathValue: func(string) string { return "" },
	}
	in := r.NewInput()
	var errs apitypes.Errors
	in.BindRequest(req, &errs)
	in.Validate(&errs)
	got := map[string]bool{}
	for _, v := range errs.All() {
		got[v.In+":"+string(v.Pointer)+":"+v.Code] = true
	}
	for _, w := range []string{
		"query:limit:maximum", "query:sort:enum", "query:owner:type", "query:modifiedSince:type", "query:createdOn:type",
		"query:active:type", "query:cursor:type", "query:id:type", "header:X-Request-Source:min-length",
	} {
		if !got[w] {
			t.Errorf("missing violation %s; have %v", w, got)
		}
	}
}

func TestPathAndRequiredHeaderBinding(t *testing.T) {
	r := routes(t, &handlers{})["getWidget"]
	in := r.NewInput()
	var errs apitypes.Errors
	in.BindRequest(&apihost.Request{Query: url.Values{}, Header: http.Header{}, PathValue: func(n string) string {
		if n == "widgetId" {
			return "3F2504E0-4F89-11D3-9A0C-0305E82C3301"
		}
		return ""
	}}, &errs)
	if errs.Len() != 0 {
		t.Fatalf("%v", errs.All())
	}
	in2 := r.NewInput()
	in2.BindRequest(&apihost.Request{Query: url.Values{}, Header: http.Header{}, PathValue: func(string) string { return "" }}, &errs)
	if errs.Len() != 1 || errs.All()[0].Code != apitypes.CodeRequired || errs.All()[0].In != apitypes.InPath {
		t.Fatalf("a missing path parameter: %v", errs.All())
	}
}

func TestSharedParametersKeepTheirBounds(t *testing.T) {
	r := routes(t, &handlers{})["createWidget"]
	in := r.NewInput()
	var errs apitypes.Errors
	in.BindRequest(&apihost.Request{Query: url.Values{}, Header: http.Header{"Idempotency-Key": {"short"}}, PathValue: func(string) string { return "" }}, &errs)
	in.Validate(&errs)
	got := codes(errs.All())
	found := false
	for _, v := range errs.All() {
		if v.In == apitypes.InHeader && v.Code == apitypes.CodeMinLength {
			found = true
		}
	}
	if !found {
		t.Fatalf("Idempotency-Key must be checked against the shared parameter's bounds: %v", got)
	}
}

func TestBodyDecodeThroughTheInput(t *testing.T) {
	r := routes(t, &handlers{})["updateWidget"]
	in := r.NewInput()
	if err := json.Unmarshal([]byte(`{"name":"x","bogus":1}`), in.BodyTarget(), json.RejectUnknownMembers(true)); err == nil {
		t.Fatal("the body target must decode strictly")
	}
	in = routes(t, &handlers{})["exportWidgets"].NewInput()
	if in.BodyTarget() != nil {
		t.Fatal("an operation without a body has no body target")
	}
}

// walk visits every type reachable from t.
func walk(t reflect.Type, seen map[reflect.Type]bool, visit func(reflect.Type)) {
	if seen[t] {
		return
	}
	seen[t] = true
	visit(t)
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Chan:
		walk(t.Elem(), seen, visit)
	case reflect.Map:
		walk(t.Key(), seen, visit)
		walk(t.Elem(), seen, visit)
	case reflect.Struct:
		for i := range t.NumField() {
			f := t.Field(i)
			if f.IsExported() {
				walk(f.Type, seen, visit)
			}
		}
	}
}

// v1 is the interface pair no reachable type may implement (ADR-0004 rule 4, the type-closure rule):
// a v1 method nested in a v2 decode silently drops the strict options.
type v1Unmarshaler interface{ UnmarshalJSON([]byte) error }
type v1Marshaler interface{ MarshalJSON() ([]byte, error) }

func TestTypeClosureHasNoV1JSONMethods(t *testing.T) {
	seen := map[reflect.Type]bool{}
	roots := []reflect.Type{}
	for _, r := range routes(t, &handlers{}) {
		roots = append(roots, reflect.TypeOf(r.NewInput()))
	}
	for _, o := range []any{
		widgets.CreateWidget201{}, widgets.GetWidget200{}, widgets.ListWidgets200{}, widgets.UpdateWidget200{},
		widgets.SearchWidgets200{}, widgets.ImportWidgets200{}, widgets.ExportWidgets200{}, widgets.DeleteWidget204{}, widgets.SetWidgetCredential204{},
	} {
		roots = append(roots, reflect.TypeOf(o))
	}
	n := 0
	un, ma := reflect.TypeFor[v1Unmarshaler](), reflect.TypeFor[v1Marshaler]()
	for _, root := range roots {
		walk(root, seen, func(ty reflect.Type) {
			n++
			for _, c := range []reflect.Type{ty, reflect.PointerTo(ty)} {
				if c.Implements(un) || c.Implements(ma) {
					t.Errorf("%s implements a v1 JSON method", ty)
				}
			}
		})
	}
	if !reflect.TypeFor[time.Time]().Implements(un) {
		t.Fatal("the check must be able to see a v1 method (time.Time has one)")
	}
	if n < 40 {
		t.Fatalf("the walk visited only %d types", n)
	}
}
