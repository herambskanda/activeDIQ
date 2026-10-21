package apihost_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

func budgetServer(t *testing.T, budget int64) *apihost.Server {
	t.Helper()
	r := jsonRow()
	m := r.meta
	doc, err := apihost.ParseDocument(docJSON([4]string{m.OperationID, m.Method, m.Path, m.Permission}))
	if err != nil {
		t.Fatal(err)
	}
	s, err := apihost.Build(doc, []apihost.TagHandlers{apihost.NewTagHandlers("widgets", r.route())},
		apihost.Policy{}, catalogue, newPorts().ports(), apihost.WithBodyBudget(budget))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// stalledBody blocks on Read until closed, and signals the first Read: readBody reads only after the
// request has reserved its buffer.
type stalledBody struct {
	once    sync.Once
	reading chan struct{}
	release chan struct{}
}

func (b *stalledBody) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.reading) })
	<-b.release
	return 0, io.EOF
}

// stalled returns a request that declares n bytes and sends none until released.
func stalled(n int) (*http.Request, *stalledBody) {
	body := &stalledBody{reading: make(chan struct{}), release: make(chan struct{})}
	req := httptest.NewRequest("POST", "/api/v1/widgets", body)
	req.RemoteAddr = "192.0.2.7:4000"
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(n)
	return req, body
}

func TestBodyBudgetBoundsConcurrentHeldBuffers(t *testing.T) {
	const declared = 1 << 10 // = the route's MaxBody
	s := budgetServer(t, 3*declared)

	var wg sync.WaitGroup
	var held []*stalledBody
	for range 3 {
		req, body := stalled(declared)
		held = append(held, body)
		wg.Add(1)
		go func() { defer wg.Done(); s.ServeHTTP(httptest.NewRecorder(), req) }()
	}
	for _, b := range held {
		select {
		case <-b.reading:
		case <-time.After(5 * time.Second):
			t.Fatal("holder never reached the body read")
		}
	}
	// The budget is spent: the fourth is refused at once, without being read.
	req, _ := stalled(declared)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	problemOf(t, rec, 429, apitypes.ProblemTypeRateLimited)
	if rec.Header().Get("Retry-After") == "" {
		t.Error("refusal carries no Retry-After")
	}

	for _, b := range held {
		close(b.release)
	}
	wg.Wait()
	// Everything released: a request fits again.
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, post("/widgets", "application/json", `{"name":"a"}`))
	if rec.Code == 429 {
		t.Fatalf("budget was not released: %s", rec.Body)
	}
}

func TestBodyBudgetMustBePositive(t *testing.T) {
	r := jsonRow()
	m := r.meta
	doc, _ := apihost.ParseDocument(docJSON([4]string{m.OperationID, m.Method, m.Path, m.Permission}))
	if _, err := apihost.Build(doc, []apihost.TagHandlers{apihost.NewTagHandlers("widgets", r.route())},
		apihost.Policy{}, catalogue, newPorts().ports(), apihost.WithBodyBudget(0)); err == nil {
		t.Fatal("Build accepted a zero budget")
	}
}

func TestOversizedContentLengthIs413AndSpendsNoBudget(t *testing.T) {
	const max = 1 << 10 // the route's MaxBody
	s := budgetServer(t, 16)
	req, _ := stalled(max + 1)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	problemOf(t, rec, 413, apitypes.ProblemTypePayloadTooLarge)
	// Budget untouched: a small body still fits.
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, post("/widgets", "application/json", `{"name":"a"}`))
	if rec.Code == 429 {
		t.Fatalf("oversized declaration consumed the budget: %s", rec.Body)
	}
}

// partitionServer mounts an authenticated write route and an anonymous write route.
func partitionServer(t *testing.T, total, anon int64) *apihost.Server {
	t.Helper()
	w := jsonRow()
	a := &row{meta: meta("enrol", "POST", "/enrol", "anonymous")}
	a.meta.Body, a.meta.MediaType, a.meta.Class = apihost.BodyJSON, "application/json", "anonymous"
	doc, err := apihost.ParseDocument(docJSON(
		[4]string{w.meta.OperationID, "POST", "/widgets", "widgets.write"},
		[4]string{"enrol", "POST", "/enrol", "anonymous"}))
	if err != nil {
		t.Fatal(err)
	}
	s, err := apihost.Build(doc, []apihost.TagHandlers{apihost.NewTagHandlers("widgets", w.route(), a.route())},
		apihost.Policy{Anonymous: []apihost.AnonymousRow{{Operation: "enrol"}}}, catalogue, newPorts().ports(),
		apihost.WithBodyBudget(total), apihost.WithAnonymousBodyBudget(anon))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAnonymousFloodCannotStarveAuthenticatedWrites(t *testing.T) {
	const declared = 1 << 10 // = each route's MaxBody
	s := partitionServer(t, 8*declared, 2*declared)

	var wg sync.WaitGroup
	var held []*stalledBody
	for i := range 2 { // N concurrent anonymous requests from distinct sources, each declaring the cap
		body := &stalledBody{reading: make(chan struct{}), release: make(chan struct{})}
		req := httptest.NewRequest("POST", "/api/v1/enrol", body)
		req.RemoteAddr = "198.51.100." + string(rune('1'+i)) + ":4000"
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = declared
		held = append(held, body)
		wg.Add(1)
		go func() { defer wg.Done(); s.ServeHTTP(httptest.NewRecorder(), req) }()
	}
	for _, b := range held {
		select {
		case <-b.reading:
		case <-time.After(5 * time.Second):
			t.Fatal("holder never reached the body read")
		}
	}
	anon := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, post("/enrol", "application/json", `{"name":"a"}`))
		return rec
	}
	authed := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, post("/widgets", "application/json", `{"name":"a"}`))
		return rec
	}
	// The anonymous pool is spent: the next anonymous request is refused, the authenticated one is not.
	rec := anon()
	problemOf(t, rec, 429, apitypes.ProblemTypeRateLimited)
	if rec.Header().Get("Retry-After") == "" {
		t.Error("refusal carries no Retry-After")
	}
	if rec := authed(); rec.Code != 200 {
		t.Fatalf("authenticated write starved by anonymous flood: %d %s", rec.Code, rec.Body)
	}

	for _, b := range held {
		close(b.release)
	}
	wg.Wait()
	// Released: both pools are full again.
	if rec := anon(); rec.Code == 429 {
		t.Fatalf("anonymous pool not released: %s", rec.Body)
	}
	if rec := authed(); rec.Code != 200 {
		t.Fatalf("authenticated pool: %d %s", rec.Code, rec.Body)
	}
}

func TestAnonymousBudgetMustFitTheTotal(t *testing.T) {
	r := jsonRow()
	m := r.meta
	doc, _ := apihost.ParseDocument(docJSON([4]string{m.OperationID, m.Method, m.Path, m.Permission}))
	for _, anon := range []int64{-1, 2048} {
		if _, err := apihost.Build(doc, []apihost.TagHandlers{apihost.NewTagHandlers("widgets", r.route())},
			apihost.Policy{}, catalogue, newPorts().ports(), apihost.WithBodyBudget(1024), apihost.WithAnonymousBodyBudget(anon)); err == nil {
			t.Errorf("Build accepted anonymous budget %d over a total of 1024", anon)
		}
	}
}
