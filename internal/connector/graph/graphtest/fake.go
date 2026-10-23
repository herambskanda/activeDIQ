// Package graphtest is an in-process fake Microsoft Graph and Entra token endpoint for tests of the
// connector and of the tickets that build on it. It verifies the client assertion for real
// (signature, audience, issuer, certificate thumbprint), serves the tenant's data with OData paging,
// and can inject throttling and failures. Not shipped: tests import it.
package graphtest

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/directory/odata/odatatest"
)

var b64 = base64.RawURLEncoding

// Tenant is the fake directory content. IDs must be GUIDs.
type Tenant struct {
	TenantID    string
	ClientID    string
	SPID        string // object id of the app's service principal
	AppObjectID string

	ServicePrincipals map[string]graph.ServicePrincipal    // by object id (needs SPID entry)
	Assignments       map[string][]graph.AppRoleAssignment // by principal id
	KeyCredentials    []graph.KeyCredential
	Owners            map[string][]graph.DirectoryObject // by application/SP/group object id
	Roles             []graph.RoleAssignment
	Groups            []graph.Group
	Members           map[string][]graph.DirectoryObject // by group id
	Applications      []graph.Application                // other apps' registrations, found by appId
	Users             []graph.DirectoryObject            // found by userPrincipalName or displayName; duplicates allowed
	// PasswordCredentials are the application's client secrets (metadata only).
	PasswordCredentials []graph.PasswordCredential
	// Memberships are the groups a principal (by object id) is a direct member of.
	Memberships map[string][]graph.Group
}

// Server is the fake. Fields are guarded by mu; use the helpers.
type Server struct {
	*httptest.Server
	T        *Tenant
	PageSize int // objects per page, default 2

	cert *x509.Certificate

	mu          sync.Mutex
	tokens      map[string]bool
	Assertions  []string // every accepted assertion, for tests to inspect
	TokenCalls  int
	GraphCalls  int
	Failures    []Failure // consumed in order by Graph calls
	TokenFail   []Failure // consumed in order by token calls
	AccessToken string
	TenantClaim string // tid put in tokens; defaults to Tenant.TenantID
}

// Failure makes one call return Status (with Retry-After when set).
type Failure struct {
	Status     int
	RetryAfter string
	Body       string
}

// NewCredential makes a self-signed RSA certificate and key.
func NewCredential(t testing.TB) graph.Credential {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "activediq-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return graph.Credential{Cert: cert, Key: key}
}

// New starts the fake (TLS) and registers cred's certificate for the tenant's app.
func New(t testing.TB, tn *Tenant, cred graph.Credential) *Server {
	t.Helper()
	s := &Server{T: tn, PageSize: 2, cert: cred.Cert, tokens: map[string]bool{}, AccessToken: "fake"}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// Config returns a client Config wired to the fake, trusting its certificate.
func (s *Server) Config(cred graph.Credential) graph.Config {
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	return graph.Config{
		TenantID: s.T.TenantID, ClientID: s.T.ClientID, Credential: cred,
		Authority: s.URL, GraphBase: s.URL + "/v1.0",
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}},
		Sleep:      func(_ context.Context, _ time.Duration) error { return nil },
	}
}

func (s *Server) FailGraph(f ...Failure) {
	s.mu.Lock()
	s.Failures = append(s.Failures, f...)
	s.mu.Unlock()
}
func (s *Server) FailToken(f ...Failure) {
	s.mu.Lock()
	s.TokenFail = append(s.TokenFail, f...)
	s.mu.Unlock()
}

func (s *Server) Calls() (token, graphCalls int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.TokenCalls, s.GraphCalls
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
		s.token(w, r)
		return
	}
	s.graph(w, r)
}

func (s *Server) inject(w http.ResponseWriter, f *[]Failure) bool {
	if len(*f) == 0 {
		return false
	}
	x := (*f)[0]
	*f = (*f)[1:]
	if x.RetryAfter != "" {
		w.Header().Set("Retry-After", x.RetryAfter)
	}
	w.WriteHeader(x.Status)
	fmt.Fprint(w, x.Body)
	return true
}

func oauthErr(w http.ResponseWriter, why string) {
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, `{"error":"invalid_client","error_description":%q}`, why)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TokenCalls++
	if s.inject(w, &s.TokenFail) {
		return
	}
	if r.URL.Path != "/"+s.T.TenantID+"/oauth2/v2.0/token" {
		oauthErr(w, "wrong tenant")
		return
	}
	_ = r.ParseForm()
	if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != s.T.ClientID ||
		r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		oauthErr(w, "bad request")
		return
	}
	if err := s.verifyAssertion(r.Form.Get("client_assertion"), "https://"+r.Host+r.URL.Path); err != nil {
		oauthErr(w, err.Error())
		return
	}
	s.Assertions = append(s.Assertions, r.Form.Get("client_assertion"))
	tid := s.TenantClaim
	if tid == "" {
		tid = s.T.TenantID
	}
	hdr, _ := json.Marshal(map[string]string{"alg": "none"})
	cl, _ := json.Marshal(map[string]any{"tid": tid, "appid": s.T.ClientID, "n": len(s.tokens)})
	tok := b64.EncodeToString(hdr) + "." + b64.EncodeToString(cl) + "." + s.AccessToken
	s.tokens[tok] = true
	_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "expires_in": 3599, "access_token": tok})
}

func (s *Server) verifyAssertion(a, aud string) error {
	parts := strings.Split(a, ".")
	if len(parts) != 3 {
		return fmt.Errorf("not a JWT")
	}
	var hdr struct {
		Alg string `json:"alg"`
		X5t string `json:"x5t#S256"`
	}
	var raw []byte
	var err error
	if raw, err = b64.DecodeString(parts[0]); err != nil || json.Unmarshal(raw, &hdr) != nil {
		return fmt.Errorf("bad header")
	}
	var cl struct {
		Aud, Iss, Sub string
		Exp, Nbf      int64
	}
	if raw, err = b64.DecodeString(parts[1]); err != nil || json.Unmarshal(raw, &cl) != nil {
		return fmt.Errorf("bad claims")
	}
	th := sha256.Sum256(s.cert.Raw)
	switch {
	case hdr.Alg != "PS256" || hdr.X5t != b64.EncodeToString(th[:]):
		return fmt.Errorf("unregistered certificate")
	case cl.Aud != aud:
		return fmt.Errorf("bad audience")
	case cl.Iss != s.T.ClientID || cl.Sub != s.T.ClientID:
		return fmt.Errorf("bad issuer")
	case time.Now().Unix() >= cl.Exp:
		return fmt.Errorf("expired")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("bad signature")
	}
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPSS(s.cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, d[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) != nil {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func (s *Server) graph(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.GraphCalls++
	ok := s.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	inj := s.inject(w, &s.Failures)
	s.mu.Unlock()
	if inj {
		return
	}
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	target, skip := splitSkip(r.RequestURI)
	req, err := odatatest.ParseRequest(target, "/v1.0")
	if err != nil { // the fake accepts exactly what the odata primitive emits
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":{"code":"Request_BadRequest","message":%q}}`, err.Error())
		return
	}
	t := s.T
	pg := func(items []any) { s.paged(w, r.Host, target, skip, items) }
	if len(req.Segments) == 1 && req.Segments[0].Kind == odatatest.SegAlt && req.Segments[0].Prop == "appId" {
		app := req.Segments[0].Val.Text
		switch req.Segments[0].Name {
		case "servicePrincipals":
			for _, sp := range t.ServicePrincipals {
				if sp.AppID == app {
					s.one(w, sp)
					return
				}
			}
			if app == t.ClientID { // the own SP, when the tenant does not list it by appId
				s.one(w, t.ServicePrincipals[t.SPID])
				return
			}
		case "applications":
			if app == t.ClientID {
				s.one(w, graph.Application{ID: t.AppObjectID, AppID: t.ClientID, DisplayName: "activeDIQ", KeyCredentials: t.KeyCredentials, PasswordCredentials: t.PasswordCredentials})
				return
			}
			for _, a := range t.Applications {
				if a.AppID == app {
					s.one(w, a)
					return
				}
			}
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var seg []string
	for _, sg := range req.Segments {
		switch sg.Kind {
		case odatatest.SegName, odatatest.SegCast:
			seg = append(seg, sg.Name)
		case odatatest.SegKey:
			seg = append(seg, sg.Val.Text)
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
	p := strings.Join(seg, "/")
	switch {
	case len(seg) == 3 && seg[0] == "servicePrincipals" && seg[2] == "appRoleAssignedTo":
		var out []graph.AppRoleAssignment
		for _, as := range t.Assignments {
			for _, a := range as {
				if a.ResourceID == seg[1] {
					out = append(out, a)
				}
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		pg(anySlice(out))
	case len(seg) == 2 && seg[0] == "servicePrincipals":
		sp, found := t.ServicePrincipals[seg[1]]
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		s.one(w, sp)
	case len(seg) == 3 && seg[0] == "servicePrincipals" && seg[2] == "appRoleAssignments":
		pg(anySlice(t.Assignments[seg[1]]))
	case len(seg) == 4 && seg[0] == "servicePrincipals" && seg[2] == "memberOf" && seg[3] == "microsoft.graph.group":
		pg(anySlice(t.Memberships[seg[1]]))
	case len(seg) == 3 && seg[2] == "owners":
		pg(anySlice(t.Owners[seg[1]]))
	case len(seg) == 3 && seg[0] == "groups" && seg[2] == "members":
		pg(anySlice(t.Members[seg[1]]))
	case p == "groups":
		f := req.Filter
		if f == nil || f.Op != "eq" || f.Prop != "isAssignableToRole" || f.Lits[0].Kind != odatatest.LitBool {
			w.WriteHeader(http.StatusBadRequest) // the fake serves only the one group query the connector makes
			return
		}
		var gs []graph.Group
		for _, g := range t.Groups {
			if g.IsAssignableToRole == (f.Lits[0].Text == "true") {
				gs = append(gs, g)
			}
		}
		pg(anySlice(gs))
	case p == "users":
		// Lookups by userPrincipalName or displayName. Matching is case-insensitive, like Graph.
		f := req.Filter
		if f == nil || f.Op != "eq" || (f.Prop != "userPrincipalName" && f.Prop != "displayName") || f.Lits[0].Kind != odatatest.LitString {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var out []any
		for _, u := range t.Users {
			have := u.UserPrincipalName
			if f.Prop == "displayName" {
				have = u.DisplayName
			}
			if strings.EqualFold(have, f.Lits[0].Text) {
				out = append(out, u)
			}
		}
		pg(out)
	case p == "roleManagement/directory/roleAssignments", p == "roleManagement/directory/roleEligibilitySchedules":
		want := strings.HasSuffix(p, "Schedules")
		principal := ""
		if f := req.Filter; f != nil {
			if f.Op != "eq" || f.Prop != "principalId" || f.Lits[0].Kind != odatatest.LitString {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			principal = f.Lits[0].Text
		}
		var out []any
		for _, ra := range t.Roles {
			if ra.Eligible == want && (principal == "" || ra.PrincipalID == principal) {
				out = append(out, map[string]any{"id": ra.ID, "principalId": ra.PrincipalID, "roleDefinitionId": ra.RoleDefinitionID,
					"directoryScopeId": ra.DirectoryScopeID, "roleDefinition": ra.Role,
					"principal": map[string]any{"id": ra.PrincipalID, "@odata.type": principalOData(ra.PrincipalType)}})
			}
		}
		pg(out)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// splitSkip separates the fake's own paging token from the request target, so the rest can be
// parsed strictly. A real nextLink is opaque; the fake's is the same target plus fakepage=N (a name that is no OData system option, so no rule mistakes it for one).
func splitSkip(target string) (string, int) {
	path, query, has := strings.Cut(target, "?")
	if !has {
		return target, 0
	}
	skip := 0
	var keep []string
	for _, part := range strings.Split(query, "&") {
		if v, ok := strings.CutPrefix(part, "fakepage="); ok {
			skip, _ = strconv.Atoi(v)
			continue
		}
		keep = append(keep, part)
	}
	if len(keep) == 0 {
		return path, skip
	}
	return path + "?" + strings.Join(keep, "&"), skip
}

func anySlice[T any](v []T) []any {
	out := make([]any, len(v))
	for i := range v {
		out[i] = v[i]
	}
	return out
}

func (s *Server) one(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// paged serves items s.PageSize at a time, linking pages with @odata.nextLink: the request target
// plus fakepage=N (a name that is no OData system option, so no rule mistakes it for one).
func (s *Server) paged(w http.ResponseWriter, host, target string, skip int, items []any) {
	size := s.PageSize
	if size <= 0 {
		size = 2
	}
	end := min(skip+size, len(items))
	resp := map[string]any{"value": items[min(skip, len(items)):end]}
	if skip >= len(items) {
		resp["value"] = []any{}
	}
	if end < len(items) {
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		resp["@odata.nextLink"] = "https://" + host + target + sep + "fakepage=" + strconv.Itoa(end)
	}
	s.one(w, resp)
}

func principalOData(t string) string {
	if t == "" {
		return ""
	}
	return "#microsoft.graph." + t
}
