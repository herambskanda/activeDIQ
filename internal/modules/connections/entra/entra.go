package entra

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"github.com/skenzeriq/activediq/internal/directory/odata"
	gs "github.com/skenzeriq/activediq/internal/directory/odata/graphschema"
	"github.com/skenzeriq/activediq/internal/modules/connections/idp"
	"github.com/skenzeriq/activediq/internal/platform/egress"
	"net/url"
	"strings"
	"time"
)

// HTTPDoer is the outbound client the adapters use: *egress.Client in production (threat model §5.9),
// an httptest client in tests. The adapters never build a transport of their own (FF-SP2).
type HTTPDoer = egress.Doer

// maxIdPBody caps what the adapters read from the token endpoint or idp.Graph.
const maxIdPBody = 1 << 20

// graphResource is the audience of a Microsoft idp.Graph access token (appId and URL forms).
// https://learn.microsoft.com/en-us/graph/auth/auth-concepts
const (
	graphAppID = "00000003-0000-0000-c000-000000000000"
	graphURL   = "https://graph.microsoft.com"
)

// Adapter errors. None carries a code, a token, a response body or a claim value.
var (
	ErrIdPExchange  = errors.New("connections: token endpoint refused the code")
	ErrIdPResponse  = errors.New("connections: token endpoint answer is not usable")
	ErrIdPClaims    = errors.New("connections: access token claims are not usable")
	ErrGraphRefused = errors.New("connections: graph refused the read")
	ErrGraphAnswer  = errors.New("connections: graph answer is not usable")
)

// OIDCIdP redeems an authorization code at login.microsoftonline.com (authorization code + PKCE,
// public client). It requests nothing but the attestation scope, so the endpoint issues no refresh
// token and no ID token; if it sent either anyway, they are never decoded into a field, so they die with
// the response. Only the access token, as a idp.Bearer, and the claims the flow needs leave Exchange.
type OIDCIdP struct {
	HTTP      HTTPDoer
	Authority string // https://login.microsoftonline.com; the tenant is appended per request
	ClientID  string
	Now       func() time.Time // nil: time.Now
}

var _ idp.IdP = (*OIDCIdP)(nil)

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

// Exchange implements idp.IdP.
func (i *OIDCIdP) Exchange(ctx context.Context, req idp.ExchangeRequest) (idp.Grant, error) {
	if i == nil || i.HTTP == nil || i.Authority == "" || i.ClientID == "" || req.TenantID == "" || req.Code == "" || req.CodeVerifier == "" {
		return idp.Grant{}, ErrIdPExchange
	}
	form := url.Values{}
	form.Set("client_id", i.ClientID)
	form.Set("grant_type", "authorization_code")
	form.Set("code", req.Code)
	form.Set("code_verifier", req.CodeVerifier)
	form.Set("redirect_uri", req.RedirectURI)
	form.Set("scope", strings.Join(req.Scopes, " "))
	endpoint := strings.TrimRight(i.Authority, "/") + "/" + url.PathEscape(req.TenantID) + "/oauth2/v2.0/token"
	resp, err := egress.Fetch(ctx, i.HTTP, egress.Request{Method: "POST", URL: endpoint,
		Header: map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
		Body:   []byte(form.Encode())}, maxIdPBody)
	if errors.Is(err, egress.ErrBody) {
		return idp.Grant{}, ErrIdPResponse
	}
	if err != nil {
		return idp.Grant{}, ErrIdPExchange // the transport error is dropped: it can quote the URL
	}
	if resp.Status != 200 {
		return idp.Grant{}, ErrIdPExchange // the error body names the cause and may echo input; not kept
	}
	body := resp.Body
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return idp.Grant{}, ErrIdPResponse
	}
	clear(body)
	if !strings.EqualFold(tr.TokenType, "Bearer") || tr.AccessToken == "" {
		return idp.Grant{}, ErrIdPResponse
	}
	claims, err := i.claims(tr.AccessToken, req.TenantID)
	if err != nil {
		return idp.Grant{}, err
	}
	scopes := claims.scopes()
	if len(scopes) == 0 {
		scopes = normaliseScopes(strings.Fields(tr.Scope))
	}
	return idp.Grant{TenantID: claims.TID, ObjectID: claims.OID, Scopes: scopes, Token: idp.NewBearer([]byte(tr.AccessToken))}, nil
}

type accessClaims struct {
	TID string         `json:"tid"`
	OID string         `json:"oid"`
	Iss string         `json:"iss"`
	Aud jsontext.Value `json:"aud"`
	Exp float64        `json:"exp"`
	Scp string         `json:"scp"`
}

func (c accessClaims) scopes() []string { return normaliseScopes(strings.Fields(c.Scp)) }

// claims reads the payload of the access token. The token came straight from the tenant-specific
// token endpoint over verified TLS, which is the channel OIDC Core §3.1.3.7 accepts in place of a
// signature check for a token received from the token endpoint. A idp.Graph access token is also not
// meant to be validated by its holder (its header carries a nonce); idp.Graph validates it on the read.
// So the signature is not checked here; the issuer, tenant, audience and expiry are.
// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
func (i *OIDCIdP) claims(jwt, wantTenant string) (accessClaims, error) {
	var c accessClaims
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return c, ErrIdPClaims
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(raw, &c) != nil {
		return c, ErrIdPClaims
	}
	now := time.Now
	if i.Now != nil {
		now = i.Now
	}
	switch {
	case c.TID == "" || c.OID == "":
		return c, ErrIdPClaims
	case !sameTenant(c.TID, wantTenant):
		return c, idp.ErrTenantMismatch
	case !issuerOfTenant(c.Iss, c.TID):
		return c, ErrIdPClaims
	case !graphAudience(c.Aud):
		return c, ErrIdPClaims
	case c.Exp <= 0 || !now().Before(time.Unix(int64(c.Exp), 0)):
		return c, ErrIdPClaims
	}
	return c, nil
}

// issuerOfTenant: the v2 issuer is https://login.microsoftonline.com/{tid}/v2.0 and the v1 issuer
// https://sts.windows.net/{tid}/. Anything else is not a token of this tenant.
func issuerOfTenant(iss, tid string) bool {
	tid = strings.ToLower(tid)
	iss = strings.ToLower(iss)
	return iss == "https://login.microsoftonline.com/"+tid+"/v2.0" || iss == "https://sts.windows.net/"+tid+"/"
}

func graphAudience(raw jsontext.Value) bool {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return false
	}
	s = strings.TrimRight(strings.ToLower(s), "/")
	return s == graphAppID || s == graphURL
}

// normaliseScopes turns "https://graph.microsoft.com/X" into "X": the token endpoint may return either form.
func normaliseScopes(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.TrimPrefix(s, graphURL+"/"))
	}
	return out
}

// GraphReader makes the one delegated read, GET /directory/onPremisesSynchronization.
// https://learn.microsoft.com/en-us/graph/api/onpremisesdirectorysynchronization-get?view=graph-rest-1.0
type GraphReader struct {
	HTTP HTTPDoer
	Base string // default https://graph.microsoft.com/v1.0
}

var _ idp.Graph = (*GraphReader)(nil)

type syncAnswer struct {
	Value []struct {
		Features struct {
			HardMatch *bool `json:"blockCloudObjectTakeoverThroughHardMatchEnabled"`
			SoftMatch *bool `json:"blockSoftMatchEnabled"`
		} `json:"features"`
	} `json:"value"`
}

// ReadSyncFeatures implements idp.Graph. The request selects the one property the flow reads. A flag
// that is absent from the answer is an error, never "false": an absent flag must not look attested
// or un-attested by accident.
func (g *GraphReader) ReadSyncFeatures(ctx context.Context, token idp.Bearer) (idp.SyncFeatures, error) {
	if g == nil || g.HTTP == nil {
		return idp.SyncFeatures{}, ErrGraphRefused
	}
	base := strings.TrimRight(g.Base, "/")
	if base == "" {
		base = graphURL + "/v1.0"
	}
	var out idp.SyncFeatures
	err := token.Use(func(b []byte) error {
		if len(b) == 0 {
			return ErrGraphRefused
		}
		bu, err := url.Parse(base)
		if err != nil {
			return ErrGraphRefused
		}
		// The URL is built by the odata primitive, never by concatenation (safe-primitives-odata §6).
		u, err := odata.Get(odata.Seg(gs.SegDirectory), odata.Seg(gs.SegOnPremisesSynchronization)).
			With(odata.Query{}.Select(gs.SyncFeatures)).URL(bu)
		if err != nil {
			return ErrGraphRefused
		}
		resp, err := egress.Fetch(ctx, g.HTTP, egress.Request{Method: "GET", URL: u.String(),
			Header: map[string]string{"Authorization": "Bearer " + string(b), "Accept": "application/json"}}, maxIdPBody)
		if errors.Is(err, egress.ErrBody) {
			return ErrGraphAnswer
		}
		if err != nil {
			return ErrGraphRefused
		}
		if resp.Status != 200 {
			return fmt.Errorf("%w: status %d", ErrGraphRefused, resp.Status)
		}
		body := resp.Body
		var a syncAnswer
		if json.Unmarshal(body, &a) != nil || len(a.Value) != 1 ||
			a.Value[0].Features.HardMatch == nil || a.Value[0].Features.SoftMatch == nil {
			return ErrGraphAnswer
		}
		out = idp.SyncFeatures{BlockCloudObjectTakeoverThroughHardMatch: *a.Value[0].Features.HardMatch,
			BlockSoftMatch: *a.Value[0].Features.SoftMatch}
		return nil
	})
	return out, err
}

func sameTenant(a, b string) bool {
	x, y := strings.ToLower(a), strings.ToLower(b)
	return x != "" && x == y
}
