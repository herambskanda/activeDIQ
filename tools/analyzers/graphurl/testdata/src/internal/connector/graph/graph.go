package graph

import (
	"net/http"
	"net/url"
	"strings"
)

func fx10(v url.Values, u *url.URL) {
	u.RawQuery = v.Encode() // want `assignment to url.URL.RawQuery` `url.Values.Encode in the Graph connector`
}

func rawPath(u *url.URL, s string) {
	u.RawPath = s // want `assignment to url.URL.RawPath`
	u.Path = s    // want `assignment to url.URL.Path`
}

func literal(s string) *url.URL {
	return &url.URL{Path: s} // want `url.URL literal sets Path`
}

func escapes(s string) string {
	return url.PathEscape(s) + url.QueryEscape(s) // want `url.PathEscape in the Graph connector` `url.QueryEscape in the Graph connector`
}

func stringURL(s string) {
	_, _ = http.NewRequest(http.MethodGet, "https://graph.example/v1.0/"+s, nil) // want `http.NewRequest outside policy.GraphHTTPSite`
}

// FX-17: a request made outside get/bearer skips the host pin, even from a URL's String().
func fx17(u *url.URL) {
	_, _ = http.NewRequest(http.MethodGet, u.String(), nil) // want `http.NewRequest outside policy.GraphHTTPSite`
}

// FX-18: other ways to send a request skip the host pin and the bearer-token destination check.
func fx18(c *http.Client, base, upn string, u *url.URL) {
	_, _ = http.Get(base + "/users/" + upn) // want `http client send Get outside policy.GraphHTTPSite`
	_, _ = c.Get(base + "/users/" + upn)    // want `http client send Get outside policy.GraphHTTPSite`
	req := &http.Request{URL: u}            // want `http.Request literal outside policy.GraphHTTPSite`
	req.URL = u                             // want `assignment to http.Request.URL outside policy.GraphHTTPSite`
	req.Host = upn                          // want `assignment to http.Request.Host outside policy.GraphHTTPSite`
	_, _ = c.Do(req)                        // want `http client send Do outside policy.GraphHTTPSite`
	_ = req.Header.Get("Authorization")     // Header.Get is not a send
}

type doer interface {
	Do(*http.Request) (*http.Response, error)
}

// FX-18b: any call taking *http.Request and returning *http.Response is a send.
func fx18b(c *http.Client, req *http.Request, d doer, s string) {
	_, _ = c.Transport.RoundTrip(req)           // want `http client send RoundTrip outside policy.GraphHTTPSite`
	_, _ = http.DefaultTransport.RoundTrip(req) // want `http client send RoundTrip outside policy.GraphHTTPSite`
	_, _ = d.Do(req)                            // want `http client send Do outside policy.GraphHTTPSite`
	_, _ = http.ReadRequest(nil)                // want `http.ReadRequest outside policy.GraphHTTPSite`
	_ = new(http.Request)                       // want `new\(http.Request\) outside policy.GraphHTTPSite`
}

type sender struct {
	do func(*http.Request) (*http.Response, error)
}

type rtFunc func(*http.Request) (*http.Response, error)

// FX-18c: a send through a function value (field, parameter, named func type) is still a send.
func fx18c(s sender, send func(*http.Request) (*http.Response, error), f rtFunc, req *http.Request) {
	_, _ = s.do(req) // want `http client send through a function value outside policy.GraphHTTPSite`
	_, _ = send(req) // want `http client send through a function value outside policy.GraphHTTPSite`
	_, _ = f(req)    // want `http client send through a function value outside policy.GraphHTTPSite`
}

// okReads: reading URL fields is fine.
func okReads(u *url.URL) {
	_ = u.Host
	_ = strings.ToLower(u.Path) // reading Path is fine
}

type Client struct {
	hc *http.Client
	do func(*http.Request) (*http.Response, error)
}

// get is a policy.GraphHTTPSite: the request comes from the String() of a *url.URL.
func (c *Client) get(u *url.URL) {
	_, _ = http.NewRequest(http.MethodGet, u.String(), nil)
	_, _ = c.do(&http.Request{URL: u})                               // a func-typed send in the listed site is allowed
	_, _ = c.hc.Do(&http.Request{URL: u})                            // get is the listed site
	_, _ = http.NewRequest(http.MethodGet, "https://x/"+u.Path, nil) // want `http.NewRequest with a URL that is not`
}

// bearer is listed in policy.GraphTokenURL as (*Client).bearer: the OAuth token endpoint is not OData.
func (c *Client) bearer(tokenURL string, form url.Values) {
	_, _ = http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
}

// A plain function or another receiver with the same name is not the listed site.
func bearer(u *url.URL, v url.Values) {
	u.RawQuery = v.Encode() // want `assignment to url.URL.RawQuery` `url.Values.Encode in the Graph connector`
}

type other struct{}

func (o other) bearer(u *url.URL, v url.Values) {
	u.RawQuery = v.Encode() // want `assignment to url.URL.RawQuery` `url.Values.Encode in the Graph connector`
}

// FX-14 to FX-16: other URL fields, and a parse function used as a value.
func fx14(h, upn string, u *url.URL) {
	_ = &url.URL{Scheme: "https", Host: h, Opaque: "//g/users/" + upn} // want `url.URL literal sets Scheme` `url.URL literal sets Host` `url.URL literal sets Opaque`
	u.Opaque = "//g/users/" + upn                                      // want `assignment to url.URL.Opaque`
	u.Host = h                                                         // want `assignment to url.URL.Host`
	_ = url.URL{"https", "", nil, h, "", "", "", "", "", false, false} // want `unkeyed url.URL literal`
}

func fx16(base, upn string) {
	p := url.Parse // want `url.Parse in the Graph connector`
	_, _ = p(base + upn)
}

// FX-12 and FX-13: a URL made from data by Parse or JoinPath.
func fx12(base, upn string) {
	u, _ := url.Parse(base + "/users/" + upn) // want `url.Parse in the Graph connector`
	_ = u
}

func fx13(b *url.URL, upn string) {
	_ = b.JoinPath("users", upn)       // want `url.JoinPath in the Graph connector`
	_, _ = url.ParseRequestURI(upn)    // want `url.ParseRequestURI in the Graph connector`
	_, _ = b.Parse(upn)                // want `url.Parse in the Graph connector`
	_ = b.ResolveReference(&url.URL{}) // want `url.ResolveReference in the Graph connector`
}

// list is a policy.GraphURLParse site: the host-pinned nextLink parse.
func list(next string) (*url.URL, error) { return url.Parse(next) }

// New is a policy.GraphURLParse site: the configured bases.
func New(base string) (*url.URL, error) { return url.Parse(base) }
