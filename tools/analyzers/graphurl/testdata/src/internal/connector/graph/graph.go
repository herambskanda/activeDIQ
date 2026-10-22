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
	return &url.URL{Scheme: "https", Path: s} // want `url.URL literal sets Path`
}

func escapes(s string) string {
	return url.PathEscape(s) + url.QueryEscape(s) // want `url.PathEscape in the Graph connector` `url.QueryEscape in the Graph connector`
}

func stringURL(s string) {
	_, _ = http.NewRequest(http.MethodGet, "https://graph.example/v1.0/"+s, nil) // want `http.NewRequest with a URL that is not`
}

// okPinned: the String() of a *url.URL is the odata result or a pinned nextLink.
func okPinned(u *url.URL) {
	_, _ = http.NewRequest(http.MethodGet, u.String(), nil)
	_ = u.Host
	_ = strings.ToLower(u.Path) // reading Path is fine
}

// bearer is listed in policy.GraphTokenURL: the OAuth token endpoint is not OData.
func bearer(tokenURL string, form url.Values) {
	_, _ = http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
}
