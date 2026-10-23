package m

import "net/url"

// Outside the Graph connector the pass says nothing (other rules govern it).
func f(u *url.URL, s string) { u.RawQuery = url.QueryEscape(s) }
