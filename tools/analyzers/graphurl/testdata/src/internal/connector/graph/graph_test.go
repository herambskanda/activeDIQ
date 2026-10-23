package graph

import "net/url"

func inTest(u *url.URL, s string) { u.Path = s }
