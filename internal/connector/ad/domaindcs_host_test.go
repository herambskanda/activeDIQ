package ad

import "testing"

func TestValidDCHostname(t *testing.T) {
	for h, want := range map[string]bool{
		"dc1.corp.example.com": true, "dc-1.corp": true, "dc1.corp.example.com.": true, "DC1": true,
		"": false, "host:22": false, "10.0.0.1": false, "::1": false, "[::1]": false, "a..b": false,
		"-a.b": false, "a b.c": false, "dc1/x.corp": false, "dc1,x": false,
	} {
		if got := ValidDCHostname(h); got != want {
			t.Errorf("%q: got %v want %v", h, got, want)
		}
	}
}
