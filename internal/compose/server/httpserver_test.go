package server

import (
	"net/http"
	"testing"
)

func TestAPIServerTimeoutsAreSet(t *testing.T) {
	s := newAPIServer("127.0.0.1:0", http.NotFoundHandler())
	for name, d := range map[string]int64{
		"ReadHeaderTimeout": int64(s.ReadHeaderTimeout), "ReadTimeout": int64(s.ReadTimeout),
		"IdleTimeout": int64(s.IdleTimeout), "MaxHeaderBytes": int64(s.MaxHeaderBytes),
	} {
		if d <= 0 {
			t.Errorf("%s is %d; a zero value means no limit", name, d)
		}
	}
	if s.ReadHeaderTimeout > s.ReadTimeout {
		t.Errorf("ReadHeaderTimeout %v exceeds ReadTimeout %v", s.ReadHeaderTimeout, s.ReadTimeout)
	}
	if s.MaxHeaderBytes >= http.DefaultMaxHeaderBytes*2 {
		t.Errorf("MaxHeaderBytes %d is not a considered cap", s.MaxHeaderBytes)
	}
}
