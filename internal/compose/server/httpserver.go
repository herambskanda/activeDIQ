package server

import (
	"net/http"
	"time"
)

// Limits of the API listener. They are non-zero on purpose: a zero http.Server timeout means "wait
// forever", which lets a client that opens a connection and trickles bytes hold it (and the body
// buffer apihost reserves for it) indefinitely. They are fixed, not configuration, until a customer
// needs otherwise.
const (
	// APIReadHeaderTimeout bounds the time to read the request line and headers (slowloris).
	APIReadHeaderTimeout = 10 * time.Second
	// APIReadTimeout bounds the whole request read, headers and body. The largest JSON body is a
	// bulk request; a client that cannot deliver it in this time is too slow to be served.
	APIReadTimeout = 60 * time.Second
	// APIIdleTimeout bounds a keep-alive connection waiting for its next request.
	APIIdleTimeout = 120 * time.Second
	// APIMaxHeaderBytes caps request headers, including cookies and the Authorization header.
	APIMaxHeaderBytes = 32 << 10
)

// newAPIServer is the one place the API's http.Server is made. The write timeout is left to the
// handler chain: binary downloads and exports stream for as long as the client keeps reading, and a
// blanket WriteTimeout would cut them off. Total body memory is bounded by apihost's body budget.
func newAPIServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: APIReadHeaderTimeout,
		ReadTimeout:       APIReadTimeout,
		IdleTimeout:       APIIdleTimeout,
		MaxHeaderBytes:    APIMaxHeaderBytes,
	}
}
