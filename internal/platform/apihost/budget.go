package apihost

import "sync"

// DefaultBodyBudget is the total of body buffers the router holds at once when WithBodyBudget is
// not given: 64 MiB. A buffer is allocated before its first byte arrives (ADR-0004 rule 6 step 1),
// so without a ceiling a crowd of connections declaring a large Content-Length and sending nothing
// pins memory that only the per-IP limiter bounds.
const DefaultBodyBudget int64 = 64 << 20

// bodyBudget is a non-blocking byte semaphore. A request reserves its buffer size before the buffer
// is allocated and releases it when the buffer is cleared; if the bytes are not there the request
// is refused at once rather than queued, so waiting cannot itself hold a connection.
type bodyBudget struct {
	mu    sync.Mutex
	free  int64
	total int64
}

func newBodyBudget(total int64) *bodyBudget { return &bodyBudget{free: total, total: total} }

// tryAcquire reserves n bytes, reporting false when fewer than n are free.
func (b *bodyBudget) tryAcquire(n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n > b.free {
		return false
	}
	b.free -= n
	return true
}

func (b *bodyBudget) release(n int64) {
	b.mu.Lock()
	b.free += n
	b.mu.Unlock()
}

// reserveSize is the number of bytes readBody will allocate for a request.
func reserveSize(contentLength, limit int64) int64 {
	if contentLength >= 0 {
		return contentLength
	}
	return limit + 1
}
