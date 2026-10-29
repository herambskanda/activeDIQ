package gateway

import "time"

// NextForTest exposes the jittered refresh interval to the external tests.
func (p *PoolProvider) NextForTest() time.Duration { return p.next() }
