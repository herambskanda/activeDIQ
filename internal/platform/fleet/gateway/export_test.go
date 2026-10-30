package gateway

import (
	"crypto/x509"
	"time"
)

// NextForTest exposes the jittered refresh interval to the external tests.
func (p *PoolProvider) NextForTest() time.Duration { return p.next() }

// CandidatesForTest is how many CAs a leaf makes the index try: the number of signature checks a
// verification can cost.
func (ix *CAIndex) CandidatesForTest(leaf *x509.Certificate) int { return len(ix.candidates(leaf)) }
