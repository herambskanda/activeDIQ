package agentpolicy_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
)

// F1 (agent-host-addc-contract C8, ADR-0007 rule 2): a policy outside the §3 bounds is rejected whole,
// at signing and at the agent, whatever the bytes say. Every bound has a case, so a loosened bound fails.
func TestF1OutOfBoundsPolicyRejected(t *testing.T) {
	long := strings.Repeat("a", agentpolicy.MaxBannedTermLen+1)
	cases := map[string]func(p *agentpolicy.AddcPolicy){
		"min_length 0":              func(p *agentpolicy.AddcPolicy) { p.Password.MinLength = 0 },
		"min_length 257":            func(p *agentpolicy.AddcPolicy) { p.Password.MinLength = 257 },
		"max_length below min":      func(p *agentpolicy.AddcPolicy) { p.Password.MaxLength = p.Password.MinLength - 1 },
		"max_length 257":            func(p *agentpolicy.AddcPolicy) { p.Password.MaxLength = 257 },
		"min_classes 5":             func(p *agentpolicy.AddcPolicy) { p.Password.MinClasses = 5 },
		"class 0":                   func(p *agentpolicy.AddcPolicy) { p.Password.ClassesRequired = []agentpolicy.Class{0} },
		"class 5":                   func(p *agentpolicy.AddcPolicy) { p.Password.ClassesRequired = []agentpolicy.Class{5} },
		"duplicate class":           func(p *agentpolicy.AddcPolicy) { p.Password.ClassesRequired = []agentpolicy.Class{1, 1} },
		"empty banned term":         func(p *agentpolicy.AddcPolicy) { p.Password.BannedTerms = []string{""} },
		"banned term over 64 units": func(p *agentpolicy.AddcPolicy) { p.Password.BannedTerms = []string{long} },
		"banned term invalid utf-8": func(p *agentpolicy.AddcPolicy) { p.Password.BannedTerms = []string{"\xff\xfe"} },
		"banned terms over 20000":   func(p *agentpolicy.AddcPolicy) { p.Password.BannedTerms = make([]string, agentpolicy.MaxBannedTerms+1) },
		"third channel":             func(p *agentpolicy.AddcPolicy) { p.Events.Channels = []agentpolicy.Channel{1, 2, 3} },
		"unknown channel":           func(p *agentpolicy.AddcPolicy) { p.Events.Channels = []agentpolicy.Channel{7} },
		"unsorted event ids":        func(p *agentpolicy.AddcPolicy) { p.Events.EventIDs = []uint32{4740, 4624} },
		"event id 0":                func(p *agentpolicy.AddcPolicy) { p.Events.EventIDs = []uint32{0} },
		"over 256 event ids":        func(p *agentpolicy.AddcPolicy) { p.Events.EventIDs = ascending(agentpolicy.MaxEventIDs + 1) },
		"events/s 0":                func(p *agentpolicy.AddcPolicy) { p.Events.MaxEventsPerSecond = 0 },
		"events/s over ceiling":     func(p *agentpolicy.AddcPolicy) { p.Events.MaxEventsPerSecond = agentpolicy.MaxEventsPerSec + 1 },
		"batch 0":                   func(p *agentpolicy.AddcPolicy) { p.Events.BatchMaxBytes = 0 },
		"batch above outbox":        func(p *agentpolicy.AddcPolicy) { p.Events.BatchMaxBytes = p.Events.OutboxMaxBytes + 1 },
		"outbox 0":                  func(p *agentpolicy.AddcPolicy) { p.Events.OutboxMaxBytes = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := pol()
			mutate(&p)
			if err := p.Validate(); !errors.Is(err, agentpolicy.ErrOutOfBounds) {
				t.Fatalf("Validate accepted an out-of-bounds policy: %v", err)
			}
			if _, err := p.Encode(); !errors.Is(err, agentpolicy.ErrOutOfBounds) {
				t.Fatalf("Encode signed-ready bytes for an out-of-bounds policy: %v", err)
			}
		})
	}
	// The in-bounds control, so a Validate that rejects everything cannot pass this test.
	if err := pol().Validate(); err != nil {
		t.Fatalf("control policy rejected: %v", err)
	}
}

func ascending(n int) []uint32 {
	ids := make([]uint32, n)
	for i := range ids {
		ids[i] = uint32(i + 1)
	}
	return ids
}

// FuzzF1DecodeOnlyAcceptsInBounds: for any bytes the agent decodes, the result is inside the bounds and
// re-encodes to the same bytes (one encoding per policy), so no hand-built body slips a value past
// Validate. The seeds are valid, boundary and hostile bodies; `make fitness-agent-host` runs it for 20 s.
func FuzzF1DecodeOnlyAcceptsInBounds(f *testing.F) {
	valid, err := pol().Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add(append(bytes.Clone(valid), 0))
	f.Add(valid[:len(valid)-1])
	for i := range valid {
		m := bytes.Clone(valid)
		m[i] ^= 0xff
		f.Add(m)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := agentpolicy.DecodeAddcPolicy(b)
		if err != nil {
			return
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("decoded a policy that fails Validate: %v", err)
		}
		again, err := p.Encode()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("accepted a non-canonical body (re-encode differs: %v)", err)
		}
	})
}
