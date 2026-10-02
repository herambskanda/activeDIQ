package apitypes

// Presence records, for one decoded object, which members were present and which of those were
// JSON null. Generated structs hold it in an unexported field. v2 turns null into the zero value of
// a non-nullable member, so without this the validator could not report "null for a non-nullable
// member" (ADR-0004 rule 4, D-0014). Members are numbered in the generator's order; one object can
// have at most 64.
type Presence struct {
	set, null uint64
	decoded   bool
}

// Mark records member i as present, and as null when null is true.
func (p *Presence) Mark(i int, null bool) {
	p.decoded = true
	p.set |= 1 << uint(i)
	if null {
		p.null |= 1 << uint(i)
	}
}

// Decoded reports whether the value came from a decoder. A value built in code (a response) has no
// presence bits, so required-member checks apply only to decoded values.
func (p *Presence) Decoded() bool { return p.decoded }

// Begin marks the value as decoded even when it has no members.
func (p *Presence) Begin() { p.decoded = true }

// Has reports whether member i was present.
func (p *Presence) Has(i int) bool { return p.set&(1<<uint(i)) != 0 }

// IsNull reports whether member i was present and null.
func (p *Presence) IsNull(i int) bool { return p.null&(1<<uint(i)) != 0 }
