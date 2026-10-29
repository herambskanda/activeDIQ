package agentpolicy

import (
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// Class is a character class a password must draw from.
type Class uint8

// Password character classes.
const (
	ClassLower Class = iota + 1
	ClassUpper
	ClassDigit
	ClassSymbol
)

// Channel is an event log channel the agent may collect (§3: these two and no other).
type Channel uint8

// Collectable channels.
const (
	ChannelSecurity Channel = iota + 1
	ChannelDirectoryService
)

// Bounds of agent-host-addc-contract §3. The agent compiles the same constants in; a document cannot
// change them, and a value outside them rejects the whole document.
const (
	MaxPasswordLength = 256
	MaxBannedTerms    = 20_000
	MaxBannedTermLen  = 64 // UTF-16 code units
	MaxBannedBytes    = 1 << 20
	MaxEventIDs       = 256
	MaxEventsPerSec   = 100_000 // server-side sanity ceiling; the agent narrows it to its local ceiling
	maxBodyBytes      = MaxBannedBytes + 64<<10
)

// ErrOutOfBounds is returned for a policy body outside the schema bounds.
var ErrOutOfBounds = errors.New("agentpolicy: policy is outside the schema bounds")

// PasswordRules is the password half of AddcPolicy.
type PasswordRules struct {
	MinLength uint32
	MaxLength uint32
	// ClassesRequired is a set: strictly increasing, no duplicates.
	ClassesRequired []Class
	MinClasses      uint8
	// BannedTerms are matched as literal substrings. They are never interpreted: no regular
	// expression exists in the schema (ReDoS next to LSASS).
	BannedTerms            []string
	RejectSAMInPassword    bool
	RejectDisplayNameParts bool
}

// EventRules is the event collection half of AddcPolicy.
type EventRules struct {
	// CollectionEnabled false is allowed by design (TM-R7) and is always reported by the agent.
	CollectionEnabled bool
	// Channels is a set: strictly increasing, no duplicates.
	Channels []Channel
	// EventIDs is a set: strictly increasing, no duplicates. The agent also checks each against its
	// compiled-in catalogue; the server cannot know that catalogue.
	EventIDs           []uint32
	MaxEventsPerSecond uint32
	BatchMaxBytes      uint32
	OutboxMaxBytes     uint32
}

// AddcPolicy is the whole policy of the addc module (§3): typed data inside bounds, never code, a
// path, a URL, a command or a regular expression.
type AddcPolicy struct {
	Password PasswordRules
	Events   EventRules
}

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrOutOfBounds, fmt.Sprintf(format, a...))
}

// Validate checks every bound of §3. It names the field, never the value.
func (p AddcPolicy) Validate() error {
	pw := p.Password
	switch {
	case pw.MinLength < 1 || pw.MinLength > MaxPasswordLength:
		return bad("password.min_length")
	case pw.MaxLength < pw.MinLength || pw.MaxLength > MaxPasswordLength:
		return bad("password.max_length")
	case pw.MinClasses > 4:
		return bad("password.min_classes")
	case len(pw.ClassesRequired) > 4:
		return bad("password.classes_required")
	}
	for i, c := range pw.ClassesRequired {
		if c < ClassLower || c > ClassSymbol || (i > 0 && pw.ClassesRequired[i-1] >= c) {
			return bad("password.classes_required")
		}
	}
	if len(pw.BannedTerms) > MaxBannedTerms {
		return bad("password.banned_terms count")
	}
	total := 0
	for _, t := range pw.BannedTerms {
		total += len(t)
		if t == "" || !utf8.ValidString(t) || len(utf16.Encode([]rune(t))) > MaxBannedTermLen || total > MaxBannedBytes {
			return bad("password.banned_terms entry")
		}
	}
	ev := p.Events
	if len(ev.Channels) > 2 {
		return bad("events.channels")
	}
	for i, c := range ev.Channels {
		if c < ChannelSecurity || c > ChannelDirectoryService || (i > 0 && ev.Channels[i-1] >= c) {
			return bad("events.channels")
		}
	}
	if len(ev.EventIDs) > MaxEventIDs {
		return bad("events.event_ids")
	}
	for i, id := range ev.EventIDs {
		if id == 0 || (i > 0 && ev.EventIDs[i-1] >= id) {
			return bad("events.event_ids")
		}
	}
	if ev.MaxEventsPerSecond < 1 || ev.MaxEventsPerSecond > MaxEventsPerSec {
		return bad("events.max_events_per_second")
	}
	if ev.BatchMaxBytes == 0 || ev.OutboxMaxBytes == 0 || ev.BatchMaxBytes > ev.OutboxMaxBytes {
		return bad("events batch/outbox bytes")
	}
	return nil
}

// Encode is the canonical body encoding. It validates first: an out-of-bounds policy is never signed.
func (p AddcPolicy) Encode() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	var e enc
	pw := p.Password
	e.u32(pw.MinLength)
	e.u32(pw.MaxLength)
	e.u8(uint8(len(pw.ClassesRequired)))
	for _, c := range pw.ClassesRequired {
		e.u8(uint8(c))
	}
	e.u8(pw.MinClasses)
	e.u32(uint32(len(pw.BannedTerms)))
	for _, t := range pw.BannedTerms {
		e.str(t)
	}
	e.u8(boolByte(pw.RejectSAMInPassword))
	e.u8(boolByte(pw.RejectDisplayNameParts))
	ev := p.Events
	e.u8(boolByte(ev.CollectionEnabled))
	e.u8(uint8(len(ev.Channels)))
	for _, c := range ev.Channels {
		e.u8(uint8(c))
	}
	e.u32(uint32(len(ev.EventIDs)))
	for _, id := range ev.EventIDs {
		e.u32(id)
	}
	e.u32(ev.MaxEventsPerSecond)
	e.u32(ev.BatchMaxBytes)
	e.u32(ev.OutboxMaxBytes)
	return e.b, nil
}

func boolByte(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// DecodeAddcPolicy parses and validates a body. Any trailing byte, non-canonical boolean or value
// outside the bounds rejects the document whole.
func DecodeAddcPolicy(b []byte) (AddcPolicy, error) {
	if len(b) > maxBodyBytes {
		return AddcPolicy{}, ErrMalformed
	}
	d := dec{b: b}
	var p AddcPolicy
	pw := &p.Password
	pw.MinLength, pw.MaxLength = d.u32(), d.u32()
	for n := d.u8(); n > 0 && d.err == nil; n-- {
		pw.ClassesRequired = append(pw.ClassesRequired, Class(d.u8()))
	}
	pw.MinClasses = d.u8()
	nTerms := d.u32()
	if d.err == nil && nTerms > MaxBannedTerms {
		return AddcPolicy{}, bad("password.banned_terms count")
	}
	for i := uint32(0); i < nTerms && d.err == nil; i++ {
		pw.BannedTerms = append(pw.BannedTerms, d.str(MaxBannedBytes))
	}
	pw.RejectSAMInPassword = d.flag()
	pw.RejectDisplayNameParts = d.flag()
	ev := &p.Events
	ev.CollectionEnabled = d.flag()
	for n := d.u8(); n > 0 && d.err == nil; n-- {
		ev.Channels = append(ev.Channels, Channel(d.u8()))
	}
	nIDs := d.u32()
	if d.err == nil && nIDs > MaxEventIDs {
		return AddcPolicy{}, bad("events.event_ids")
	}
	for i := uint32(0); i < nIDs && d.err == nil; i++ {
		ev.EventIDs = append(ev.EventIDs, d.u32())
	}
	ev.MaxEventsPerSecond, ev.BatchMaxBytes, ev.OutboxMaxBytes = d.u32(), d.u32(), d.u32()
	if err := d.done(); err != nil {
		return AddcPolicy{}, err
	}
	if err := p.Validate(); err != nil {
		return AddcPolicy{}, err
	}
	return p, nil
}

// flag reads a boolean that must be exactly 0 or 1, so a body has one encoding.
func (d *dec) flag() bool {
	switch d.u8() {
	case 0:
		return false
	case 1:
		return true
	}
	if d.err == nil {
		d.err = ErrMalformed
	}
	return false
}
