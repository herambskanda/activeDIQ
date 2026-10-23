// Package gplink is the DM-23.I1 codec for the gPLink attribute, shared by the tier0 classifier (C9)
// and the connector's Plan/Apply step 7 so both read links one way.
//
// A value is a sequence of "[LDAP://<GPO DN>;<options>]" entries. The GPO is named by the first RDN
// of its DN (cn={GUID}), never by objectGUID. Options: 0x1 link disabled, 0x2 enforced. Order is
// left as stored; MS-GPOL gives no direction and DM-23.I1 tags link order [UNVERIFIED] [LAB: Windows]
// (the last entry is link order 1).
//
// Parsing is strict. A value or entry that does not parse is an error and callers must treat it as
// tier0 (connector-contract §8.1 C9): a link we cannot read is a link we cannot rule out.
package gplink

import (
	"errors"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// Option bits of a link.
const (
	Disabled uint32 = 0x1
	Enforced uint32 = 0x2
)

// MaxLinks bounds one value; a SOM with more links than this is refused.
const MaxLinks = 1024

// ErrMalformed is returned for any value or entry the codec rejects. It carries no value text.
var ErrMalformed = errors.New("gplink: malformed value")

// Link is one parsed entry.
type Link struct {
	GPO     dn.DN     // the GPO's DN as written in the link
	GPOID   guid.GUID // the GPO's id: the first RDN (cn={GUID}) of GPO
	Options uint32
}

// Disabled reports whether the link is switched off. A disabled link still counts for tier0:
// enabling it is one write.
func (l Link) Disabled() bool { return l.Options&Disabled != 0 }

// Enforced reports whether the link is enforced.
func (l Link) Enforced() bool { return l.Options&Enforced != 0 }

const scheme = "ldap://"

// Parse reads a gPLink value. The empty string and a lone space are "no links" (AD stores both).
func Parse(value string) ([]Link, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var out []Link
	rest := value
	for rest != "" {
		if len(out) >= MaxLinks || rest[0] != '[' {
			return nil, ErrMalformed
		}
		body, tail, ok := cutEntry(rest[1:])
		if !ok {
			return nil, ErrMalformed
		}
		l, err := parseEntry(body)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
		rest = tail
	}
	return out, nil
}

// cutEntry returns the text up to the first "]" that follows ";<digits>" and ends the entry, and what
// follows it. A "]" inside an (escaped) DN value is not an end because only ";<digits>]" closes.
func cutEntry(s string) (body, tail string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] != ';' {
			continue
		}
		j := i + 1
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j > i+1 && j < len(s) && s[j] == ']' && (j+1 == len(s) || s[j+1] == '[') {
			return s[:j], s[j+1:], true
		}
	}
	return "", "", false
}

func parseEntry(body string) (Link, error) {
	if len(body) < len(scheme) || !strings.EqualFold(body[:len(scheme)], scheme) {
		return Link{}, ErrMalformed
	}
	body = body[len(scheme):]
	semi := strings.LastIndexByte(body, ';')
	if semi < 0 {
		return Link{}, ErrMalformed
	}
	var opts uint64
	for _, c := range []byte(body[semi+1:]) {
		opts = opts*10 + uint64(c-'0')
		if opts > 0xFFFFFFFF {
			return Link{}, ErrMalformed
		}
	}
	d, err := dn.Parse(body[:semi], dn.Strict)
	if err != nil {
		return Link{}, ErrMalformed
	}
	rdns := d.RDNs()
	if len(rdns) == 0 || rdns[0].Type() != dn.CN {
		return Link{}, ErrMalformed
	}
	id, err := guid.Parse(rdns[0].Value())
	if err != nil {
		return Link{}, ErrMalformed
	}
	return Link{GPO: d, GPOID: id, Options: uint32(opts)}, nil
}
