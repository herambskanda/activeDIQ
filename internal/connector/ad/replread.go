package ad

import (
	"context"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad/replxml"
)

// ReplAttr is one of the four msDS-Repl* rootDSE attributes of connector-contract §5.6. The set is
// closed: there is no constructor from a string, so the XML form of exactly these names is the only
// thing ReadReplication can ask a DC for. It never sends the ";binary" qualifier and never names
// the binary replication blobs (rule 3; fitness RX6).
type ReplAttr uint8

// The closed set. The zero value is not a valid attribute.
const (
	ReplInboundNeighbors ReplAttr = iota + 1
	ReplPendingOps
	ReplConnectionFailures
	ReplLinkFailures
)

// AllReplAttrs lists the four attributes in enum order.
var AllReplAttrs = []ReplAttr{ReplInboundNeighbors, ReplPendingOps, ReplConnectionFailures, ReplLinkFailures}

var replAttrNames = map[ReplAttr]string{
	ReplInboundNeighbors:   "msDS-ReplAllInboundNeighbors",
	ReplPendingOps:         "msDS-ReplPendingOps",
	ReplConnectionFailures: "msDS-ReplConnectionFailures",
	ReplLinkFailures:       "msDS-ReplLinkFailures",
}

// LDAPName is the attribute name that goes on the wire.
func (a ReplAttr) LDAPName() string { return replAttrNames[a] }

// ReplValues is what a DC returned for one attribute.
type ReplValues struct {
	// Present: the DC returned the attribute at all. A DC that returns nothing for it (Samba, or a
	// reader that cannot see it) leaves this false; that is NOT_RETURNED, never an empty list.
	Present bool
	// Values are the XML texts, one per value, ranges followed to the terminal range.
	Values [][]byte
	// RangeIncomplete: a ranged retrieval did not reach the "*" terminal range (the DC stopped
	// answering ranges, or the round-trip bound was hit). Values is then not to be used.
	RangeIncomplete bool
	// Denied: the DC refused this attribute with insufficient access rights.
	Denied bool
}

// ReplRead is the result of ReadReplication, keyed by attribute.
type ReplRead map[ReplAttr]ReplValues

// ReadReplication reads the requested msDS-Repl* attributes from the rootDSE of the bound DC, one
// base search per attribute so a refusal for one is a refusal for that attribute only. It sends
// no LDAP control (contract §5.6 rule 6: the call adds no write, no control and no privilege), so
// it does not use searchOnceLocked, which adds the domain-scope control. Multi-valued results are
// followed with attr;range=x-* until the terminal range (rule 5).
func (s *Session) ReadReplication(ctx context.Context, attrs []ReplAttr) (ReplRead, error) {
	if len(attrs) == 0 {
		return nil, fail(CodeInvalidArgument, "attributes required", nil)
	}
	for _, a := range attrs {
		if _, ok := replAttrNames[a]; !ok {
			return nil, fail(CodeInvalidArgument, "replication attribute", nil)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil, fail(CodeUnreachable, "session closed", nil)
	}
	stop := s.watch(ctx, s.conn)
	defer stop()

	out := make(ReplRead, len(attrs))
	for _, a := range attrs {
		if _, dup := out[a]; dup {
			continue
		}
		v, err := s.readOneReplAttr(ctx, a)
		if err != nil {
			if CodeOf(err) == CodeInsufficientRights {
				out[a] = ReplValues{Denied: true}
				continue
			}
			return nil, err
		}
		out[a] = v
	}
	return out, nil
}

func (s *Session) readOneReplAttr(ctx context.Context, a ReplAttr) (ReplValues, error) {
	name := a.LDAPName()
	lower := strings.ToLower(name)
	var v ReplValues
	size := 0
	req := name
	for round := 0; round < maxRangeRequests; round++ {
		res, err := s.searchRaw(ctx, "", ldap.ScopeBaseObject, objectClassPresent, []string{req}, nil)
		if err != nil {
			return ReplValues{}, err
		}
		if len(res.Entries) > 1 {
			return ReplValues{}, fail(CodeProtocol, "rootDSE returned more than once", nil)
		}
		got := false
		next, terminal := 0, true
		var attrs []*ldap.EntryAttribute
		if len(res.Entries) == 1 { // none: a reader that cannot see the rootDSE attributes; not returned
			attrs = res.Entries[0].Attributes
		}
		for _, at := range attrs {
			base, _, hi, star, isRange := splitRange(at.Name)
			if strings.ToLower(base) != lower {
				continue
			}
			got = true
			for _, b := range at.ByteValues {
				size += len(b)
			}
			if size > replxml.MaxCallBytes {
				// More than the decoder will take for one DC in one call (X2): stop reading.
				v.Present, v.RangeIncomplete, v.Values = true, true, nil
				return v, nil
			}
			v.Values = append(v.Values, at.ByteValues...)
			if isRange && !star {
				terminal, next = false, hi+1
			}
		}
		if !got {
			if round == 0 {
				return ReplValues{}, nil // not returned
			}
			v.Present, v.RangeIncomplete = true, true
			return v, nil
		}
		v.Present = true
		if terminal {
			return v, nil
		}
		req = name + ";range=" + strconv.Itoa(next) + "-*"
	}
	v.RangeIncomplete = true
	return v, nil
}
