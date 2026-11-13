package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/authority"
)

// TargetClassTier0Scope is the class of a target naming a connection's Tier-0 scope (inventory's
// TargetClassScope). Its GUID is a connection ID, not an object GUID, so no connector can be asked
// about it.
const TargetClassTier0Scope = "tier0_scope"

// maxAncestry bounds the parent walk. A chain that deeper (or that loops) is reported incomplete.
const maxAncestry = 64

// ErrNoReads is returned for a directory target when no connector read is wired. The read fails
// closed: the caller refuses the operation rather than authorising on guessed facts.
var ErrNoReads = errors.New("client: no connector read wired; facts unavailable")

// ObjectRead is what one live connector read of an object reports.
type ObjectRead struct {
	Exists bool
	// Tier0 is the connector's computed Tier-0 verdict for the object (the tier0 package).
	Tier0 bool
	// Parent is the objectGUID of the parent container; empty when the object is the head of its
	// naming context (it has no parent in the connection).
	Parent string
}

// Reads is the connector's read half as the facts reader needs it: one object, live, on the pins.
// ConnectorReads (reads.go) implements it over the connector's Read RPC. needTier0 asks for the
// Tier-0 verdict, which only the target's own read needs; a parent-chain read passes false.
type Reads interface {
	Object(ctx context.Context, pins authority.Pins, target authority.TargetRef, guid string, needTier0 bool) (ObjectRead, error)
}

// ConnectorFacts is the connector-backed FactsReader. It reads the target and, when asked, walks
// its parent chain, each read live on the pins.
type ConnectorFacts struct{ reads Reads }

// NewConnectorFacts returns the facts reader over reads. A nil reads is valid: every directory
// target then fails closed with ErrNoReads, while targets that are not directory objects (below)
// still answer.
func NewConnectorFacts(reads Reads) *ConnectorFacts { return &ConnectorFacts{reads: reads} }

// Facts implements FactsReader.
//
// A tier0_scope target carries a connection ID in the GUID position and a target in activeDIQ's own
// store (no connection) is not a directory object: neither is read. Both answer Exists with
// Tier0 false and no ancestry, so the Tier-0 guard neither refuses them as "tier0" nor fails closed
// on a read of an ID the directory has never heard of. The authorisation for them is the
// Authorizer's, from the grants alone.
func (c *ConnectorFacts) Facts(ctx context.Context, pins authority.Pins, q authority.FactsQuery) (authority.Facts, error) {
	t := q.Target
	if t.Class == TargetClassTier0Scope || t.Connection == "" {
		return authority.Facts{Exists: true}, nil
	}
	if c == nil || c.reads == nil {
		return authority.Facts{}, ErrNoReads
	}
	// A target still to be created has no GUID: its facts are those of its planned parent, so scope,
	// Tier-0 and ancestry are judged on the container it will land in, never on an empty GUID.
	guid := t.GUID
	if guid == "" {
		guid = t.Parent
	}
	obj, err := c.reads.Object(ctx, pins, t, guid, true)
	if err != nil {
		return authority.Facts{}, fmt.Errorf("client: reading target: %w", err)
	}
	f := authority.Facts{Exists: obj.Exists, Tier0: obj.Tier0}
	if !obj.Exists || !q.Ancestry {
		return f, nil
	}
	seen := map[string]bool{guid: true}
	for parent := obj.Parent; parent != ""; {
		if seen[parent] || len(f.Ancestors) >= maxAncestry {
			return f, nil // a loop or an absurd depth: incomplete, which fails closed
		}
		seen[parent] = true
		f.Ancestors = append(f.Ancestors, parent)
		p, err := c.reads.Object(ctx, pins, t, parent, false)
		if err != nil {
			return authority.Facts{}, fmt.Errorf("client: reading parent chain: %w", err)
		}
		if !p.Exists {
			return f, nil // a parent that vanished mid-read: incomplete
		}
		parent = p.Parent
	}
	f.AncestorsComplete = true
	return f, nil
}
