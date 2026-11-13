// Package clienttest is an in-memory directory for tests of the connector clients: a tree of OUs and
// users that answers ScopedSearch (roots, depth, a substring filter) and the container reads a
// parent-chain walk makes, and records what it was asked. It is for tests only (like authztest);
// directory behaviour itself is proved against Samba in the lab tests.
package clienttest

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"google.golang.org/grpc"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Node is an object of the fake directory. Parent is "" for the head of the naming context.
type Node struct {
	GUID, Parent string // canonical text GUIDs
	User         bool
	Display, Sam string
	Disabled     bool
}

// Directory is the fake. Build it with New; the zero value has no nodes.
type Directory struct {
	mu    sync.Mutex
	nodes map[string]Node
	order []string

	// ReadErr, when set, is returned by every container read.
	ReadErr error

	// SearchOpenErr, when set, is returned by ScopedSearch before any stream exists. SearchStreamErr,
	// when set, ends the stream after its first batch (a mid-stream failure) instead of completing it.
	SearchOpenErr   error
	SearchStreamErr error

	// Recorded traffic.
	Searches [][]string // for each ScopedSearch call, the root GUIDs asked
	Depths   []connectorv1.SearchDepth
	Reads    []string // container GUIDs read
}

// New returns a directory holding nodes (parents may be listed after their children).
func New(nodes ...Node) *Directory {
	d := &Directory{nodes: map[string]Node{}}
	for _, n := range nodes {
		d.nodes[n.GUID] = n
		d.order = append(d.order, n.GUID)
	}
	return d
}

func wire(text string) *connectorv1.Guid {
	b, err := hex.DecodeString(strings.ReplaceAll(text, "-", ""))
	if err != nil || len(b) != 16 {
		panic("clienttest: bad guid " + text)
	}
	return &connectorv1.Guid{Value: b}
}

func text(g *connectorv1.Guid) string {
	b := g.GetValue()
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Connector implements client.ConnectorSource.
func (d *Directory) Connector(context.Context, string) (connectorv1.ConnectorClient, error) {
	return &conn{d: d}, nil
}

var _ client.ConnectorSource = (*Directory)(nil)

// Object implements client.Reads: one container read, live.
func (d *Directory) Object(_ context.Context, pins authority.Pins, _ authority.TargetRef, guid string, _ bool) (client.ObjectRead, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Reads = append(d.Reads, guid)
	if d.ReadErr != nil {
		return client.ObjectRead{}, d.ReadErr
	}
	if len(pins) != 0 {
		return client.ObjectRead{}, errors.New("clienttest: a scope-root ancestry read carries no pins")
	}
	n, ok := d.nodes[guid]
	return client.ObjectRead{Exists: ok, Parent: n.Parent}, nil
}

var _ client.Reads = (*Directory)(nil)

type conn struct {
	connectorv1.ConnectorClient
	d *Directory
}

func (c *conn) ScopedSearch(_ context.Context, in *connectorv1.ScopedSearchRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[connectorv1.ScopedSearchResponse], error) {
	d := c.d
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.SearchOpenErr != nil {
		return nil, d.SearchOpenErr
	}
	var roots []string
	for _, r := range in.GetRoots() {
		roots = append(roots, text(r.GetGuid()))
	}
	d.Searches = append(d.Searches, roots)
	d.Depths = append(d.Depths, in.GetDepth())
	needle := strings.ToLower(substring(in.GetFilter()))
	var entries []*connectorv1.DirectoryEntry
	for _, g := range d.order {
		n := d.nodes[g]
		if !n.User || !(strings.Contains(strings.ToLower(n.Display), needle) || strings.Contains(strings.ToLower(n.Sam), needle)) {
			continue
		}
		if !d.under(n, roots, in.GetDepth()) {
			continue
		}
		e := &connectorv1.DirectoryEntry{ObjectGuid: wire(n.GUID)}
		if n.Parent != "" {
			e.ParentGuid = wire(n.Parent)
		}
		uac := int32(0)
		if n.Disabled {
			uac = 2
		}
		e.Attributes = []*connectorv1.Attribute{
			attr("displayName", &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Text{Text: n.Display}}),
			attr("sAMAccountName", &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Text{Text: n.Sam}}),
			attr("userAccountControl", &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Int32Value{Int32Value: uac}}),
		}
		entries = append(entries, e)
	}
	if d.SearchStreamErr != nil {
		return &stream{
			msgs: []*connectorv1.ScopedSearchResponse{{Event: &connectorv1.ScopedSearchResponse_Batch{Batch: &connectorv1.SearchBatch{Entries: entries}}}},
			end:  d.SearchStreamErr,
		}, nil
	}
	return &stream{msgs: []*connectorv1.ScopedSearchResponse{
		{Event: &connectorv1.ScopedSearchResponse_Batch{Batch: &connectorv1.SearchBatch{Entries: entries}}},
		{Event: &connectorv1.ScopedSearchResponse_Completed{Completed: &connectorv1.SearchCompleted{}}},
	}}, nil
}

// under: n is in the subtree of a root (the root itself excluded as a user), or a direct child.
func (d *Directory) under(n Node, roots []string, depth connectorv1.SearchDepth) bool {
	for _, r := range roots {
		if depth == connectorv1.SearchDepth_SEARCH_DEPTH_ONE_LEVEL {
			if n.Parent == r {
				return true
			}
			continue
		}
		for cur, hops := n.Parent, 0; cur != "" && hops < 100; hops++ {
			if cur == r {
				return true
			}
			cur = d.nodes[cur].Parent
		}
	}
	return false
}

func attr(name string, v *connectorv1.AttributeValue) *connectorv1.Attribute {
	return &connectorv1.Attribute{Name: name, Values: []*connectorv1.AttributeValue{v}}
}

// substring finds the first substring node's text in a filter tree.
func substring(f *connectorv1.Filter) string {
	switch n := f.GetNode().(type) {
	case *connectorv1.Filter_Substring:
		if a := n.Substring.GetAny(); len(a) > 0 {
			return a[0]
		}
	case *connectorv1.Filter_And:
		for _, c := range n.And.GetChildren() {
			if s := substring(c); s != "" {
				return s
			}
		}
	case *connectorv1.Filter_Or:
		for _, c := range n.Or.GetChildren() {
			if s := substring(c); s != "" {
				return s
			}
		}
	}
	return ""
}

type stream struct {
	grpc.ClientStream
	msgs []*connectorv1.ScopedSearchResponse
	end  error // returned once msgs run out, instead of io.EOF
}

func (s *stream) Recv() (*connectorv1.ScopedSearchResponse, error) {
	if len(s.msgs) == 0 {
		if s.end != nil {
			return nil, s.end
		}
		return nil, io.EOF
	}
	m := s.msgs[0]
	s.msgs = s.msgs[1:]
	return m, nil
}
