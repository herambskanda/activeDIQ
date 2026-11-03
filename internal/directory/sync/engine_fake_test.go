package sync_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	gosync "sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/directory/client"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// fnode is one object of the fake forest. parent 0 is the head of the naming context.
type fnode struct {
	n, parent uint64
	class     []string
	sam       string
	dn        string
	rid       uint32   // objectSid = domain SID + rid, when non-zero
	members   []uint64 // groups: member objects
	pgid      int32    // users: primaryGroupID
	badUAC    bool     // a malformed userAccountControl (a text where a number belongs)
}

// fdom is one domain NC of the fake: count nodes served by at, in stream order, so the 100k test never holds them.
type fdom struct {
	nc    uint64
	count int
	at    func(i int) fnode
	// sid is the domain SID's second sub-authority, to tell the domains apart.
	sid uint32
}

// searchRec is what one ScopedSearch call asked.
type searchRec struct {
	roots    []string
	depth    connectorv1.SearchDepth
	attrs    []string
	pageSize uint32
	pin      string
	filter   *connectorv1.Filter
	nc       string
	prescan  bool
}

// fakeConnector is a connector client that serves a fake forest through Describe and ScopedSearch and records
// every call. It is the only part of the engine's world that is not real; directory behaviour is proved
// against Samba in the lab tests.
type fakeConnector struct {
	client.Connector
	mu       gosync.Mutex
	doms     map[string]*fdom
	extraNCs map[string]connectorv1.NamingContextKind // configuration/schema NCs Describe also reports
	maxPage  uint32
	dsa      uint64

	// Faults, applied to the main pass of the named domain (the one asking for more than two attributes).
	cutAfter map[string]int // end the stream after n entries with no completion marker
	errAfter map[string]int // fail the stream after n entries with an error whose message holds a value

	searches []searchRec
	describe int
	// onEntries is called for every batch the fake sends (the memory test samples the heap there).
	onBatch func()
}

const leakSentinel = "SENTINEL-CN=secret,OU=hidden,DC=leak"

func newFake(doms ...*fdom) *fakeConnector {
	f := &fakeConnector{doms: map[string]*fdom{}, extraNCs: map[string]connectorv1.NamingContextKind{},
		cutAfter: map[string]int{}, errAfter: map[string]int{}, maxPage: 1000, dsa: 0xd5a}
	for _, d := range doms {
		f.doms[gtext(d.nc)] = d
	}
	return f
}

func (f *fakeConnector) calls() (searches []searchRec, describes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]searchRec(nil), f.searches...), f.describe
}

func (f *fakeConnector) Describe(_ context.Context, _ *connectorv1.DescribeRequest, _ ...grpc.CallOption) (*connectorv1.DescribeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.describe++
	out := &connectorv1.DescribeResponse{Limits: &connectorv1.Limits{MaxPageSize: f.maxPage}}
	for _, d := range f.doms {
		out.NamingContexts = append(out.NamingContexts, &connectorv1.NamingContextInfo{NcGuid: gid(d.nc), Kind: connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_DOMAIN})
	}
	for text, k := range f.extraNCs {
		g := mustWire(text)
		out.NamingContexts = append(out.NamingContexts, &connectorv1.NamingContextInfo{NcGuid: g, Kind: k})
	}
	return out, nil
}

func mustWire(text string) *connectorv1.Guid {
	b, err := hex.DecodeString(strings.ReplaceAll(text, "-", ""))
	if err != nil || len(b) != 16 {
		panic("bad guid text " + text)
	}
	return &connectorv1.Guid{Value: b}
}

func (f *fakeConnector) ScopedSearch(_ context.Context, req *connectorv1.ScopedSearchRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[connectorv1.ScopedSearchResponse], error) {
	rec := searchRec{depth: req.GetDepth(), attrs: req.GetAttributes(), pageSize: req.GetPageSize(), filter: req.GetFilter()}
	for _, r := range req.GetRoots() {
		rec.roots = append(rec.roots, textOfWire(r.GetGuid()))
	}
	if p := req.GetDc().GetPinnedDsaGuid(); p != nil {
		rec.pin = textOfWire(p)
	}
	rec.prescan = len(rec.attrs) <= 2
	f.mu.Lock()
	f.searches = append(f.searches, rec)
	f.mu.Unlock()
	if len(rec.roots) != 1 {
		return nil, status.Error(codes.InvalidArgument, "roots")
	}
	rec.nc = rec.roots[0]
	d := f.doms[rec.nc]
	if d == nil {
		return nil, status.Error(codes.NotFound, "no such root")
	}
	s := &fstream{f: f, d: d, rec: rec, want: map[string]bool{}}
	for _, a := range rec.attrs {
		s.want[strings.ToLower(a)] = true
	}
	if !rec.prescan {
		if n, ok := f.cutAfter[rec.nc]; ok {
			s.limit, s.mode = n, "cut"
		}
		if n, ok := f.errAfter[rec.nc]; ok {
			s.limit, s.mode = n, "err"
		}
	}
	return s, nil
}

func textOfWire(g *connectorv1.Guid) string {
	b := g.GetValue()
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

type fstream struct {
	grpc.ClientStream
	f     *fakeConnector
	d     *fdom
	rec   searchRec
	want  map[string]bool
	pos   int
	stage int // 0 entries, 1 root completed, 2 completed, 3 done
	limit int
	mode  string
}

const fakeBatch = 200

func (s *fstream) Recv() (*connectorv1.ScopedSearchResponse, error) {
	switch s.stage {
	case 0:
		end := min(s.pos+fakeBatch, s.d.count)
		if s.mode != "" {
			end = min(end, s.limit)
		}
		if s.pos >= end {
			if s.mode == "cut" {
				return nil, io.EOF
			}
			if s.mode == "err" {
				return nil, status.Error(codes.Unavailable, "dc down: "+leakSentinel)
			}
			s.stage = 1
			return s.Recv()
		}
		b := &connectorv1.SearchBatch{}
		for ; s.pos < end; s.pos++ {
			b.Entries = append(b.Entries, s.entry(s.d.at(s.pos)))
		}
		if s.f.onBatch != nil {
			s.f.onBatch()
		}
		return &connectorv1.ScopedSearchResponse{Event: &connectorv1.ScopedSearchResponse_Batch{Batch: b}}, nil
	case 1:
		s.stage = 2
		return &connectorv1.ScopedSearchResponse{Event: &connectorv1.ScopedSearchResponse_RootCompleted{RootCompleted: &connectorv1.RootCompleted{Root: gid(s.d.nc)}}}, nil
	case 2:
		s.stage = 3
		return &connectorv1.ScopedSearchResponse{Event: &connectorv1.ScopedSearchResponse_Completed{Completed: &connectorv1.SearchCompleted{
			Observed: &connectorv1.Observation{Dc: &connectorv1.DcIdentity{DsaGuid: gid(s.f.dsa)}}}}}, nil
	}
	return nil, io.EOF
}

func (s *fstream) CloseSend() error { return nil }

func (s *fstream) domSID(rid uint32) *connectorv1.Sid {
	b := domSID(rid).Value
	b[8+4*2] = byte(s.d.sid) // the domain's own second sub-authority
	return &connectorv1.Sid{Value: b}
}

// entry builds the directory entry of a node with only the attributes the request named, the way the
// connector does (an attribute with no value is omitted).
func (s *fstream) entry(n fnode) *connectorv1.DirectoryEntry {
	var as attrs
	if s.want["objectclass"] {
		as = as.classes(n.class...)
	}
	if s.want["samaccountname"] && n.sam != "" {
		as = as.with("sAMAccountName", txt(n.sam))
	}
	if s.want["objectsid"] && n.rid != 0 {
		as = as.with("objectSid", sidv(s.domSID(n.rid)))
	}
	if s.want["primarygroupid"] && n.pgid != 0 {
		as = as.with("primaryGroupID", i32(n.pgid))
	}
	if s.want["useraccountcontrol"] && n.class[len(n.class)-1] == "user" {
		if n.badUAC {
			as = as.with("userAccountControl", txt("not-a-number"))
		} else {
			as = as.with("userAccountControl", i32(512))
		}
	}
	if s.want["member"] && len(n.members) > 0 {
		vs := make([]*connectorv1.AttributeValue, len(n.members))
		for i, m := range n.members {
			vs[i] = dnv(fmt.Sprintf("CN=m%d,DC=x", m), gid(m))
		}
		as = as.with("member", vs...)
	}
	var parent *connectorv1.Guid
	if n.parent != 0 {
		parent = gid(n.parent)
	}
	return entry(n.n, n.dn, parent, as)
}
