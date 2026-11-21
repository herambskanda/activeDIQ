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
	// listing is a reconcile listing: the objectGUID alone.
	listing bool
}

// fakeConnector is a connector client that serves a fake forest through Describe and ScopedSearch and records
// every call. It is the only part of the engine's world that is not real; directory behaviour is proved
// against Samba in the lab tests.
type fakeConnector struct {
	mu       gosync.Mutex
	doms     map[string]*fdom
	extraNCs map[string]connectorv1.NamingContextKind // configuration/schema NCs Describe also reports
	maxPage  uint32
	dsa      uint64

	// Faults, applied to the main pass of the named domain (the one asking for more than two attributes).
	cutAfter map[string]int // end the stream after n entries with no completion marker
	errAfter map[string]int // fail the stream after n entries with an error whose message holds a value
	// The same two faults for the reconcile listing of the named domain.
	listCut map[string]int
	listErr map[string]int

	// readTruncate makes Read report member as cut off at the cap; memberReads records each member Read call.
	readTruncate bool
	memberReads  []readRec

	searches []searchRec
	describe int
	// reads are the per-object Read requests (the password-change verdicts); pwStates and pwFaults
	// shape the answer per object GUID text.
	reads    []*connectorv1.ReadRequest
	pwStates map[string]connectorv1.PasswordChangeState
	pwFaults map[string]pwFault
	// onEntries is called for every batch the fake sends (the memory test samples the heap there).
	onBatch func()
}

const leakSentinel = "SENTINEL-CN=secret,OU=hidden,DC=leak"

func newFake(doms ...*fdom) *fakeConnector {
	f := &fakeConnector{doms: map[string]*fdom{}, extraNCs: map[string]connectorv1.NamingContextKind{},
		cutAfter: map[string]int{}, errAfter: map[string]int{}, listCut: map[string]int{}, listErr: map[string]int{}, maxPage: 1000, dsa: 0xd5a}
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
	rec.listing = len(rec.attrs) == 1 && strings.EqualFold(rec.attrs[0], "objectGUID")
	rec.prescan = len(rec.attrs) <= 2 && !rec.listing
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
	if rec.listing {
		if n, ok := f.listCut[rec.nc]; ok {
			s.limit, s.mode = n, "cut"
		}
		if n, ok := f.listErr[rec.nc]; ok {
			s.limit, s.mode = n, "err"
		}
	}
	if !rec.prescan && !rec.listing {
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
		vs := memberValues(n.members)
		if len(vs) > rangeWindow { // the DC answers member;range=0-1499 and the search never follows it
			as = append(as, &connectorv1.Attribute{Name: "member", Values: vs[:rangeWindow],
				Range: &connectorv1.ValueRange{Start: 0, End: rangeWindow - 1}})
		} else {
			as = as.with("member", vs...)
		}
	}
	var parent *connectorv1.Guid
	if n.parent != 0 {
		parent = gid(n.parent)
	}
	return entry(n.n, n.dn, parent, as)
}

const rangeWindow = 1500

// readRec is what one Read call asked.
type readRec struct {
	guid  string
	attrs []string
	pin   string
	max   uint32
}

func memberValues(ms []uint64) []*connectorv1.AttributeValue {
	vs := make([]*connectorv1.AttributeValue, len(ms))
	for i, m := range ms {
		vs[i] = dnv(fmt.Sprintf("CN=m%d,DC=x", m), gid(m))
	}
	return vs
}

// readMembers serves one object's member attribute the way the connector does: the first window in the header
// (complete = false when more follow) and the rest as ValueChunk messages ending in a terminal range.
func (f *fakeConnector) readMembers(_ context.Context, req *connectorv1.ReadRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[connectorv1.ReadResponse], error) {
	f.mu.Lock()
	f.memberReads = append(f.memberReads, readRec{guid: textOfWire(req.GetGuid()), attrs: req.GetAttributes(), pin: textOfWire(req.GetDc().GetPinnedDsaGuid()), max: req.GetMaxValuesPerAttribute()})
	f.mu.Unlock()
	var n *fnode
	for _, d := range f.doms {
		for i := 0; i < d.count; i++ {
			if x := d.at(i); textOfWire(req.GetGuid()) == gtext(x.n) {
				n = &x
			}
		}
	}
	if n == nil {
		return nil, status.Error(codes.NotFound, "no such object")
	}
	vs := memberValues(n.members)
	hdr := &connectorv1.DirectoryEntry{ObjectGuid: req.GetGuid()}
	var out []*connectorv1.ReadResponse
	if len(vs) > 0 {
		at := &connectorv1.Attribute{Name: "member", Values: vs, Complete: true}
		if len(vs) > rangeWindow {
			at.Values, at.Complete = vs[:rangeWindow], false
			at.Range = &connectorv1.ValueRange{Start: 0, End: rangeWindow - 1}
		}
		hdr.Attributes = []*connectorv1.Attribute{at}
	}
	out = append(out, &connectorv1.ReadResponse{Event: &connectorv1.ReadResponse_Header{Header: &connectorv1.ReadHeader{Entry: hdr}}})
	for st := rangeWindow; st < len(vs); st += rangeWindow {
		end := min(st+rangeWindow, len(vs))
		out = append(out, &connectorv1.ReadResponse{Event: &connectorv1.ReadResponse_Chunk{Chunk: &connectorv1.ValueChunk{
			Attribute: "member", Values: vs[st:end], Range: &connectorv1.ValueRange{Start: uint32(st), End: uint32(end - 1), Terminal: end == len(vs)}}}})
	}
	done := &connectorv1.ReadCompleted{}
	if f.readTruncate {
		done.TruncatedAttributes = []string{"member"}
	}
	out = append(out, &connectorv1.ReadResponse{Event: &connectorv1.ReadResponse_Completed{Completed: done}})
	return &readStream{msgs: out}, nil
}

// pwFault is how the fake answers the include_password_change Read of one object.
type pwFault string

const (
	pwErr       pwFault = "err"        // the call fails with a status whose message holds a value
	pwMismatch  pwFault = "mismatch"   // a verdict naming another object
	pwNoVerdict pwFault = "no_verdict" // a header without the verdict
	pwCoded     pwFault = "coded"      // NOT_CONFIRMED with an error code
	pwNoGUID    pwFault = "no_guid"    // a definite state with no object GUID
)

// Read serves the per-object read that carries the Cannot Change Password verdict. Without a fault the
// object is NO_DENY_ACE unless pwStates names another state.
func (f *fakeConnector) Read(_ context.Context, req *connectorv1.ReadRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[connectorv1.ReadResponse], error) {
	if !req.GetIncludePasswordChange() {
		return f.readMembers(context.Background(), req)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reads) < 10_000 { // the memory test reads 100k users: the fake must not be what grows
		f.reads = append(f.reads, req)
	}
	id := textOfWire(req.GetGuid())
	hdr := &connectorv1.ReadHeader{}
	if req.GetIncludePasswordChange() {
		st := connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_NO_DENY_ACE
		if s, ok := f.pwStates[id]; ok {
			st = s
		}
		v := &connectorv1.PasswordChangeVerdict{State: st, ObjectGuid: req.GetGuid()}
		switch f.pwFaults[id] {
		case pwErr:
			return nil, status.Error(codes.Unavailable, "dc down: "+leakSentinel)
		case pwMismatch:
			v.ObjectGuid = gid(0xbad)
		case pwNoVerdict:
			v = nil
		case pwCoded:
			v = &connectorv1.PasswordChangeVerdict{State: connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_NOT_CONFIRMED,
				ErrorCode: connectorv1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS}
		case pwNoGUID:
			v.ObjectGuid = nil
		}
		hdr.PasswordChange = v
	}
	return &readStream{msgs: []*connectorv1.ReadResponse{
		{Event: &connectorv1.ReadResponse_Header{Header: hdr}},
		{Event: &connectorv1.ReadResponse_Completed{Completed: &connectorv1.ReadCompleted{}}},
	}}, nil
}

type readStream struct {
	grpc.ClientStream
	msgs []*connectorv1.ReadResponse
}

func (s *readStream) Recv() (*connectorv1.ReadResponse, error) {
	if len(s.msgs) == 0 {
		return nil, io.EOF
	}
	m := s.msgs[0]
	s.msgs = s.msgs[1:]
	return m, nil
}

func (s *readStream) CloseSend() error { return nil }
