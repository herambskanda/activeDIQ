package sync

import (
	"context"
	"errors"
	"io"
	"strings"

	"google.golang.org/protobuf/proto"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// ranged says the entry's member attribute is a slice of a longer list (the DC answered attr;range=0-N).
func ranged(en *connectorv1.DirectoryEntry) bool {
	for _, a := range en.GetAttributes() {
		if strings.EqualFold(a.GetName(), "member") {
			return a.GetRange() != nil && !(a.GetRange().GetStart() == 0 && a.GetRange().GetTerminal())
		}
	}
	return false
}

// completeMembers finishes the member list of one group the search delivered as a first range: it asks the
// connector for the object's member attribute (Read serves member;range=x-y until the * terminal range and
// sends the rest as ValueChunk messages), pinned to the DC that served the search so both agree. It returns
// the group mapped with the whole list, or nil when the list could not be made whole (the connector
// truncated it at the cap, the ranges were not contiguous, or no terminal range arrived): the group then
// stays partial and no edge is removed on its account. A connector failure is a *ConnectorError.
func (r *readJob) completeMembers(ctx context.Context, mp *Mapper, en *connectorv1.DirectoryEntry, dsa string) (*Mapped, error) {
	req := &connectorv1.ReadRequest{
		Connection:            r.ref,
		Guid:                  en.GetObjectGuid(),
		NcGuid:                nil,
		Attributes:            []string{"member"},
		MaxValuesPerAttribute: maxMembers + 1,
	}
	if root, err := wireOf(string(r.nc)); err == nil {
		req.NcGuid = root
	}
	if pin, err := wireOf(dsa); dsa != "" && err == nil {
		req.Dc = &connectorv1.DcSelection{PinnedDsaGuid: pin}
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := r.cc.Read(rctx, req)
	if err != nil {
		return nil, r.connErr(rctx, err)
	}
	var (
		vals       []*connectorv1.AttributeValue
		headerSeen bool
		whole      bool // the header's value set was whole, or a terminal chunk arrived
		truncated  bool
		bad        bool
	)
	for {
		m, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, r.connErr(rctx, err)
		}
		switch ev := m.GetEvent().(type) {
		case *connectorv1.ReadResponse_Header:
			if headerSeen {
				return nil, ErrProtocol
			}
			headerSeen = true
			for _, a := range ev.Header.GetEntry().GetAttributes() {
				if !strings.EqualFold(a.GetName(), "member") {
					continue
				}
				vals = append(vals, a.GetValues()...)
				rg := a.GetRange()
				whole = a.GetComplete() || (rg != nil && rg.GetStart() == 0 && rg.GetTerminal())
				if rg != nil && rg.GetStart() != 0 {
					bad = true
				}
			}
			if !hasAttr(ev.Header.GetEntry(), "member") {
				whole = true // the group has no members any more
			}
		case *connectorv1.ReadResponse_Chunk:
			c := ev.Chunk
			if !headerSeen || !strings.EqualFold(c.GetAttribute(), "member") || whole || c.GetRange() == nil || int(c.GetRange().GetStart()) != len(vals) {
				bad = true // out of order, a gap or an overlap: the list is not whole
				continue
			}
			vals = append(vals, c.GetValues()...)
			whole = c.GetRange().GetTerminal()
		case *connectorv1.ReadResponse_Completed:
			for _, t := range ev.Completed.GetTruncatedAttributes() {
				if strings.EqualFold(t, "member") {
					truncated = true
				}
			}
		default:
			return nil, ErrProtocol
		}
	}
	if !headerSeen {
		return nil, ErrIncomplete
	}
	if bad || truncated || !whole {
		return nil, nil
	}
	// Map the entry again with the whole list in place of the first range.
	full := proto.Clone(en).(*connectorv1.DirectoryEntry)
	for _, a := range full.Attributes {
		if strings.EqualFold(a.GetName(), "member") {
			a.Values, a.Complete, a.Range = vals, true, nil
		}
	}
	if len(vals) == 0 {
		kept := full.Attributes[:0]
		for _, a := range full.Attributes {
			if !strings.EqualFold(a.GetName(), "member") {
				kept = append(kept, a)
			}
		}
		full.Attributes = kept
	}
	out, err := mp.Map(full)
	if err != nil {
		var me *Error
		if errors.As(err, &me) {
			return nil, nil // refused as malformed (e.g. too many): stays partial
		}
		return nil, err
	}
	if len(vals) == 0 {
		out.Observation.MembersComplete = true
	}
	return &out, nil
}
