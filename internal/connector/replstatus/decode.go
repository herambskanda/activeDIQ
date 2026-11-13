package replstatus

import (
	"bytes"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/ad/replxml"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// decodeAttr decodes every value of one attribute and, only if all of them decode, appends the
// results to st. A single refused value fails the attribute on this DC (rule 4): the partial list
// is dropped, because a short list would read as a healthy DC. It returns the decoder's fixed code.
func decodeAttr(st *connectorv1.ReplicationState, a ad.ReplAttr, values [][]byte, b *replxml.Budget, parts [][]byte) replxml.Code {
	var (
		ns  []*connectorv1.InboundNeighbor
		ops []*connectorv1.PendingOp
		fs  []*connectorv1.ReplFailure
	)
	for _, v := range values {
		if e := b.Take(len(v)); e != nil {
			return e.Code
		}
		switch a {
		case ad.ReplInboundNeighbors:
			n, e := replxml.DecodeNeighbors(v)
			if e != nil {
				return e.Code
			}
			if inScope(parts, n.Partition) {
				ns = append(ns, neighborOf(n))
			}
		case ad.ReplPendingOps:
			o, e := replxml.DecodePendingOps(v)
			if e != nil {
				return e.Code
			}
			if inScope(parts, o.Partition) {
				ops = append(ops, pendingOf(o))
			}
		case ad.ReplConnectionFailures, ad.ReplLinkFailures:
			f, e := replxml.DecodeFailures(v)
			if e != nil {
				return e.Code
			}
			fs = append(fs, failureOf(f))
		}
	}
	switch a {
	case ad.ReplInboundNeighbors:
		st.Neighbors = ns
	case ad.ReplPendingOps:
		st.PendingOps = ops
	case ad.ReplConnectionFailures:
		st.ConnectionFailures = fs
	case ad.ReplLinkFailures:
		st.LinkFailures = fs
	}
	return ""
}

// inScope: with no partition filter everything is in scope; with one, an item whose partition the
// DC omitted cannot be shown to match and is left out.
func inScope(parts [][]byte, g replxml.Guid) bool {
	if len(parts) == 0 {
		return true
	}
	if !g.IsSet() {
		return false
	}
	for _, p := range parts {
		if bytes.Equal(p, g.Bytes()) {
			return true
		}
	}
	return false
}

func guidOf(g replxml.Guid) *connectorv1.Guid {
	if !g.IsSet() {
		return nil
	}
	return &connectorv1.Guid{Value: g.Bytes()}
}

func timeOf(t replxml.Time) *connectorv1.TimeValue {
	switch t.Kind {
	case replxml.TimeZero:
		return &connectorv1.TimeValue{Kind: &connectorv1.TimeValue_Sentinel{Sentinel: connectorv1.TimeSentinel_TIME_SENTINEL_ZERO}}
	case replxml.TimeAt:
		return &connectorv1.TimeValue{Kind: &connectorv1.TimeValue_At{At: timestamppb.New(t.At.In(time.UTC))}}
	}
	return nil // unset: the DC did not report it
}

func u32(u replxml.U32) *uint32 {
	if !u.Set {
		return nil
	}
	v := u.V
	return &v
}

func neighborOf(n replxml.Neighbor) *connectorv1.InboundNeighbor {
	return &connectorv1.InboundNeighbor{
		Partition:           guidOf(n.Partition),
		PartitionDisplayDn:  n.PartitionDisplayDN,
		SourceDsa:           guidOf(n.SourceDSA),
		SourceDnsHost:       n.SourceDNSHost,
		LastAttempt:         timeOf(n.LastAttempt),
		LastSuccess:         timeOf(n.LastSuccess),
		ConsecutiveFailures: u32(n.ConsecutiveFailures),
		LastResultWin32:     u32(n.LastResultWin32),
		Flags:               u32(n.Flags),
	}
}

func pendingOf(o replxml.PendingOp) *connectorv1.PendingOp {
	return &connectorv1.PendingOp{
		Enqueued:           timeOf(o.Enqueued),
		SerialNumber:       u32(o.SerialNumber),
		Priority:           u32(o.Priority),
		OpType:             u32(o.OpType),
		Options:            u32(o.Options),
		Partition:          guidOf(o.Partition),
		PartitionDisplayDn: o.PartitionDisplayDN,
		Dsa:                guidOf(o.DSA),
		DsaDnsHost:         o.DSADNSHost,
	}
}

func failureOf(f replxml.Failure) *connectorv1.ReplFailure {
	return &connectorv1.ReplFailure{
		Dsa:             guidOf(f.DSA),
		FirstFailure:    timeOf(f.FirstFailure),
		Count:           u32(f.Count),
		LastResultWin32: u32(f.LastResultWin32),
	}
}
