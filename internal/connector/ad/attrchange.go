package ad

import (
	"context"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/ad/replxml"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// maxChangeTimeAttrs bounds one AttrChangeTimes call; the callers ask for a handful (mail, mobile,
// otherMobile).
const maxChangeTimeAttrs = 16

// AttrChange is the last originating change time of one attribute on one object, as the bound DC's
// msDS-ReplAttributeMetaData records it. Known is false when the DC returned no metadata for the
// attribute, the metadata did not decode, or its time is not a real instant: At is then the zero
// time and must not be read. "Unknown" is never a zero time (spec 11 Q1: the caller applies the
// tenant fallback).
type AttrChange struct {
	Known bool
	At    time.Time // UTC; meaningful only when Known
}

// AttrChangeTimes returns, for each named attribute, the time of its last originating change on the
// object. Every name is a key of the result, known or not. The metadata is a constructed attribute
// the DC computes per replica: the time is that of the originating write, not of replication to
// this DC. A metadata value the decoder refuses (or one past the per-call budget) leaves only that
// attribute unknown; it never fails the call.
func (s *Session) AttrChangeTimes(ctx context.Context, id guid.GUID, attrs []string) (map[string]AttrChange, error) {
	if len(attrs) == 0 || len(attrs) > maxChangeTimeAttrs {
		return nil, fail(CodeInvalidArgument, "attributes", nil)
	}
	want, err := s.checkAttrs(attrs, false)
	if err != nil {
		return nil, err
	}
	e, err := s.Read(ctx, dn.GUIDRef(id), []string{"msDS-ReplAttributeMetaData"}, ReadOptions{})
	if err != nil {
		return nil, err
	}
	return changeTimesFrom(want, e.Raw("msDS-ReplAttributeMetaData")), nil
}

// changeTimesFrom matches decoded metadata values to the wanted names (case-insensitive: the DC
// reports ldapDisplayName in its own case).
func changeTimesFrom(want []string, values [][]byte) map[string]AttrChange {
	out := make(map[string]AttrChange, len(want))
	idx := make(map[string]string, len(want))
	for _, w := range want {
		out[w] = AttrChange{}
		idx[strings.ToLower(w)] = w
	}
	var budget replxml.Budget
	for _, v := range values {
		if budget.Take(len(v)) != nil {
			break // the rest stay unknown
		}
		m, derr := replxml.DecodeAttrMetaData(v)
		if derr != nil {
			continue
		}
		w, ok := idx[strings.ToLower(m.AttributeName)]
		if !ok || m.OriginTime.Kind != replxml.TimeAt {
			continue
		}
		out[w] = AttrChange{Known: true, At: m.OriginTime.At.UTC()}
	}
	return out
}
