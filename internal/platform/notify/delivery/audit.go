package delivery

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/notify/mailaddr"
)

// event builds the audit event of a Delivery. It carries ids, the purpose, the recipient's kind and
// class, the attempt count and a reason code. It never carries the subject, a body, a variable value
// or the recipient's address: an external recipient is identified by its domain, an account by its
// id. Details are in strictly increasing key order.
func (s *Deliveries) event(d Delivery, kind audit.Kind, actor authority.Chain, out audit.Outcome, reason, class string, at time.Time) audit.Event {
	verb := string(kind)[strings.LastIndex(string(kind), ".")+1:]
	details := []chain.Detail{
		{Key: "attempts", Value: strconv.Itoa(d.Attempts)},
		{Key: "channel", Value: "smtp"},
		{Key: "purpose", Value: d.Purpose},
		{Key: "recipient_class", Value: class},
		{Key: "requested_by", Value: d.RequestedBy},
		{Key: "source_id", Value: d.Source.ID},
		{Key: "source_kind", Value: d.Source.Kind},
	}
	if d.Recipient.Account != "" {
		details = append(details, chain.Detail{Key: "recipient_account", Value: d.Recipient.Account})
	} else if a, err := mailaddr.Parse(d.Recipient.Address); err == nil {
		details = append(details, chain.Detail{Key: "recipient_domain", Value: a.Domain()})
	}
	slices.SortFunc(details, func(a, b chain.Detail) int { return strings.Compare(a.Key, b.Key) })
	return audit.Event{
		ID: "notify.delivery." + d.ID + "." + verb, Kind: kind, At: at, Actor: actor,
		Target:    authority.TargetRef{GUID: d.ID, Class: "notify_delivery"},
		Component: "notify.delivery", Outcome: out, Reason: reason, Details: details,
	}
}
