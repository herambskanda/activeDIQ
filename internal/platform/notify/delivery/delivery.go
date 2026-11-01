// Package delivery is DM-84 Delivery: one message to one recipient, with its own state, attempts
// and reason (modules/reports.md §7.2, §8). A message to three recipients is three Deliveries, so
// one rejected address fails alone and the others are sent.
//
// A Delivery stores metadata and variable references, never a rendered body or a secret (DM-84.I1):
// the body is produced at send time by the Renderer registered for the Delivery's purpose, which is
// how a retry sends the same message again without the platform keeping it. The audit events carry
// ids, codes and the recipient's class, never a subject, body or address.
//
// Lifecycle: queued -> sent; queued -> failed -> (retry) -> sent | given_up. A failure the relay
// will not change (egress refusal, 5xx, an external address for a message that must stay inside)
// goes straight to given_up; a transient one is failed with a backoff until MaxAttempts. A crash
// between claim and outcome is covered by the lease: the row is claimed again after it expires and
// the claim counts as an attempt, so the loop is bounded and a message can be sent more than once
// only if the process dies after the relay accepted it and before the outcome committed.
//
// A Delivery is also the authority for a delivery-link download (reports §7.2): ForSource answers
// whether this account was sent that source.
package delivery

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/notify/mailaddr"
	"github.com/skenzeriq/activediq/internal/platform/notify/settings"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.notify_deliveries", Entity: "DM-84", Kind: tablekind.Tenant})

// State of a Delivery.
type State string

const (
	Queued  State = "queued"
	Sent    State = "sent"
	Failed  State = "failed" // the last attempt failed and a retry is scheduled
	GivenUp State = "given_up"
)

// Terminal reports whether no further attempt will be made.
func (s State) Terminal() bool { return s == Sent || s == GivenUp }

// DefaultMaxAttempts is used when NewDelivery.MaxAttempts is zero.
const DefaultMaxAttempts = 5

// Errors. None carries an address or a stored value.
var (
	ErrInvalid = errors.New("delivery: invalid input")
	// ErrConflict: the dedup key already names a different delivery.
	ErrConflict = errors.New("delivery: dedup key already used for a different delivery")
)

// SourceRef says what a message is about: ("report_export", <export id>) for a delivery link.
type SourceRef struct{ Kind, ID string }

// Recipient is an account of the tenant or a mail address. Exactly one field is set.
type Recipient struct {
	Account string // account UUID
	Address string // any e-mail address; stored in canonical form
}

// Delivery is a stored DM-84 row.
type Delivery struct {
	ID              string
	Purpose         string
	TemplateVersion int
	Variables       map[string]string
	Recipient       Recipient
	Source          SourceRef
	RequestedBy     string
	RequireInternal bool
	State           State
	Attempts        int
	MaxAttempts     int
	NextAttemptAt   *time.Time
	// LastErrorCode is the stable code of the last failure, or "".
	LastErrorCode     string
	ProviderMessageID string
	SentAt            *time.Time
	CreatedAt         time.Time
}

// NewDelivery is a request to deliver one message to one recipient.
type NewDelivery struct {
	// DedupKey makes Enqueue idempotent: the same key returns the stored Delivery. A schedule fire
	// uses, for example, "<fire id>:<recipient>".
	DedupKey        string
	Purpose         string // names the Renderer: "reports.schedule.delivery"
	TemplateVersion int
	// Variables are references the Renderer resolves (ids, not values of secrets or bodies).
	Variables map[string]string
	Recipient Recipient
	Source    SourceRef
	// RequireInternal refuses to send the message to an address outside the allowed domains at send
	// time (TM-D30 SX-5: an attachment never leaves the organisation).
	RequireInternal bool
	MaxAttempts     int
}

var (
	dedupRe   = regexp.MustCompile(`^[\x21-\x7e]{1,200}$`)
	purposeRe = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
	kindRe    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
	idRe      = regexp.MustCompile(`^[\x21-\x7e]{1,128}$`)
	uuidRe    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// Audit kinds. The events are about the delivery, not the message.
const (
	KindQueued  audit.Kind = "notify.delivery.queued"
	KindSent    audit.Kind = "notify.delivery.sent"
	KindGivenUp audit.Kind = "notify.delivery.given_up"
)

// Deliveries stores DM-84 rows. It holds no state beyond the audit sink; every method runs in the
// caller's transaction, in the tenant's context.
type Deliveries struct {
	audit audit.Sink
	set   settings.Store
}

// New returns the store. Enqueue and the dispatcher's outcomes append events to sink.
func New(sink audit.Sink) (*Deliveries, error) {
	if sink == nil {
		return nil, errors.New("delivery: store needs an audit sink")
	}
	return &Deliveries{audit: sink}, nil
}

func scan(row interface{ Scan(dest ...any) error }) (Delivery, error) {
	var (
		d              Delivery
		vars           []byte
		acct, addr     *string
		lastErr, pmid  *string
		state          string
		tv, att, maxAt int32
	)
	if err := row.Scan(&d.ID, &d.Purpose, &tv, &vars, &acct, &addr, &d.Source.Kind, &d.Source.ID, &d.RequestedBy, &d.RequireInternal,
		&state, &att, &maxAt, &d.NextAttemptAt, &lastErr, &pmid, &d.SentAt, &d.CreatedAt); err != nil {
		return Delivery{}, err
	}
	d.TemplateVersion, d.Attempts, d.MaxAttempts, d.State = int(tv), int(att), int(maxAt), State(state)
	if err := json.Unmarshal(vars, &d.Variables); err != nil {
		return Delivery{}, fmt.Errorf("delivery: stored variables: %w", err)
	}
	if acct != nil {
		d.Recipient.Account = *acct
	}
	if addr != nil {
		d.Recipient.Address = *addr
	}
	if lastErr != nil {
		d.LastErrorCode = *lastErr
	}
	if pmid != nil {
		d.ProviderMessageID = *pmid
	}
	return d, nil
}

func (n NewDelivery) validate() (NewDelivery, error) {
	if !dedupRe.MatchString(n.DedupKey) || !purposeRe.MatchString(n.Purpose) || n.TemplateVersion < 1 ||
		!kindRe.MatchString(n.Source.Kind) || !idRe.MatchString(n.Source.ID) || n.MaxAttempts < 0 || n.MaxAttempts > 20 {
		return n, ErrInvalid
	}
	if n.MaxAttempts == 0 {
		n.MaxAttempts = DefaultMaxAttempts
	}
	if n.Variables == nil {
		n.Variables = map[string]string{}
	}
	switch {
	case n.Recipient.Account != "" && n.Recipient.Address == "":
		if !uuidRe.MatchString(n.Recipient.Account) {
			return n, ErrInvalid
		}
	case n.Recipient.Address != "" && n.Recipient.Account == "":
		a, err := mailaddr.Parse(n.Recipient.Address)
		if err != nil {
			return n, ErrInvalid
		}
		n.Recipient.Address = a.String() // the canonical string is the one stored, classified and sent to
	default:
		return n, ErrInvalid
	}
	return n, nil
}

// Enqueue stores a queued Delivery in tx and appends notify.delivery.queued, attributed to by (the
// principal behind the message). The same DedupKey returns the stored Delivery and appends nothing;
// a key reused for a different delivery is ErrConflict. The Delivery is due at once.
func (s *Deliveries) Enqueue(ctx context.Context, tx store.Tx, nd NewDelivery, by authority.Chain) (Delivery, error) {
	nd, err := nd.validate()
	if err != nil || by.Validate() != nil || len(by.Requester.ID) > 128 {
		return Delivery{}, ErrInvalid
	}
	if len(nd.Variables) > 32 {
		return Delivery{}, ErrInvalid
	}
	vars, err := json.Marshal(nd.Variables, json.Deterministic(true))
	if err != nil || len(vars) > 4096 {
		return Delivery{}, ErrInvalid
	}
	cur, err := (settings.Store{}).Get(ctx, tx)
	if err != nil {
		return Delivery{}, err
	}
	var acct, addr *string
	if nd.Recipient.Account != "" {
		acct = &nd.Recipient.Account
	} else {
		addr = &nd.Recipient.Address
	}
	row := tx.QueryRow(ctx, sqlInsert,
		nd.DedupKey, nd.Purpose, nd.TemplateVersion, string(vars), recipientKind(nd.Recipient), acct, addr,
		nd.Source.Kind, nd.Source.ID, by.Requester.ID, nd.RequireInternal, nd.MaxAttempts)
	d, err := scan(row)
	if store.IsNoRows(err) { // the key exists: idempotent only for the same delivery
		prior, err := scan(tx.QueryRow(ctx, sqlByDedupKey, nd.DedupKey))
		if err != nil {
			return Delivery{}, fmt.Errorf("delivery: read existing: %w", err)
		}
		if !sameRequest(prior, nd) {
			return Delivery{}, ErrConflict
		}
		return prior, nil
	}
	if err != nil {
		return Delivery{}, fmt.Errorf("delivery: enqueue: %w", err)
	}
	class := "account"
	if nd.Recipient.Address != "" {
		a, _ := mailaddr.Parse(nd.Recipient.Address)
		class = cur.Classify(a).String()
	}
	if err := s.audit.Append(ctx, tx, s.event(d, KindQueued, by, audit.Success, "queued", class, d.CreatedAt)); err != nil {
		return Delivery{}, fmt.Errorf("delivery: audit queued: %w", err)
	}
	return d, nil
}

func recipientKind(r Recipient) string {
	if r.Account != "" {
		return "account"
	}
	return "address"
}

func sameRequest(d Delivery, n NewDelivery) bool {
	if d.Purpose != n.Purpose || d.TemplateVersion != n.TemplateVersion || d.Source != n.Source || d.Recipient != n.Recipient ||
		d.RequireInternal != n.RequireInternal || len(d.Variables) != len(n.Variables) {
		return false
	}
	for k, v := range n.Variables {
		if d.Variables[k] != v {
			return false
		}
	}
	return true
}

// ForSource returns the Delivery that sent source to the account in recipient, for the delivery-link
// authority (reports §7.2). It runs under row-level security in the caller's tenant, so another
// tenant's delivery is invisible. It answers false for another account, for an address recipient
// and for a Delivery that was given up (that account was never sent the link). When one account was
// sent the same source twice the latest Delivery is returned. A queued or failed (still retrying)
// Delivery is returned too, not only a sent one: the link is authorised from the moment it is queued.
func (s *Deliveries) ForSource(ctx context.Context, tx store.Tx, source SourceRef, recipient Recipient) (Delivery, bool, error) {
	if recipient.Account == "" || recipient.Address != "" || !uuidRe.MatchString(recipient.Account) ||
		!kindRe.MatchString(source.Kind) || !idRe.MatchString(source.ID) {
		return Delivery{}, false, nil
	}
	d, err := scan(tx.QueryRow(ctx, sqlLatestForSource, source.Kind, source.ID, recipient.Account))
	if store.IsNoRows(err) {
		return Delivery{}, false, nil
	}
	if err != nil {
		return Delivery{}, false, fmt.Errorf("delivery: for source: %w", err)
	}
	return d, true, nil
}

// Get returns one Delivery of the tenant, for status views.
func (s *Deliveries) Get(ctx context.Context, tx store.Tx, id string) (Delivery, error) {
	if !uuidRe.MatchString(id) {
		return Delivery{}, ErrInvalid
	}
	d, err := scan(tx.QueryRow(ctx, sqlByID, id))
	if store.IsNoRows(err) {
		return Delivery{}, ErrNotFound
	}
	return d, err
}

// ErrNotFound: no such delivery in the tenant.
var ErrNotFound = errors.New("delivery: not found")
