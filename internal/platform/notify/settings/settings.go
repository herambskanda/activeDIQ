// Package settings holds the tenant's mail settings: the SMTP relay (DM-82, channel kind smtp) and
// the allowed recipient domains (modules/reports.md §8, spec Q3, TM-D30 SX-7).
//
// The allowed-domains list decides one thing: whether an address is internal or external. An empty
// list makes every address external, so a new install is closed until the administrator names the
// organisation's domains. Matching is exact on the canonical domain (mailaddr: IDNA ToASCII, lower
// case); "ok.example" does not admit "sub.ok.example" or "ok.example.evil.example", and there is no
// wildcard. The address that is classified is the canonical address that the SMTP layer sends to.
//
// The settings are written by one door only, the notify.settings.update Action (internal/modules/
// notify), through Store.Set, which takes the Action's step token. Reading is open to any server
// code that holds a transaction in the tenant's context. SMTP AUTH credentials are not held here.
package settings

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/notify/mailaddr"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.notify_settings", Entity: "DM-82", Kind: tablekind.Tenant})

// MaxAllowedDomains bounds the list (the table CHECK holds the same number).
const MaxAllowedDomains = 200

// Errors. None carries a submitted value.
var (
	// ErrInvalid: the update is not acceptable. The wrapped message says which field.
	ErrInvalid = errors.New("notify settings: invalid")
	// ErrNoTenant: the transaction has no tenant context.
	ErrNoTenant = errors.New("notify settings: no tenant context")
	// ErrStale: the settings changed since the plan read them.
	ErrStale = errors.New("notify settings: changed since the plan")
)

// Security is how the relay connection is protected. The zero value is not valid.
type Security string

const (
	// StartTLS upgrades a plain connection with STARTTLS before anything is sent; if the relay does
	// not offer it the connection is refused. Certificates are always verified.
	StartTLS Security = "starttls"
	// ImplicitTLS is TLS from the first byte (SMTPS, usually port 465).
	ImplicitTLS Security = "tls"
	// Plaintext is no TLS at all. It needs the explicit opt-in on the Relay.
	Plaintext Security = "none"
)

// Relay is the SMTP relay of the tenant. Host is a DNS name or an IP literal; reaching an internal
// address additionally needs an installation-operator egress allow-list entry (TM-F-EGRESS).
type Relay struct {
	Host     string
	Port     int // 0 takes the default for Security: 587, 465, 25
	Security Security
	// From is the envelope and header sender, a canonical address.
	From string
	// PlaintextOptIn must be true exactly when Security is Plaintext.
	PlaintextOptIn bool
}

// Class says whether an address is inside the organisation. The zero value is External, so a
// missing answer is never "internal".
type Class int

const (
	External Class = iota
	Internal
)

func (c Class) String() string {
	if c == Internal {
		return "internal"
	}
	return "external"
}

// Settings is a tenant's mail settings. The zero value is the install default: no relay and no
// allowed domain, so every address is external.
type Settings struct {
	// AllowedDomains are canonical, sorted, unique.
	AllowedDomains []string
	// Relay is nil until configured.
	Relay *Relay
	// Version is 0 before the first write and rises by one per write.
	Version int
}

// Classify says whether a is inside the allowed domains. The zero Address is External.
func (s Settings) Classify(a mailaddr.Address) Class {
	if a.IsZero() {
		return External
	}
	if _, found := slices.BinarySearch(s.AllowedDomains, a.Domain()); found {
		return Internal
	}
	return External
}

// ClassifyString parses raw strictly and classifies the canonical address. The returned Address is
// the string to put on RCPT TO; there is no second parse.
func (s Settings) ClassifyString(raw string) (mailaddr.Address, Class, error) {
	a, err := mailaddr.Parse(raw)
	if err != nil {
		return mailaddr.Address{}, External, err
	}
	return a, s.Classify(a), nil
}

// Update is the full replacement of the writable settings. It is applied whole: a domain absent from
// AllowedDomains is removed.
type Update struct {
	AllowedDomains []string
	Relay          *Relay
}

// Normalize validates u and returns it in stored form: domains canonical, sorted and unique, the
// relay defaulted. Callers store the returned value.
func (u Update) Normalize() (Update, error) {
	if len(u.AllowedDomains) > MaxAllowedDomains {
		return Update{}, fmt.Errorf("%w: at most %d allowed domains", ErrInvalid, MaxAllowedDomains)
	}
	out := Update{AllowedDomains: make([]string, 0, len(u.AllowedDomains))}
	for _, d := range u.AllowedDomains {
		c, err := mailaddr.NormalizeDomain(d)
		if err != nil {
			return Update{}, fmt.Errorf("%w: an allowed domain is not a plain domain name (no wildcard, no leading dot, no address)", ErrInvalid)
		}
		out.AllowedDomains = append(out.AllowedDomains, c)
	}
	slices.Sort(out.AllowedDomains)
	out.AllowedDomains = slices.Compact(out.AllowedDomains)
	if u.Relay != nil {
		r, err := u.Relay.normalize()
		if err != nil {
			return Update{}, err
		}
		out.Relay = &r
	}
	return out, nil
}

func (r Relay) normalize() (Relay, error) {
	if !validHost(r.Host) {
		return Relay{}, fmt.Errorf("%w: relay host must be a plain host name or IP address", ErrInvalid)
	}
	r.Host = strings.ToLower(r.Host)
	switch r.Security {
	case StartTLS, ImplicitTLS, Plaintext:
	default:
		return Relay{}, fmt.Errorf("%w: relay security must be starttls, tls or none", ErrInvalid)
	}
	switch {
	case r.Security == Plaintext && !r.PlaintextOptIn:
		return Relay{}, fmt.Errorf("%w: plaintext SMTP needs the explicit opt-in", ErrInvalid)
	case r.Security != Plaintext && r.PlaintextOptIn:
		return Relay{}, fmt.Errorf("%w: plaintext opt-in given with TLS", ErrInvalid)
	}
	if r.Port == 0 {
		r.Port = map[Security]int{StartTLS: 587, ImplicitTLS: 465, Plaintext: 25}[r.Security]
	}
	if r.Port < 1 || r.Port > 65535 {
		return Relay{}, fmt.Errorf("%w: relay port out of range", ErrInvalid)
	}
	from, err := mailaddr.Parse(r.From)
	if err != nil {
		return Relay{}, fmt.Errorf("%w: relay sender is not a plain e-mail address", ErrInvalid)
	}
	r.From = from.String()
	return r, nil
}

// validHost accepts an IP literal or an ASCII DNS name. Anything else, including a port, a path, a
// bracket or an internationalised name, is refused: the operator enters the punycode form.
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return !strings.Contains(h, "%") // no zone
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Store reads and writes notify_settings. It holds no state; every method runs in the caller's
// transaction, and the tenant is the transaction's (app.tenant_id), enforced again by row-level
// security.
type Store struct{}

const cols = `allowed_domains, smtp_host, smtp_port, smtp_security, smtp_from, plaintext_opt_in, version`

func scanSettings(row interface{ Scan(dest ...any) error }) (Settings, error) {
	var (
		s                  Settings
		host, security, fr *string
		port               *int32
		optIn              bool
		ver                int32
	)
	if err := row.Scan(&s.AllowedDomains, &host, &port, &security, &fr, &optIn, &ver); err != nil {
		return Settings{}, err
	}
	s.Version = int(ver)
	if s.AllowedDomains == nil {
		s.AllowedDomains = []string{}
	}
	if host != nil && port != nil && security != nil && fr != nil {
		s.Relay = &Relay{Host: *host, Port: int(*port), Security: Security(*security), From: *fr, PlaintextOptIn: optIn}
	}
	return s, nil
}

func requireTenant(ctx context.Context, tx store.Tx) error {
	var tid string
	if err := tx.QueryRow(ctx, `SELECT coalesce(current_setting('app.tenant_id', true), '')`).Scan(&tid); err != nil {
		return fmt.Errorf("notify settings: tenant context: %w", err)
	}
	if tid == "" {
		return ErrNoTenant
	}
	return nil
}

// Get returns the tenant's settings, or the install default (Version 0) when none were written.
func (Store) Get(ctx context.Context, tx store.Tx) (Settings, error) {
	if err := requireTenant(ctx, tx); err != nil {
		return Settings{}, err
	}
	s, err := scanSettings(tx.QueryRow(ctx, `SELECT `+cols+` FROM public.notify_settings
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid`))
	if store.IsNoRows(err) {
		return Settings{AllowedDomains: []string{}}, nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("notify settings: read: %w", err)
	}
	return s, nil
}

// Set replaces the writable settings and returns what was stored. It takes the Action's step token:
// the settings have no other writer. fromVersion is the Version the plan read; if the row has moved
// since, Set returns ErrStale and writes nothing.
func (st Store) Set(ctx context.Context, s step.Step, u Update, fromVersion int) (Settings, error) {
	if err := s.Valid(); err != nil {
		return Settings{}, err
	}
	return st.set(ctx, s.Tx(), u, fromVersion)
}

func (Store) set(ctx context.Context, tx store.Tx, u Update, fromVersion int) (Settings, error) {
	n, err := u.Normalize()
	if err != nil {
		return Settings{}, err
	}
	if err := requireTenant(ctx, tx); err != nil {
		return Settings{}, err
	}
	var host, security, from *string
	var port *int32
	optIn := false
	if r := n.Relay; r != nil {
		p, sec := int32(r.Port), string(r.Security)
		host, port, security, from, optIn = &r.Host, &p, &sec, &r.From, r.PlaintextOptIn
	}
	// Lock the row (or its absence) so the version check and the write are one step.
	var cur int32
	err = tx.QueryRow(ctx, `SELECT version FROM public.notify_settings
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid FOR UPDATE`).Scan(&cur)
	switch {
	case store.IsNoRows(err):
		if fromVersion != 0 {
			return Settings{}, ErrStale
		}
		row := tx.QueryRow(ctx, `INSERT INTO public.notify_settings
			(tenant_id, allowed_domains, smtp_host, smtp_port, smtp_security, smtp_from, plaintext_opt_in, version, updated_at)
			VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1, $2, $3, $4, $5, $6, 1, now())
			RETURNING `+cols, n.AllowedDomains, host, port, security, from, optIn)
		return scanStored(row)
	case err != nil:
		return Settings{}, fmt.Errorf("notify settings: lock: %w", err)
	}
	if int(cur) != fromVersion {
		return Settings{}, ErrStale
	}
	row := tx.QueryRow(ctx, `UPDATE public.notify_settings
		SET allowed_domains = $1, smtp_host = $2, smtp_port = $3, smtp_security = $4, smtp_from = $5,
		    plaintext_opt_in = $6, version = version + 1, updated_at = now()
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
		RETURNING `+cols, n.AllowedDomains, host, port, security, from, optIn)
	return scanStored(row)
}

func scanStored(row interface{ Scan(dest ...any) error }) (Settings, error) {
	s, err := scanSettings(row)
	if err != nil {
		return Settings{}, fmt.Errorf("notify settings: write: %w", err)
	}
	return s, nil
}
